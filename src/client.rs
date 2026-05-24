use crate::crypto_logic::{HybridHandshake, ReplayGuard};
use crate::management_client::{load_or_enroll, AgentBootstrap};
use crate::models::{AgentKind, AgentStatusReport, ClientConfig, HeartbeatRequest, StatusRequest};
use crate::tunnel_protocol::{decode_server_hello, encode_client_auth, encode_client_hello};
use crate::TunParams;
use rand_core::OsRng;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use ml_kem::kem::{Encapsulate, EncapsulationKey};
use ml_kem::EncodedSizeUser;

pub struct ClientArgs {
    pub management_url: String,
    pub enrollment_token: String,
    pub state_dir: PathBuf,
    pub device_name: String,
    pub verbose: bool,
}

pub fn run(args: ClientArgs) -> io::Result<()> {

    println!("client starting...");
    println!("connecting to manager...");

    let verbose = args.verbose;

    println!("sending enrollment...");

    let (agent_state, manager_client) = load_or_enroll(&AgentBootstrap {
        kind: AgentKind::Client,
        management_url: args.management_url.clone(),
        enrollment_token: args.enrollment_token,
        node_name: args.device_name.clone(),
        state_dir: args.state_dir,
    })?;

    println!("enrollment successful");

    if verbose {
        println!(
            "[client] Agent {} is registered with manager {}",
            agent_state.agent_id, args.management_url
        );
    }

    let status = Arc::new(Mutex::new(AgentStatusReport::default()));
    let mut shared_config: Option<Arc<Mutex<ClientConfig>>> = None;
    let mut poll_interval = 15u64;
    let mut next_identity_refresh = Instant::now();
    
    println!("starting heartbeat loop...");

    loop {
        if Instant::now() >= next_identity_refresh {
            refresh_public_network_info(&status, verbose);
            next_identity_refresh = Instant::now() + Duration::from_secs(300);
        }

        let snapshot = status.lock().map(|state| state.clone()).unwrap_or_default();
        let heartbeat = manager_client.heartbeat(&HeartbeatRequest {
            agent_id: agent_state.agent_id.clone(),
            agent_secret: agent_state.agent_secret.clone(),
            kind: AgentKind::Client,
            current_version: snapshot.applied_version,
            status: snapshot,
        });

        match heartbeat {
            Ok(response) => {
                poll_interval = response.poll_interval_seconds.max(5);
                if let Some(config) = response.client_config {
                    if shared_config.is_none() {
                        if !config.enabled {
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "client enrolled but waiting for manager assignment",
                                verbose,
                            );
                        } else {
                            let config_ref = Arc::new(Mutex::new(config.clone()));
                            start_runtime(
                                config.clone(),
                                Arc::clone(&config_ref),
                                Arc::clone(&status),
                                verbose,
                            )?;
                            shared_config = Some(config_ref);
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "managed VPN client runtime started",
                                verbose,
                            );
                        }
                    } else if let Some(config_ref) = &shared_config {
                        let current = config_ref
                            .lock()
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "config lock failed")
                            })?
                            .clone();
                        if structural_change(&current, &config) {
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "structural client config changed; restart process to apply tunnel/server updates",
                                verbose,
                            );
                        } else {
                            *config_ref.lock().map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "config lock failed")
                            })? = config.clone();
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "live client control update applied",
                                verbose,
                            );
                        }
                    }
                }
            }
            Err(err) => {
                set_status_message(
                    &status,
                    None,
                    Some(err.to_string()),
                    "management heartbeat failed",
                    verbose,
                );
            }
        }

        let snapshot = status.lock().map(|state| state.clone()).unwrap_or_default();
        let _ = manager_client.status(&StatusRequest {
            agent_id: agent_state.agent_id.clone(),
            agent_secret: agent_state.agent_secret.clone(),
            kind: AgentKind::Client,
            status: snapshot,
        });

        thread::sleep(Duration::from_secs(poll_interval));
    }
}

fn start_runtime(
    config: ClientConfig,
    shared_config: Arc<Mutex<ClientConfig>>,
    status: Arc<Mutex<AgentStatusReport>>,
    verbose: bool,
) -> io::Result<()> {
    if verbose {
        println!(
            "[client] Creating TUN {} at {}/{} and targeting {}",
            config.tun_name, config.tun_address, config.tun_prefix, config.server_endpoint
        );
    }

    println!("creating tunnel...");

    let dev = Arc::new(crate::create_tun(&TunParams {
        name: config.tun_name.clone(),
        address_v4: config.tun_address.clone(),
        prefix_v4: config.tun_prefix,
        mtu: config.mtu,
    })?);
    
    println!("tunnel created");

    if let Err(err) = apply_platform_network_settings(&config, verbose) {
        set_status_message(
            &status,
            None,
            Some(err.to_string()),
            "network route/DNS setup failed",
            verbose,
        );
    }

    let server_addr: SocketAddr = config
        .server_endpoint
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    udp.connect(server_addr)?;
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    let session_key = perform_managed_handshake(&udp, &config)?;
    if verbose {
        println!(
            "[client] Hybrid handshake completed with server {}",
            config.server_endpoint
        );
    }
    let shared_key = Arc::new(Mutex::new(session_key));

    let dev_tx = Arc::clone(&dev);
    let udp_tx = udp.try_clone()?;
    let key_tx = Arc::clone(&shared_key);
    let config_tx = Arc::clone(&shared_config);
    let status_tx = Arc::clone(&status);

    thread::spawn(move || -> io::Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = dev_tx.recv(&mut buf)?;
            let config = config_tx
                .lock()
                .map(|cfg| cfg.clone())
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "config lock failed"))?;
            if !config.enabled {
                continue;
            }
            let key = key_tx
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "key lock failed"))?;
            let encrypted = HybridHandshake::encrypt_data(&*key, &buf[..n]);
            let _ = udp_tx.send(&encrypted);
            add_traffic(&status_tx, n as u64, 0);
        }
    });

    let dev_rx = Arc::clone(&dev);
    let key_rx = Arc::clone(&shared_key);
    let config_rx = Arc::clone(&shared_config);
    let status_rx = Arc::clone(&status);

    thread::spawn(move || -> io::Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut replay_guard = ReplayGuard::default();
        loop {
            match udp.recv(&mut buf) {
                Ok(n) => {
                    let config = config_rx
                        .lock()
                        .map(|cfg| cfg.clone())
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "config lock failed"))?;
                    if !config.enabled {
                        continue;
                    }
                    let key = key_rx
                        .lock()
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "key lock failed"))?;
                    if replay_guard.is_fresh_packet(&buf[..n]) {
                        if let Some(packet) = HybridHandshake::decrypt_data(&*key, &buf[..n]) {
                            add_traffic(&status_rx, 0, packet.len() as u64);
                            let _ = dev_rx.send(&packet);
                        }
                    } else if verbose {
                        println!("[client] Dropped replayed or malformed tunnel packet");
                    }
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => {
                    set_status_message(
                        &status_rx,
                        None,
                        Some(err.to_string()),
                        "client UDP receive loop failed",
                        verbose,
                    );
                }
            }
        }
    });

    spawn_traffic_reporter(Arc::clone(&status), verbose);

    Ok(())
}

fn add_traffic(status: &Arc<Mutex<AgentStatusReport>>, upload_bytes: u64, download_bytes: u64) {
    if let Ok(mut guard) = status.lock() {
        guard.upload_bytes = Some(
            guard
                .upload_bytes
                .unwrap_or_default()
                .saturating_add(upload_bytes),
        );
        guard.download_bytes = Some(
            guard
                .download_bytes
                .unwrap_or_default()
                .saturating_add(download_bytes),
        );
    }
}

fn spawn_traffic_reporter(status: Arc<Mutex<AgentStatusReport>>, verbose: bool) {
    thread::spawn(move || {
        let mut last_upload = 0u64;
        let mut last_download = 0u64;

        loop {
            thread::sleep(Duration::from_secs(1));

            let (upload, download) = status
                .lock()
                .map(|state| {
                    (
                        state.upload_bytes.unwrap_or_default(),
                        state.download_bytes.unwrap_or_default(),
                    )
                })
                .unwrap_or_default();

            let upload_bps = upload.saturating_sub(last_upload);
            let download_bps = download.saturating_sub(last_download);
            last_upload = upload;
            last_download = download;

            if verbose && (upload_bps > 0 || download_bps > 0) {
                println!(
                    "[client] traffic upload_bytes={} download_bytes={} upload_bps={} download_bps={}",
                    upload, download, upload_bps, download_bps
                );
            }
        }
    });
}

fn refresh_public_network_info(status: &Arc<Mutex<AgentStatusReport>>, verbose: bool) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            if verbose {
                eprintln!("[client] public IP lookup client failed: {err}");
            }
            return;
        }
    };

    let response = match client.get("https://ipapi.co/json/").send() {
        Ok(response) => response,
        Err(err) => {
            if verbose {
                eprintln!("[client] public IP lookup failed: {err}");
            }
            return;
        }
    };

    let data = match response.json::<serde_json::Value>() {
        Ok(data) => data,
        Err(err) => {
            if verbose {
                eprintln!("[client] public IP lookup parse failed: {err}");
            }
            return;
        }
    };

    let public_ip = data
        .get("ip")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let country = data
        .get("country_name")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);

    if let Ok(mut guard) = status.lock() {
        if public_ip.is_some() {
            guard.public_ip = public_ip;
        }
        if country.is_some() {
            guard.country = country;
        }
    }
}

fn perform_managed_handshake(udp: &UdpSocket, config: &ClientConfig) -> io::Result<[u8; 32]> {
    udp.send(&encode_client_hello(&config.client_id))?;

    let mut incoming = [0u8; 2048];
    let n = udp.recv(&mut incoming).map_err(|err| {
        if err.kind() == io::ErrorKind::TimedOut || err.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "server {} did not respond to the initial UDP handshake for client {}. Check that the Linux server is running the latest code, UDP/9000 is reachable, and this client is assigned to the currently running server in the manager portal",
                    config.server_endpoint, config.client_id
                ),
            )
        } else {
            err
        }
    })?;
    let (server_xpub_bytes, server_pq_bytes) =
        decode_server_hello(&incoming[..n]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid server hello from managed VPN server",
            )
        })?;

    let server_xpub = XPublicKey::from(server_xpub_bytes);
    let pq_slice = server_pq_bytes.get(..1184).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid PQ public key length")
    })?;
    let pq_array: &[u8; 1184] = pq_slice
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PQ public key length"))?;
    let server_pq = EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(pq_array.into());

    let client_xpriv = EphemeralSecret::random_from_rng(&mut OsRng);
    let client_xpub = XPublicKey::from(&client_xpriv);
    let (ciphertext, pq_shared) = server_pq
        .encapsulate(&mut OsRng)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "KEM encapsulation failed"))?;

    let client_xpub_bytes = *client_xpub.as_bytes();
    let ciphertext_bytes = ciphertext.as_slice();
    let auth = encode_client_auth(
        &config.client_id,
        &client_xpub_bytes,
        ciphertext_bytes,
        &config.tunnel_token,
    );
    udp.send(&auth)?;

    let x_shared = client_xpriv.diffie_hellman(&server_xpub);
    let pq_bytes = pq_shared.as_slice();
    Ok(HybridHandshake::derive_session_key(
        x_shared.as_bytes(),
        pq_bytes,
    ))
}

fn structural_change(current: &ClientConfig, next: &ClientConfig) -> bool {
    current.server_endpoint != next.server_endpoint
        || current.tun_name != next.tun_name
        || current.tun_address != next.tun_address
        || current.tun_prefix != next.tun_prefix
        || current.mtu != next.mtu
        || current.dns_server != next.dns_server
}

fn set_status_message(
    status: &Arc<Mutex<AgentStatusReport>>,
    version: Option<u64>,
    error: Option<String>,
    message: &str,
    verbose: bool,
) {
    if let Ok(mut guard) = status.lock() {
        let version_changed = version.is_some_and(|value| guard.applied_version != Some(value));
        let error_changed = guard.last_error != error;
        let message_changed = guard.last_message.as_deref() != Some(message);
        if let Some(version) = version {
            guard.applied_version = Some(version);
        }
        guard.last_error = error;
        guard.last_message = Some(message.to_string());

        if verbose && (version_changed || error_changed || message_changed) {
            if let Some(err) = &guard.last_error {
                eprintln!("[client] {message}: {err}");
            } else {
                println!("[client] {message}");
            }
        }
    }
}

fn apply_platform_network_settings(config: &ClientConfig, verbose: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return apply_linux_network_settings(config, verbose);
    }
    #[cfg(target_os = "windows")]
    {
        return apply_windows_network_settings(config, verbose);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (config, verbose);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_network_settings(config: &ClientConfig, verbose: bool) -> io::Result<()> {
    let server_addr = config
        .server_endpoint
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let server_ip = match server_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows auto-route setup currently expects an IPv4 server endpoint",
            ))
        }
    };
    let gateway = windows_default_gateway()?;

    let _ = run_windows_cmd("route", &["delete", &server_ip]);
    run_windows_cmd(
        "route",
        &[
            "add",
            &server_ip,
            "mask",
            "255.255.255.255",
            &gateway,
            "metric",
            "5",
        ],
    )?;

    let _ = run_windows_cmd(
        "route",
        &["delete", "0.0.0.0", "mask", "0.0.0.0", &config.dns_server],
    );
    run_windows_cmd(
        "route",
        &[
            "add",
            "0.0.0.0",
            "mask",
            "0.0.0.0",
            &config.dns_server,
            "metric",
            "5",
        ],
    )?;

    run_windows_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={}", config.tun_name),
            "static",
            &config.dns_server,
            "primary",
        ],
    )?;

    if verbose {
        println!(
            "[client] Configured Windows route protection for {server_ip}, default route via {}, and DNS on {}",
            config.dns_server, config.tun_name
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_default_gateway() -> io::Result<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop",
        ])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gateway.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "unable to find an IPv4 default gateway for Windows route setup",
        ))
    } else {
        Ok(gateway)
    }
}

#[cfg(target_os = "windows")]
fn run_windows_cmd(program: &str, args: &[&str]) -> io::Result<()> {
    let output = std::process::Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no additional error output".to_string()
    };
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("command failed: {} {} ({detail})", program, args.join(" ")),
    ))
}

#[cfg(target_os = "linux")]
fn apply_linux_network_settings(config: &ClientConfig, verbose: bool) -> io::Result<()> {
    let server_ip = config
        .server_endpoint
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .ip()
        .to_string();
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let route = String::from_utf8_lossy(&output.stdout);
    let gateway = route
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1])
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "unable to determine default gateway")
        })?;
    let iface = route
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1])
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "unable to determine default interface",
            )
        })?;

    run_cmd(
        "ip",
        &[
            "route",
            "replace",
            &format!("{server_ip}/32"),
            "via",
            gateway,
            "dev",
            iface,
        ],
    )?;
    run_cmd(
        "ip",
        &["route", "replace", "default", "dev", &config.tun_name],
    )?;

    let dns_result = std::process::Command::new("resolvectl")
        .args(["dns", &config.tun_name, &config.dns_server])
        .status();
    if verbose {
        println!(
            "Configured Linux client route and attempted DNS setup for {}",
            config.tun_name
        );
    }
    if let Ok(status) = dns_result {
        if status.success() {
            let _ = std::process::Command::new("resolvectl")
                .args(["domain", &config.tun_name, "~."])
                .status();
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_cmd(program: &str, args: &[&str]) -> io::Result<()> {
    let status = std::process::Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("command failed: {} {}", program, args.join(" ")),
        ))
    }
}
