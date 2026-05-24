use crate::management_client::{load_or_enroll, AgentBootstrap};
use crate::models::AgentKind;
use std::io;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::crypto_logic::{HybridHandshake, ReplayGuard};
#[cfg(target_os = "linux")]
use crate::models::{AgentStatusReport, HeartbeatRequest, ServerConfig, StatusRequest};
#[cfg(target_os = "linux")]
use crate::tunnel_protocol::{
    compute_auth_tag, decode_client_auth, decode_client_hello, encode_server_hello,
};
#[cfg(target_os = "linux")]
use crate::TunParams;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

pub struct ServerArgs {
    pub management_url: String,
    pub enrollment_token: String,
    pub state_dir: PathBuf,
    pub node_name: String,
    pub verbose: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientSession {
    assigned_ip: Ipv4Addr,
    addr: SocketAddr,
    session_key: [u8; 32],
    replay_guard: Arc<Mutex<ReplayGuard>>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct SessionMaps {
    by_addr: HashMap<SocketAddr, ClientSession>,
    addr_by_client: HashMap<String, SocketAddr>,
    addr_by_ip: HashMap<Ipv4Addr, SocketAddr>,
}

#[cfg(not(target_os = "linux"))]
pub fn run(args: ServerArgs) -> io::Result<()> {
    let _ = args.verbose;
    let _ = load_or_enroll(&AgentBootstrap {
        kind: AgentKind::Server,
        management_url: args.management_url,
        enrollment_token: args.enrollment_token,
        node_name: args.node_name,
        state_dir: args.state_dir,
    })?;
    println!("Server mode requires Linux for TUN, NAT, firewall, and DoH proxy runtime.");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run(args: ServerArgs) -> io::Result<()> {
    let verbose = args.verbose;

    let (agent_state, manager_client) = load_or_enroll(&AgentBootstrap {
        kind: AgentKind::Server,
        management_url: args.management_url.clone(),
        enrollment_token: args.enrollment_token,
        node_name: args.node_name.clone(),
        state_dir: args.state_dir,
    })?;

    if verbose {
        println!(
            "[server] Agent {} is registered with manager {}",
            agent_state.agent_id, args.management_url
        );
    }

    let status = Arc::new(Mutex::new(AgentStatusReport::default()));
    let sessions = Arc::new(Mutex::new(SessionMaps::default()));
    let mut shared_config: Option<Arc<Mutex<ServerConfig>>> = None;
    let mut poll_interval = 15u64;

    loop {
        let snapshot = build_status_snapshot(&status, &sessions);
        let heartbeat = manager_client.heartbeat(&HeartbeatRequest {
            agent_id: agent_state.agent_id.clone(),
            agent_secret: agent_state.agent_secret.clone(),
            kind: AgentKind::Server,
            current_version: snapshot.applied_version,
            status: snapshot,
        });

        match heartbeat {
            Ok(response) => {
                poll_interval = response.poll_interval_seconds.max(5);
                if let Some(config) = response.server_config {
                    if shared_config.is_none() {
                        if !config.enabled {
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "server enrolled but currently disabled by manager",
                                verbose,
                            );
                        } else {
                            let config_ref = Arc::new(Mutex::new(config.clone()));
                            start_runtime(
                                config.clone(),
                                Arc::clone(&config_ref),
                                Arc::clone(&status),
                                Arc::clone(&sessions),
                                verbose,
                            )?;
                            shared_config = Some(config_ref);
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "managed VPN server runtime started",
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
                                "structural server config changed; restart process to apply listen/tun updates",
                                verbose,
                            );
                        } else {
                            apply_live_update(config_ref, &config)?;
                            reconcile_server_policy(&config)?;
                            set_status_message(
                                &status,
                                Some(config.version),
                                None,
                                "live policy update applied",
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

        let snapshot = build_status_snapshot(&status, &sessions);
        let _ = manager_client.status(&StatusRequest {
            agent_id: agent_state.agent_id.clone(),
            agent_secret: agent_state.agent_secret.clone(),
            kind: AgentKind::Server,
            status: snapshot,
        });

        thread::sleep(Duration::from_secs(poll_interval));
    }
}

#[cfg(target_os = "linux")]
fn start_runtime(
    initial_config: ServerConfig,
    shared_config: Arc<Mutex<ServerConfig>>,
    status: Arc<Mutex<AgentStatusReport>>,
    sessions: Arc<Mutex<SessionMaps>>,
    verbose: bool,
) -> io::Result<()> {
    if verbose {
        println!(
            "[server] Creating TUN {} at {}/{} and listening on {}",
            initial_config.tun_name,
            initial_config.tun_address,
            initial_config.tun_prefix,
            initial_config.listen_addr
        );
    }

    let dev = Arc::new(crate::create_tun(&TunParams {
        name: initial_config.tun_name.clone(),
        address_v4: initial_config.tun_address.clone(),
        prefix_v4: initial_config.tun_prefix,
        mtu: initial_config.mtu,
    })?);

    reconcile_server_policy(&initial_config)?;

    let udp = UdpSocket::bind(&initial_config.listen_addr)?;
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    spawn_dns_proxy(Arc::clone(&shared_config), Arc::clone(&status), verbose)?;

    let (pq_sk, pq_pk_bytes) = HybridHandshake::generate_pq_keys();
    let (server_xsec, server_xpub) = HybridHandshake::generate_x25519_keys();

    let udp_rx = udp.try_clone()?;
    let dev_rx = Arc::clone(&dev);
    let status_rx = Arc::clone(&status);
    let sessions_rx = Arc::clone(&sessions);
    let config_rx = Arc::clone(&shared_config);

    thread::spawn(move || -> io::Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp_rx.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let config = clone_config(&config_rx)?;
                    if !config.enabled {
                        continue;
                    }

                    if let Some(client_id) = decode_client_hello(&buf[..n]) {
                        if let Some(client) = allowed_client(&config, &client_id) {
                            if client.enabled {
                                let reply =
                                    encode_server_hello(server_xpub.as_bytes(), &pq_pk_bytes);
                                let _ = udp_rx.send_to(&reply, from);
                            } else if verbose {
                                println!(
                                    "[server] Ignored hello from {} for disabled client {}",
                                    from, client_id
                                );
                            }
                        } else if verbose {
                            println!(
                                "[server] Ignored hello from {} for unassigned/unknown client {}",
                                from, client_id
                            );
                        }
                        continue;
                    }

                    if let Some((client_id, client_xpub, pq_ciphertext, auth_tag)) =
                        decode_client_auth(&buf[..n])
                    {
                        if let Some(client) = allowed_client(&config, &client_id) {
                            if !client.enabled {
                                if verbose {
                                    println!(
                                        "[server] Ignored auth from {} for disabled client {}",
                                        from, client_id
                                    );
                                }
                                continue;
                            }

                            if !within_client_limit(&sessions_rx, config.max_clients, &client_id) {
                                if verbose {
                                    println!(
                                        "[server] Ignored auth from {} because client limit {} is reached",
                                        from, config.max_clients
                                    );
                                }
                                continue;
                            }

                            let expected = compute_auth_tag(
                                &client.tunnel_token,
                                &client_xpub,
                                &pq_ciphertext,
                            );
                            if auth_tag != expected {
                                if verbose {
                                    println!(
                                        "[server] Ignored auth from {} for client {} because the tunnel token did not match",
                                        from, client_id
                                    );
                                }
                                continue;
                            }

                            let client_xpub = x25519_dalek::PublicKey::from(client_xpub);
                            let x_shared = server_xsec.diffie_hellman(&client_xpub);
                            if let Ok(pq_shared) =
                                HybridHandshake::decapsulate_pq_key(&pq_sk, &pq_ciphertext)
                            {
                                let session_key = HybridHandshake::derive_session_key(
                                    x_shared.as_bytes(),
                                    &pq_shared,
                                );
                                register_session(
                                    &sessions_rx,
                                    from,
                                    &client_id,
                                    &client.assigned_ip,
                                    session_key,
                                )?;
                                set_connected_clients(&status_rx, &sessions_rx);
                                if verbose {
                                    println!("Accepted managed client {} from {}", client_id, from);
                                }
                            }
                        } else if verbose {
                            println!(
                                "[server] Ignored auth from {} for unassigned/unknown client {}",
                                from, client_id
                            );
                        }
                        continue;
                    }

                    if let Some(session) = lookup_session_by_addr(&sessions_rx, &from)? {
                        let is_fresh = session
                            .replay_guard
                            .lock()
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "replay guard lock failed")
                            })?
                            .is_fresh_packet(&buf[..n]);
                        if is_fresh {
                            if let Some(packet) =
                                HybridHandshake::decrypt_data(&session.session_key, &buf[..n])
                            {
                                if packet_source_matches(&packet, session.assigned_ip) {
                                    let _ = dev_rx.send(&packet);
                                }
                            }
                        } else if verbose {
                            println!("[server] Dropped replayed or malformed packet from {from}");
                        }
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
                        "server UDP receive loop failed",
                        verbose,
                    );
                }
            }
        }
    });

    let udp_tx = udp.try_clone()?;
    let dev_tx = Arc::clone(&dev);
    let sessions_tx = Arc::clone(&sessions);
    let status_tx = Arc::clone(&status);

    thread::spawn(move || -> io::Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = dev_tx.recv(&mut buf)?;
            if let Some(destination) = packet_destination(&buf[..n]) {
                if let Some(session) = lookup_session_by_ip(&sessions_tx, destination)? {
                    let encrypted = HybridHandshake::encrypt_data(&session.session_key, &buf[..n]);
                    let _ = udp_tx.send_to(&encrypted, session.addr);
                }
            }
            set_connected_clients(&status_tx, &sessions_tx);
        }
    });

    Ok(())
}

#[cfg(target_os = "linux")]
fn structural_change(current: &ServerConfig, next: &ServerConfig) -> bool {
    current.listen_addr != next.listen_addr
        || current.tun_name != next.tun_name
        || current.tun_address != next.tun_address
        || current.tun_prefix != next.tun_prefix
        || current.mtu != next.mtu
        || current.dns.bind_addr != next.dns.bind_addr
}

#[cfg(target_os = "linux")]
fn apply_live_update(
    shared_config: &Arc<Mutex<ServerConfig>>,
    next: &ServerConfig,
) -> io::Result<()> {
    let mut config = shared_config
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "config lock failed"))?;
    *config = next.clone();
    Ok(())
}

#[cfg(target_os = "linux")]
fn clone_config(shared_config: &Arc<Mutex<ServerConfig>>) -> io::Result<ServerConfig> {
    shared_config
        .lock()
        .map(|config| config.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "config lock failed"))
}

#[cfg(target_os = "linux")]
fn allowed_client<'a>(
    config: &'a ServerConfig,
    client_id: &str,
) -> Option<&'a crate::models::ManagedClientRecord> {
    config
        .allowed_clients
        .iter()
        .find(|client| client.client_id == client_id)
}

#[cfg(target_os = "linux")]
fn within_client_limit(
    sessions: &Arc<Mutex<SessionMaps>>,
    max_clients: usize,
    client_id: &str,
) -> bool {
    sessions
        .lock()
        .map(|map| map.by_addr.len() < max_clients || map.addr_by_client.contains_key(client_id))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn register_session(
    sessions: &Arc<Mutex<SessionMaps>>,
    addr: SocketAddr,
    client_id: &str,
    assigned_ip: &str,
    session_key: [u8; 32],
) -> io::Result<()> {
    let assigned_ip = assigned_ip
        .parse::<Ipv4Addr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut map = sessions
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "session lock failed"))?;

    if let Some(previous_addr) = map.addr_by_client.insert(client_id.to_string(), addr) {
        if let Some(previous_session) = map.by_addr.remove(&previous_addr) {
            map.addr_by_ip.remove(&previous_session.assigned_ip);
        }
    }

    map.addr_by_ip.insert(assigned_ip, addr);
    map.by_addr.insert(
        addr,
        ClientSession {
            assigned_ip,
            addr,
            session_key,
            replay_guard: Arc::new(Mutex::new(ReplayGuard::default())),
        },
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn lookup_session_by_addr(
    sessions: &Arc<Mutex<SessionMaps>>,
    addr: &SocketAddr,
) -> io::Result<Option<ClientSession>> {
    sessions
        .lock()
        .map(|map| map.by_addr.get(addr).cloned())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "session lock failed"))
}

#[cfg(target_os = "linux")]
fn lookup_session_by_ip(
    sessions: &Arc<Mutex<SessionMaps>>,
    destination: Ipv4Addr,
) -> io::Result<Option<ClientSession>> {
    let map = sessions
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "session lock failed"))?;
    Ok(map
        .addr_by_ip
        .get(&destination)
        .and_then(|addr| map.by_addr.get(addr))
        .cloned())
}

#[cfg(target_os = "linux")]
fn build_status_snapshot(
    status: &Arc<Mutex<AgentStatusReport>>,
    sessions: &Arc<Mutex<SessionMaps>>,
) -> AgentStatusReport {
    let mut snapshot = status.lock().map(|state| state.clone()).unwrap_or_default();
    snapshot.connected_clients = Some(
        sessions
            .lock()
            .map(|map| map.by_addr.len())
            .unwrap_or_default(),
    );
    snapshot
}

#[cfg(target_os = "linux")]
fn set_connected_clients(
    status: &Arc<Mutex<AgentStatusReport>>,
    sessions: &Arc<Mutex<SessionMaps>>,
) {
    let count = sessions
        .lock()
        .map(|map| map.by_addr.len())
        .unwrap_or_default();
    if let Ok(mut guard) = status.lock() {
        guard.connected_clients = Some(count);
    }
}

#[cfg(target_os = "linux")]
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
                eprintln!("[server] {message}: {err}");
            } else {
                println!("[server] {message}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn packet_source_matches(packet: &[u8], expected: Ipv4Addr) -> bool {
    packet_source(packet)
        .map(|source| source == expected)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn packet_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

#[cfg(target_os = "linux")]
fn packet_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(target_os = "linux")]
fn spawn_dns_proxy(
    shared_config: Arc<Mutex<ServerConfig>>,
    status: Arc<Mutex<AgentStatusReport>>,
    verbose: bool,
) -> io::Result<()> {
    let bind_addr = clone_config(&shared_config)?.dns.bind_addr;
    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    thread::spawn(move || {
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                set_status_message(
                    &status,
                    None,
                    Some(err.to_string()),
                    "failed to create DoH client",
                    verbose,
                );
                return;
            }
        };

        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let config = match clone_config(&shared_config) {
                        Ok(config) => config,
                        Err(err) => {
                            set_status_message(
                                &status,
                                None,
                                Some(err.to_string()),
                                "failed to read DNS config",
                                verbose,
                            );
                            continue;
                        }
                    };
                    if !config.enabled {
                        continue;
                    }
                    match forward_doh_query(&client, &config.dns.doh_url, &buf[..n]) {
                        Ok(response) => {
                            let _ = socket.send_to(&response, peer);
                            if verbose {
                                println!("Forwarded DNS query for {} bytes via DoH", n);
                            }
                        }
                        Err(err) => {
                            set_status_message(
                                &status,
                                None,
                                Some(err.to_string()),
                                "DoH resolution failed",
                                verbose,
                            );
                        }
                    }
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => {
                    set_status_message(
                        &status,
                        None,
                        Some(err.to_string()),
                        "DNS proxy loop failed",
                        verbose,
                    );
                }
            }
        }
    });

    Ok(())
}

#[cfg(target_os = "linux")]
fn forward_doh_query(
    client: &reqwest::blocking::Client,
    doh_url: &str,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let response = client
        .post(doh_url)
        .header("accept", "application/dns-message")
        .header("content-type", "application/dns-message")
        .body(query.to_vec())
        .send()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("DoH upstream returned {}", response.status()),
        ));
    }

    response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

#[cfg(target_os = "linux")]
fn reconcile_server_policy(config: &ServerConfig) -> io::Result<()> {
    if !config.setup_nat {
        return Ok(());
    }
    let wan_iface = config.nat_iface.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "NAT interface is required when setup_nat is enabled",
        )
    })?;

    run_cmd("ip", &["link", "set", "dev", &config.tun_name, "up"])?;
    run_cmd(
        "ip",
        &[
            "route",
            "replace",
            &config.client_cidr,
            "dev",
            &config.tun_name,
        ],
    )?;
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    ensure_chain("filter", "NTZ-FWD")?;
    ensure_jump("filter", "FORWARD", "NTZ-FWD")?;
    flush_chain("filter", "NTZ-FWD")?;
    for destination in &config.firewall.protected_destinations {
        add_rule(
            "filter",
            &["-A", "NTZ-FWD", "-d", destination, "-j", "DROP"],
        )?;
    }
    for destination in &config.firewall.blocked_destinations {
        add_rule(
            "filter",
            &["-A", "NTZ-FWD", "-d", destination, "-j", "DROP"],
        )?;
    }
    add_rule(
        "filter",
        &[
            "-A",
            "NTZ-FWD",
            "-i",
            &config.tun_name,
            "-o",
            wan_iface,
            "-j",
            "ACCEPT",
        ],
    )?;
    ensure_established_rule(&config.tun_name, wan_iface)?;
    ensure_chain("nat", "NTZ-SNAT")?;
    ensure_jump("nat", "POSTROUTING", "NTZ-SNAT")?;
    flush_chain("nat", "NTZ-SNAT")?;
    for client in config
        .allowed_clients
        .iter()
        .filter(|client| client.enabled)
    {
        if let Some(egress_ip) = client.egress_ip.as_deref() {
            add_rule(
                "nat",
                &[
                    "-A",
                    "NTZ-SNAT",
                    "-s",
                    &format!("{}/32", client.assigned_ip),
                    "-o",
                    wan_iface,
                    "-j",
                    "SNAT",
                    "--to-source",
                    egress_ip,
                ],
            )?;
        }
    }
    if let Some(default_egress) = config.egress_ips.first() {
        add_rule(
            "nat",
            &[
                "-A",
                "NTZ-SNAT",
                "-s",
                &config.client_cidr,
                "-o",
                wan_iface,
                "-j",
                "SNAT",
                "--to-source",
                default_egress,
            ],
        )?;
    } else {
        add_rule(
            "nat",
            &[
                "-A",
                "NTZ-SNAT",
                "-s",
                &config.client_cidr,
                "-o",
                wan_iface,
                "-j",
                "MASQUERADE",
            ],
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_cmd(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
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
}

#[cfg(target_os = "linux")]
fn ensure_chain(table: &str, chain: &str) -> io::Result<()> {
    if probe_cmd_success("iptables", &["-t", table, "-L", chain])? {
        Ok(())
    } else {
        run_cmd("iptables", &["-t", table, "-N", chain])
    }
}

#[cfg(target_os = "linux")]
fn ensure_jump(table: &str, source_chain: &str, target_chain: &str) -> io::Result<()> {
    if probe_cmd_success(
        "iptables",
        &["-t", table, "-C", source_chain, "-j", target_chain],
    )? {
        Ok(())
    } else {
        run_cmd(
            "iptables",
            &["-t", table, "-A", source_chain, "-j", target_chain],
        )
    }
}

#[cfg(target_os = "linux")]
fn flush_chain(table: &str, chain: &str) -> io::Result<()> {
    run_cmd("iptables", &["-t", table, "-F", chain])
}

#[cfg(target_os = "linux")]
fn add_rule(table: &str, args: &[&str]) -> io::Result<()> {
    let mut full = vec!["-t", table];
    full.extend_from_slice(args);
    run_cmd("iptables", &full)
}

#[cfg(target_os = "linux")]
fn ensure_established_rule(tun_name: &str, wan_iface: &str) -> io::Result<()> {
    if probe_cmd_success(
        "iptables",
        &[
            "-C",
            "FORWARD",
            "-i",
            wan_iface,
            "-o",
            tun_name,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )? {
        Ok(())
    } else {
        run_cmd(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-i",
                wan_iface,
                "-o",
                tun_name,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )
    }
}

#[cfg(target_os = "linux")]
fn probe_cmd_success(program: &str, args: &[&str]) -> io::Result<bool> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}
