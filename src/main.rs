use clap::Parser;
use std::io;
use std::path::PathBuf;

mod agent_state;
mod client;
pub mod crypto_logic;
mod management_client;
mod manager;
mod models;
mod server;
mod tunnel_protocol;

use tun_rs::{DeviceBuilder, Layer, SyncDevice};

#[derive(Clone, Debug)]
pub struct TunParams {
    pub name: String,
    pub address_v4: String,
    pub prefix_v4: u8,
    pub mtu: Option<u16>,
}

pub(crate) fn create_tun(params: &TunParams) -> io::Result<SyncDevice> {
    let mut builder = DeviceBuilder::new().name(&params.name).layer(Layer::L3);

    builder = builder.ipv4(params.address_v4.clone(), params.prefix_v4, None);

    if let Some(mtu) = params.mtu {
        builder = builder.mtu(mtu);
    }

    #[cfg(windows)]
    if let Some(wintun_path) = find_wintun_dll() {
        builder = builder.wintun_file(wintun_path.to_string_lossy().into_owned());
    }

    builder.build_sync().map_err(annotate_tun_error)
}

fn annotate_tun_error(err: impl std::fmt::Display) -> io::Error {
    let message = err.to_string();

    #[cfg(windows)]
    {
        if message.contains("GetProcAddress failed") || message.contains("LoadLibrary") {
            let detail = match find_wintun_dll() {
                Some(path) => format!(
                    "A wintun.dll was found at '{}', but it looks incompatible. Use the official DLL from wintun.net that matches this PC architecture, and run PowerShell as Administrator.",
                    path.display()
                ),
                None => "No wintun.dll was found in the project directory or next to the built executable. Download the official DLL from wintun.net and place it next to target\\debug\\ntz-proto.exe or in this project folder, then run PowerShell as Administrator.".to_string(),
            };

            return io::Error::new(io::ErrorKind::Other, format!("{message}. {detail}"));
        }
    }

    io::Error::new(io::ErrorKind::Other, message)
}

#[cfg(windows)]
fn find_wintun_dll() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("wintun.dll"));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("wintun.dll"));
        }
    }

    candidates.into_iter().find(|path| path.is_file())
}

#[derive(Parser, Debug)]
enum Mode {
    /// Run as VPN client managed by the control plane
    Client {
        #[arg(long)]
        management_url: String,

        #[arg(long)]
        enrollment_token: String,

        #[arg(long, default_value = "./state/client")]
        state_dir: PathBuf,

        #[arg(long, default_value = "ntz-client")]
        device_name: String,

        #[arg(long)]
        verbose: bool,
    },

    /// Run as VPN server managed by the control plane
    Server {
        #[arg(long)]
        management_url: String,

        #[arg(long)]
        enrollment_token: String,

        #[arg(long, default_value = "./state/server")]
        state_dir: PathBuf,

        #[arg(long, default_value = "ntz-server")]
        node_name: String,

        #[arg(long)]
        verbose: bool,
    },

    /// Run the central management server and web portal
    Manager {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: std::net::SocketAddr,

        #[arg(long, default_value = "./state/manager/ntz-manager.sqlite3")]
        db: PathBuf,

        #[arg(long, default_value = "admin")]
        admin_user: String,

        #[arg(long, default_value = "admin123")]
        admin_pass: String,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Hybrid Post-Quantum VPN Tunnel")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

fn main() -> io::Result<()> {

    env_logger::init();

    println!("NTZ starting...");

    let args = Args::parse();

    match args.mode {
        Mode::Client {
            management_url,
            enrollment_token,
            state_dir,
            device_name,
            verbose,
        } => client::run(client::ClientArgs {
            management_url,
            enrollment_token,
            state_dir,
            device_name,
            verbose,
        }),

        Mode::Server {
            management_url,
            enrollment_token,
            state_dir,
            node_name,
            verbose,
        } => server::run(server::ServerArgs {
            management_url,
            enrollment_token,
            state_dir,
            node_name,
            verbose,
        }),

        Mode::Manager {
            bind,
            db,
            admin_user,
            admin_pass,
        } => manager::run(manager::ManagerArgs {
            bind,
            db_path: db,
            admin_user,
            admin_pass,
        }),
    }
}