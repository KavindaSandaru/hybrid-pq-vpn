use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Server,
    Client,
}

impl AgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    FullTunnel,
}

impl Default for RouteMode {
    fn default() -> Self {
        Self::FullTunnel
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub blocked_destinations: Vec<String>,
    pub protected_destinations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsProfile {
    pub bind_addr: String,
    pub doh_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectedClient {
    pub device_name: String,
    pub vpn_ip: String,
    pub public_ip: String,
    pub connected_since: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedClientRecord {
    pub client_id: String,
    pub device_name: String,
    pub enabled: bool,
    pub assigned_ip: String,
    pub tunnel_token: String,
    pub egress_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub version: u64,
    pub server_id: String,
    pub enabled: bool,
    pub node_name: String,
    pub listen_addr: String,
    pub public_endpoint: String,
    pub tun_name: String,
    pub tun_address: String,
    pub tun_prefix: u8,
    pub mtu: Option<u16>,
    pub client_cidr: String,
    pub max_clients: usize,
    pub nat_iface: Option<String>,
    pub setup_nat: bool,
    pub firewall: FirewallPolicy,
    pub dns: DnsProfile,
    pub egress_ips: Vec<String>,
    pub allowed_clients: Vec<ManagedClientRecord>,
    pub poll_interval_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub version: u64,
    pub client_id: String,
    pub enabled: bool,
    pub device_name: String,
    pub server_id: String,
    pub server_endpoint: String,
    pub tunnel_token: String,
    pub tun_name: String,
    pub tun_address: String,
    pub tun_prefix: u8,
    pub mtu: Option<u16>,
    pub dns_server: String,
    pub route_mode: RouteMode,
    pub egress_ip: Option<String>,
    pub poll_interval_seconds: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentStatusReport {
    pub applied_version: Option<u64>,
    pub connected_clients: Option<usize>,
    pub connected_client_list: Option<Vec<ConnectedClient>>,
    pub public_ip: Option<String>,
    pub country: Option<String>,
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub last_error: Option<String>,
    pub last_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub kind: AgentKind,
    pub enrollment_token: String,
    pub node_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub agent_id: String,
    pub agent_secret: String,
    pub poll_interval_seconds: u64,
    pub config_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub agent_secret: String,
    pub kind: AgentKind,
    pub current_version: Option<u64>,
    pub status: AgentStatusReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub poll_interval_seconds: u64,
    pub config_changed: bool,
    pub server_config: Option<ServerConfig>,
    pub client_config: Option<ClientConfig>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusRequest {
    pub agent_id: String,
    pub agent_secret: String,
    pub kind: AgentKind,
    pub status: AgentStatusReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedAgentState {
    pub agent_id: String,
    pub agent_secret: String,
    pub kind: AgentKind,
    pub enrolled_at: String,
}
