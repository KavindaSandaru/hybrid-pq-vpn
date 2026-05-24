use crate::models::{
    AgentKind, AgentStatusReport, ClientConfig, DnsProfile, EnrollmentRequest, EnrollmentResponse,
    FirewallPolicy, HeartbeatRequest, HeartbeatResponse, ManagedClientRecord, RouteMode,
    ServerConfig, StatusRequest, StatusResponse,
};
use axum::extract::{Form, Path, State};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct ManagerArgs {
    pub bind: SocketAddr,
    pub db_path: PathBuf,
    pub admin_user: String,
    pub admin_pass: String,
}

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
    sessions: Arc<Mutex<HashMap<String, String>>>,
    log_tx: broadcast::Sender<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    kind: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct GlobalSettingsForm {
    listen_addr: String,
    public_endpoint: String,
    tun_name: String,
    tun_address: String,
    tun_prefix: u8,
    client_cidr: String,
    mtu: String,
    nat_iface: String,
    setup_nat: Option<String>,
    max_clients: usize,
    doh_url: String,
    dns_bind_addr: String,
    blocked_ips: String,
    protected_ips: String,
    egress_ips: String,
}

#[derive(Debug, Deserialize)]
struct ServerForm {
    listen_addr: String,
    public_endpoint: String,
    nat_iface: String,
    max_clients: usize,
    enabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientForm {
    assigned_ip: String,
    server_id: String,
    egress_ip: String,
    enabled: Option<String>,
}

#[derive(Clone)]
struct ServerRow {
    server_id: String,
    node_name: String,
    enabled: bool,
    listen_addr: String,
    public_endpoint: String,
    nat_iface: String,
    max_clients: usize,
    last_seen: String,
    current_version: Option<u64>,
    last_error: String,
    last_message: String,
    connected_clients: usize,
}

#[derive(Clone)]
struct ClientRow {
    client_id: String,
    device_name: String,
    enabled: bool,
    assigned_ip: String,
    server_id: String,
    egress_ip: String,
    last_seen: String,
    current_version: Option<u64>,
    last_error: String,
    last_message: String,
}

#[derive(Clone)]
struct TokenRow {
    token: String,
    kind: String,
    label: String,
    created_at: String,
    used_at: String,
}

pub fn run(args: ManagerArgs) -> io::Result<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    runtime.block_on(async move { run_async(args).await })
}

async fn run_async(args: ManagerArgs) -> io::Result<()> {
    initialize_db(&args.db_path, &args.admin_user, &args.admin_pass)?;

    let (log_tx, _) = broadcast::channel(1000);

    let state = AppState {
        db_path: args.db_path.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        log_tx,
    };

    let app = Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/", get(dashboard))
        .route("/tokens", post(create_token))
        .route("/settings", post(update_settings))
        .route("/servers/:id", post(update_server))
        .route("/servers/:id/delete", post(delete_server))
        .route("/clients/:id", post(update_client))
        .route("/clients/:id/delete", post(delete_client))
        .route("/api/agent/enroll", post(api_enroll))
        .route("/api/agent/heartbeat", post(api_heartbeat))
        .route("/api/agent/status", post(api_status))
        .route("/api/alerts", get(api_alerts))
        .route("/api/logs", get(api_logs))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::AddrNotAvailable, err.to_string()))?;

    println!("Management portal listening on http://{}", args.bind);
    axum::serve(listener, app)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}

async fn login_page() -> Html<String> {
    Html(render_login(None))
}

async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<impl IntoResponse, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    if !verify_admin(&conn, &form.username, &form.password).map_err(internal_response)? {
        return Ok(Html(render_login(Some("Invalid username or password"))).into_response());
    }

    let session_token = random_token();
    state
        .sessions
        .lock()
        .map_err(|_| {
            internal_response(io::Error::new(io::ErrorKind::Other, "session lock failed"))
        })?
        .insert(session_token.clone(), form.username);

    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "ntz_session={}; HttpOnly; Path=/; SameSite=Lax",
            session_token
        ))
        .map_err(internal_response)?,
    );
    Ok(response)
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Response> {
    if let Some(token) = session_token_from_headers(&headers) {
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.remove(&token);
        }
    }

    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("ntz_session=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"),
    );
    Ok(response)
}

async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let settings = load_settings(&conn).map_err(internal_response)?;
    let servers = list_servers(&conn).map_err(internal_response)?;
    let clients = list_clients(&conn).map_err(internal_response)?;
    let tokens = list_tokens(&conn).map_err(internal_response)?;
    let version = current_config_version(&conn).map_err(internal_response)?;

    Ok(Html(render_dashboard(
        version, &settings, &servers, &clients, &tokens,
    )))
}

async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let kind = match form.kind.as_str() {
        "server" => AgentKind::Server,
        "client" => AgentKind::Client,
        _ => {
            return Ok(simple_redirect_with_error(
                "/",
                "Unsupported token type requested",
            ))
        }
    };

    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let token = random_token();
    conn.execute(
        "INSERT INTO bootstrap_tokens (token, kind, label, created_at, used_at)
         VALUES (?1, ?2, ?3, ?4, NULL)",
        params![
            token,
            kind.as_str(),
            form.label.trim(),
            Utc::now().to_rfc3339()
        ],
    )
    .map_err(internal_response)?;

    Ok(Redirect::to("/").into_response())
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GlobalSettingsForm>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;

    save_setting(&tx, "listen_addr", form.listen_addr.trim())?;
    save_setting(&tx, "public_endpoint", form.public_endpoint.trim())?;
    save_setting(&tx, "tun_name", form.tun_name.trim())?;
    save_setting(&tx, "tun_address", form.tun_address.trim())?;
    save_setting(&tx, "tun_prefix", &form.tun_prefix.to_string())?;
    save_setting(&tx, "client_cidr", form.client_cidr.trim())?;
    save_setting(&tx, "mtu", form.mtu.trim())?;
    save_setting(&tx, "nat_iface", form.nat_iface.trim())?;
    save_setting(&tx, "setup_nat", bool_to_setting(form.setup_nat.is_some()))?;
    save_setting(&tx, "max_clients", &form.max_clients.to_string())?;
    save_setting(&tx, "doh_url", form.doh_url.trim())?;
    save_setting(&tx, "dns_bind_addr", form.dns_bind_addr.trim())?;
    save_setting(
        &tx,
        "blocked_ips_json",
        &to_json_list(&parse_lines(&form.blocked_ips)).map_err(internal_response)?,
    )?;
    save_setting(
        &tx,
        "protected_ips_json",
        &to_json_list(&parse_lines(&form.protected_ips)).map_err(internal_response)?,
    )?;
    save_setting(
        &tx,
        "egress_ips_json",
        &to_json_list(&parse_lines(&form.egress_ips)).map_err(internal_response)?,
    )?;
    bump_config_version(&tx)?;
    tx.commit().map_err(internal_response)?;

    Ok(Redirect::to("/"))
}

async fn update_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ServerForm>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;
    tx.execute(
        "UPDATE server_nodes
         SET listen_addr = ?1, public_endpoint = ?2, nat_iface = ?3, max_clients = ?4, enabled = ?5
         WHERE server_id = ?6",
        params![
            form.listen_addr.trim(),
            form.public_endpoint.trim(),
            empty_to_none(form.nat_iface.trim()),
            form.max_clients as i64,
            bool_to_i64(form.enabled.is_some()),
            id
        ],
    )
    .map_err(internal_response)?;
    bump_config_version(&tx)?;
    tx.commit().map_err(internal_response)?;
    Ok(Redirect::to("/"))
}

async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ClientForm>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;
    tx.execute(
        "UPDATE client_nodes
         SET assigned_ip = ?1, server_id = ?2, egress_ip = ?3, enabled = ?4
         WHERE client_id = ?5",
        params![
            form.assigned_ip.trim(),
            empty_to_none(form.server_id.trim()),
            empty_to_none(form.egress_ip.trim()),
            bool_to_i64(form.enabled.is_some()),
            id
        ],
    )
    .map_err(internal_response)?;
    bump_config_version(&tx)?;
    tx.commit().map_err(internal_response)?;
    Ok(Redirect::to("/"))
}

async fn delete_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;
    delete_server_record(&tx, &id)?;
    tx.commit().map_err(internal_response)?;
    Ok(Redirect::to("/"))
}

async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Response> {
    require_session(&state, &headers)?;
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;
    delete_client_record(&tx, &id)?;
    tx.commit().map_err(internal_response)?;
    Ok(Redirect::to("/"))
}

fn delete_server_record(conn: &Connection, server_id: &str) -> Result<(), Response> {
    conn.execute(
        "UPDATE client_nodes SET server_id = NULL WHERE server_id = ?1",
        params![server_id],
    )
    .map_err(internal_response)?;
    conn.execute(
        "DELETE FROM server_nodes WHERE server_id = ?1",
        params![server_id],
    )
    .map_err(internal_response)?;
    conn.execute(
        "DELETE FROM agents WHERE agent_id = ?1 AND kind = 'server'",
        params![server_id],
    )
    .map_err(internal_response)?;
    bump_config_version(conn)?;
    Ok(())
}

fn delete_client_record(conn: &Connection, client_id: &str) -> Result<(), Response> {
    conn.execute(
        "DELETE FROM client_nodes WHERE client_id = ?1",
        params![client_id],
    )
    .map_err(internal_response)?;
    conn.execute(
        "DELETE FROM agents WHERE agent_id = ?1 AND kind = 'client'",
        params![client_id],
    )
    .map_err(internal_response)?;
    bump_config_version(conn)?;
    Ok(())
}

async fn api_enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;
    let tx = conn.unchecked_transaction().map_err(internal_response)?;
    let token_row = tx
        .query_row(
            "SELECT kind, used_at FROM bootstrap_tokens WHERE token = ?1",
            params![request.enrollment_token.trim()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(internal_response)?;

    let (kind, used_at) = match token_row {
        Some(value) => value,
        None => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid enrollment token",
            ))
        }
    };

    if used_at.is_some() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "bootstrap token already used",
        ));
    }

    if kind != request.kind.as_str() {
        return Err(api_error(StatusCode::BAD_REQUEST, "token kind mismatch"));
    }

    let agent_id = Uuid::new_v4().to_string();
    let agent_secret = random_token();
    let config_version = current_config_version(&tx).map_err(internal_response)?;

    tx.execute(
        "INSERT INTO agents
         (agent_id, kind, node_name, agent_secret, enabled, current_version, last_seen, last_error, last_message, connected_clients)
         VALUES (?1, ?2, ?3, ?4, 1, NULL, NULL, '', '', 0)",
        params![
            agent_id,
            request.kind.as_str(),
            request.node_name.trim(),
            agent_secret
        ],
    )
    .map_err(internal_response)?;

    match request.kind {
        AgentKind::Server => {
            enroll_server(&tx, &agent_id, &request.node_name).map_err(internal_response)?
        }
        AgentKind::Client => {
            enroll_client(&tx, &agent_id, &request.node_name).map_err(internal_response)?
        }
    }

    tx.execute(
        "UPDATE bootstrap_tokens SET used_at = ?1 WHERE token = ?2",
        params![Utc::now().to_rfc3339(), request.enrollment_token.trim()],
    )
    .map_err(internal_response)?;
    tx.commit().map_err(internal_response)?;

    Ok(Json(EnrollmentResponse {
        agent_id,
        agent_secret,
        poll_interval_seconds: 15,
        config_version,
    }))
}

async fn api_heartbeat(
    State(state): State<AppState>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;

    validate_agent(
        &conn,
        &request.agent_id,
        &request.agent_secret,
        &request.kind,
    )
    .map_err(internal_response)?;

    process_security_report(&conn, &request.agent_id, &request.kind, &request.status)
        .map_err(internal_response)?;

    conn.execute(
        "UPDATE agents
         SET last_seen = ?1, current_version = ?2, last_error = ?3, last_message = ?4,
             connected_clients = ?5, current_country = ?6, current_public_ip = ?7,
             upload_bytes = ?8, download_bytes = ?9
         WHERE agent_id = ?10",
        params![
            Utc::now().to_rfc3339(),
            request.status.applied_version.map(|value| value as i64),
            request.status.last_error.clone().unwrap_or_default(),
            request.status.last_message.clone().unwrap_or_default(),
            request.status.connected_clients.unwrap_or_default() as i64,
            request.status.country.clone().unwrap_or_default(),
            request.status.public_ip.clone().unwrap_or_default(),
            option_u64_to_i64(request.status.upload_bytes),
            option_u64_to_i64(request.status.download_bytes),
            request.agent_id
        ],
    )
    .map_err(internal_response)?;

    let _ = state.log_tx.send(format!(
        "[{}] {} heartbeat received",
        request.kind.as_str(),
        request.agent_id
    ));
    write_log(
        &conn,
        "INFO",
        &format!(
            "[{}] {} heartbeat received",
            request.kind.as_str(),
            request.agent_id
        ),
    );

    let version = current_config_version(&conn).map_err(internal_response)?;

    let config_changed = request.current_version.unwrap_or_default() != version;

    let (server_config, client_config) = match request.kind {
        AgentKind::Server if config_changed => (
            Some(build_server_config(&conn, &request.agent_id).map_err(internal_response)?),
            None,
        ),

        AgentKind::Client if config_changed => (
            None,
            Some(build_client_config(&conn, &request.agent_id).map_err(internal_response)?),
        ),

        AgentKind::Server => (None, None),

        AgentKind::Client => (None, None),
    };

    Ok(Json(HeartbeatResponse {
        ok: true,
        poll_interval_seconds: 15,
        config_changed,
        server_config,
        client_config,
        message: Some("heartbeat accepted".to_string()),
    }))
}

async fn api_status(
    State(state): State<AppState>,
    Json(request): Json<StatusRequest>,
) -> Result<Json<StatusResponse>, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;

    validate_agent(
        &conn,
        &request.agent_id,
        &request.agent_secret,
        &request.kind,
    )
    .map_err(internal_response)?;

    process_security_report(&conn, &request.agent_id, &request.kind, &request.status)
        .map_err(internal_response)?;

    conn.execute(
        "UPDATE agents
         SET last_seen = ?1, current_version = ?2, last_error = ?3, last_message = ?4,
             connected_clients = ?5, current_country = ?6, current_public_ip = ?7,
             upload_bytes = ?8, download_bytes = ?9
         WHERE agent_id = ?10",
        params![
            Utc::now().to_rfc3339(),
            request.status.applied_version.map(|value| value as i64),
            request.status.last_error.clone().unwrap_or_default(),
            request.status.last_message.clone().unwrap_or_default(),
            request.status.connected_clients.unwrap_or_default() as i64,
            request.status.country.clone().unwrap_or_default(),
            request.status.public_ip.clone().unwrap_or_default(),
            option_u64_to_i64(request.status.upload_bytes),
            option_u64_to_i64(request.status.download_bytes),
            request.agent_id
        ],
    )
    .map_err(internal_response)?;

    let _ = state.log_tx.send(format!(
        "[{}] {} status updated",
        request.kind.as_str(),
        request.agent_id
    ));
    write_log(
        &conn,
        "INFO",
        &format!(
            "[{}] {} status updated",
            request.kind.as_str(),
            request.agent_id
        ),
    );

    Ok(Json(StatusResponse { ok: true }))
}

async fn api_logs(State(state): State<AppState>) -> Result<Json<Vec<String>>, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;

    let mut stmt = conn
        .prepare(
            "SELECT timestamp, level, message
             FROM logs
             ORDER BY id DESC
             LIMIT 100",
        )
        .map_err(internal_response)?;

    let rows = stmt
        .query_map([], |row| {
            let timestamp: String = row.get(0)?;

            let level: String = row.get(1)?;

            let message: String = row.get(2)?;

            Ok(format!("[{}] [{}] {}", timestamp, level, message))
        })
        .map_err(internal_response)?;

    let logs: Vec<String> = rows.filter_map(Result::ok).collect();

    Ok(Json(logs))
}

async fn api_alerts(State(state): State<AppState>) -> Result<Json<Vec<String>>, Response> {
    let conn = open_db(&state.db_path).map_err(internal_response)?;

    let mut stmt = conn
        .prepare(
            "SELECT timestamp, level, agent_id, message
             FROM security_alerts
             ORDER BY id DESC
             LIMIT 50",
        )
        .map_err(internal_response)?;

    let rows = stmt
        .query_map([], |row| {
            Ok(format!(
                "[{}] [{}] {} - {}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(internal_response)?;

    Ok(Json(rows.filter_map(Result::ok).collect()))
}

fn initialize_db(db_path: &FsPath, admin_user: &str, admin_pass: &str) -> io::Result<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(db_path)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            message TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS client_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            connected_at TEXT NOT NULL,
            public_ip TEXT,
            country TEXT,
            status_message TEXT
        );
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bootstrap_tokens (
            token TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            node_name TEXT NOT NULL,
            agent_secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            current_version INTEGER,
            last_seen TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            last_message TEXT NOT NULL DEFAULT '',
            connected_clients INTEGER NOT NULL DEFAULT 0,
            current_country TEXT NOT NULL DEFAULT '',
            current_public_ip TEXT NOT NULL DEFAULT '',
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS server_nodes (
            server_id TEXT PRIMARY KEY,
            node_name TEXT NOT NULL,
            listen_addr TEXT NOT NULL,
            public_endpoint TEXT NOT NULL,
            tun_name TEXT NOT NULL,
            tun_address TEXT NOT NULL,
            tun_prefix INTEGER NOT NULL,
            mtu INTEGER,
            client_cidr TEXT NOT NULL,
            nat_iface TEXT,
            setup_nat INTEGER NOT NULL DEFAULT 1,
            max_clients INTEGER NOT NULL,
            egress_ips_json TEXT NOT NULL,
            blocked_ips_json TEXT NOT NULL,
            protected_ips_json TEXT NOT NULL,
            doh_url TEXT NOT NULL,
            dns_bind_addr TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS client_nodes (
            client_id TEXT PRIMARY KEY,
            device_name TEXT NOT NULL,
            assigned_ip TEXT NOT NULL,
            server_id TEXT,
            tunnel_token TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            egress_ip TEXT
        );
        ",
    )
    .map_err(to_io_error)?;

    ensure_column(
        &conn,
        "agents",
        "current_country",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "agents",
        "current_public_ip",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "agents",
        "upload_bytes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "agents",
        "download_bytes",
        "INTEGER NOT NULL DEFAULT 0",
    )?;

    conn.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?1, ?2)
         ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
        params![admin_user, sha256_hex(admin_pass)],
    )
    .map_err(to_io_error)?;

    seed_setting(&conn, "config_version", "1")?;
    seed_setting(&conn, "listen_addr", "0.0.0.0:9000")?;
    seed_setting(&conn, "public_endpoint", "127.0.0.1:9000")?;
    seed_setting(&conn, "tun_name", "ntz0")?;
    seed_setting(&conn, "tun_address", "10.44.0.1")?;
    seed_setting(&conn, "tun_prefix", "24")?;
    seed_setting(&conn, "client_cidr", "10.44.0.0/24")?;
    seed_setting(&conn, "mtu", "1400")?;
    seed_setting(&conn, "nat_iface", "eth0")?;
    seed_setting(&conn, "setup_nat", "true")?;
    seed_setting(&conn, "max_clients", "32")?;
    seed_setting(&conn, "doh_url", "https://1.1.1.1/dns-query")?;
    seed_setting(&conn, "dns_bind_addr", "10.44.0.1:53")?;
    seed_setting(&conn, "blocked_ips_json", "[]")?;
    seed_setting(&conn, "protected_ips_json", "[]")?;
    seed_setting(&conn, "egress_ips_json", "[]")?;

    Ok(())
}

fn open_db(db_path: &FsPath) -> io::Result<Connection> {
    Connection::open(db_path).map_err(to_io_error)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> io::Result<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(to_io_error)?;

    for row in rows {
        if row.map_err(to_io_error)? == column {
            return Ok(());
        }
    }

    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map(|_| ())
    .map_err(to_io_error)
}

fn seed_setting(conn: &Connection, key: &str, value: &str) -> io::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .map(|_| ())
    .map_err(to_io_error)
}

fn save_setting(conn: &Connection, key: &str, value: &str) -> Result<(), Response> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map(|_| ())
    .map_err(internal_response)
}

fn load_settings(conn: &Connection) -> io::Result<HashMap<String, String>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM settings")
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(to_io_error)?;

    let mut settings = HashMap::new();
    for row in rows {
        let (key, value) = row.map_err(to_io_error)?;
        settings.insert(key, value);
    }
    Ok(settings)
}

fn verify_admin(conn: &Connection, username: &str, password: &str) -> io::Result<bool> {
    let stored = conn
        .query_row(
            "SELECT password_hash FROM admins WHERE username = ?1",
            params![username.trim()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_error)?;
    Ok(stored
        .map(|value| value == sha256_hex(password))
        .unwrap_or(false))
}

fn require_session(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let token = session_token_from_headers(headers).ok_or_else(|| redirect_response("/login"))?;
    let sessions = state.sessions.lock().map_err(|_| {
        internal_response(io::Error::new(io::ErrorKind::Other, "session lock failed"))
    })?;
    sessions
        .get(&token)
        .cloned()
        .ok_or_else(|| redirect_response("/login"))
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix("ntz_session=") {
            return Some(value.to_string());
        }
    }
    None
}

fn list_servers(conn: &Connection) -> io::Result<Vec<ServerRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.server_id, s.node_name, s.enabled, s.listen_addr, s.public_endpoint,
                    COALESCE(s.nat_iface, ''), s.max_clients,
                    COALESCE(a.last_seen, ''), a.current_version, COALESCE(a.last_error, ''),
                    COALESCE(a.last_message, ''), COALESCE(a.connected_clients, 0)
             FROM server_nodes s
             LEFT JOIN agents a ON a.agent_id = s.server_id
             ORDER BY s.node_name",
        )
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ServerRow {
                server_id: row.get(0)?,
                node_name: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                listen_addr: row.get(3)?,
                public_endpoint: row.get(4)?,
                nat_iface: row.get(5)?,
                max_clients: row.get::<_, i64>(6)? as usize,
                last_seen: row.get(7)?,
                current_version: row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
                last_error: row.get(9)?,
                last_message: row.get(10)?,
                connected_clients: row.get::<_, i64>(11)? as usize,
            })
        })
        .map_err(to_io_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(to_io_error)
}

fn list_clients(conn: &Connection) -> io::Result<Vec<ClientRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT c.client_id, c.device_name, c.enabled, c.assigned_ip, COALESCE(c.server_id, ''),
                    COALESCE(c.egress_ip, ''), COALESCE(a.last_seen, ''), a.current_version,
                    COALESCE(a.last_error, ''), COALESCE(a.last_message, '')
             FROM client_nodes c
             LEFT JOIN agents a ON a.agent_id = c.client_id
             ORDER BY c.device_name",
        )
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ClientRow {
                client_id: row.get(0)?,
                device_name: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                assigned_ip: row.get(3)?,
                server_id: row.get(4)?,
                egress_ip: row.get(5)?,
                last_seen: row.get(6)?,
                current_version: row.get::<_, Option<i64>>(7)?.map(|value| value as u64),
                last_error: row.get(8)?,
                last_message: row.get(9)?,
            })
        })
        .map_err(to_io_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(to_io_error)
}

fn list_tokens(conn: &Connection) -> io::Result<Vec<TokenRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT token, kind, label, created_at, COALESCE(used_at, '')
             FROM bootstrap_tokens
             ORDER BY created_at DESC",
        )
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TokenRow {
                token: row.get(0)?,
                kind: row.get(1)?,
                label: row.get(2)?,
                created_at: row.get(3)?,
                used_at: row.get(4)?,
            })
        })
        .map_err(to_io_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(to_io_error)
}

fn current_config_version(conn: &Connection) -> io::Result<u64> {
    conn.query_row(
        "SELECT value FROM settings WHERE key = 'config_version'",
        [],
        |row| row.get::<_, String>(0),
    )
    .map_err(to_io_error)?
    .parse::<u64>()
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn bump_config_version(conn: &Connection) -> Result<u64, Response> {
    let next = current_config_version(conn).map_err(internal_response)? + 1;
    save_setting(conn, "config_version", &next.to_string())?;
    Ok(next)
}

fn validate_agent(
    conn: &Connection,
    agent_id: &str,
    agent_secret: &str,
    kind: &AgentKind,
) -> io::Result<()> {
    let row = conn
        .query_row(
            "SELECT kind, agent_secret, enabled FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(to_io_error)?;

    match row {
        Some((stored_kind, stored_secret, enabled))
            if stored_kind == kind.as_str() && stored_secret == agent_secret && enabled != 0 =>
        {
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid agent credentials",
        )),
    }
}

fn enroll_server(conn: &Connection, agent_id: &str, node_name: &str) -> io::Result<()> {
    let settings = load_settings(conn)?;
    conn.execute(
        "INSERT INTO server_nodes
         (server_id, node_name, listen_addr, public_endpoint, tun_name, tun_address, tun_prefix,
          mtu, client_cidr, nat_iface, setup_nat, max_clients, egress_ips_json, blocked_ips_json,
          protected_ips_json, doh_url, dns_bind_addr, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 1)",
        params![
            agent_id,
            node_name.trim(),
            settings_value(&settings, "listen_addr"),
            settings_value(&settings, "public_endpoint"),
            settings_value(&settings, "tun_name"),
            settings_value(&settings, "tun_address"),
            settings_value(&settings, "tun_prefix")
                .parse::<i64>()
                .unwrap_or(24),
            parse_optional_i64(settings_value(&settings, "mtu")),
            settings_value(&settings, "client_cidr"),
            empty_to_none(settings_value(&settings, "nat_iface")),
            bool_to_i64(parse_bool(settings_value(&settings, "setup_nat"))),
            settings_value(&settings, "max_clients")
                .parse::<i64>()
                .unwrap_or(32),
            settings_value(&settings, "egress_ips_json"),
            settings_value(&settings, "blocked_ips_json"),
            settings_value(&settings, "protected_ips_json"),
            settings_value(&settings, "doh_url"),
            settings_value(&settings, "dns_bind_addr"),
        ],
    )
    .map(|_| ())
    .map_err(to_io_error)
}

fn enroll_client(conn: &Connection, agent_id: &str, device_name: &str) -> io::Result<()> {
    let settings = load_settings(conn)?;
    let server_id = conn
        .query_row(
            "SELECT server_id FROM server_nodes ORDER BY rowid ASC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_error)?
        .unwrap_or_default();

    let assigned_ip = allocate_client_ip(
        conn,
        settings_value(&settings, "client_cidr"),
        settings_value(&settings, "tun_address"),
    )?;

    conn.execute(
        "INSERT INTO client_nodes
         (client_id, device_name, assigned_ip, server_id, tunnel_token, enabled, egress_ip)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, NULL)",
        params![
            agent_id,
            device_name.trim(),
            assigned_ip,
            empty_to_none(&server_id),
            random_token()
        ],
    )
    .map(|_| ())
    .map_err(to_io_error)
}

fn build_server_config(conn: &Connection, server_id: &str) -> io::Result<ServerConfig> {
    let version = current_config_version(conn)?;
    let row = conn
        .query_row(
            "SELECT server_id, node_name, enabled, listen_addr, public_endpoint, tun_name, tun_address,
                    tun_prefix, mtu, client_cidr, nat_iface, setup_nat, max_clients,
                    egress_ips_json, blocked_ips_json, protected_ips_json, doh_url, dns_bind_addr
             FROM server_nodes WHERE server_id = ?1",
            params![server_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)? as u8,
                    row.get::<_, Option<i64>>(8)?.map(|value| value as u16),
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)? != 0,
                    row.get::<_, i64>(12)? as usize,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .optional()
        .map_err(to_io_error)?;

    let (
        server_id,
        node_name,
        enabled,
        listen_addr,
        public_endpoint,
        tun_name,
        tun_address,
        tun_prefix,
        mtu,
        client_cidr,
        nat_iface,
        setup_nat,
        max_clients,
        egress_ips_json,
        blocked_ips_json,
        protected_ips_json,
        doh_url,
        dns_bind_addr,
    ) = row.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "server not registered"))?;

    let mut stmt = conn
        .prepare(
            "SELECT client_id, device_name, enabled, assigned_ip, tunnel_token, egress_ip
             FROM client_nodes
             WHERE server_id = ?1
             ORDER BY device_name",
        )
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map(params![server_id.clone()], |row| {
            Ok(ManagedClientRecord {
                client_id: row.get(0)?,
                device_name: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                assigned_ip: row.get(3)?,
                tunnel_token: row.get(4)?,
                egress_ip: row.get(5)?,
            })
        })
        .map_err(to_io_error)?;

    let allowed_clients = rows.collect::<Result<Vec<_>, _>>().map_err(to_io_error)?;

    Ok(ServerConfig {
        version,
        server_id,
        enabled,
        node_name,
        listen_addr,
        public_endpoint,
        tun_name,
        tun_address,
        tun_prefix,
        mtu,
        client_cidr,
        max_clients,
        nat_iface,
        setup_nat,
        firewall: FirewallPolicy {
            blocked_destinations: parse_json_list(&blocked_ips_json)?,
            protected_destinations: parse_json_list(&protected_ips_json)?,
        },
        dns: DnsProfile {
            bind_addr: dns_bind_addr,
            doh_url,
        },
        egress_ips: parse_json_list(&egress_ips_json)?,
        allowed_clients,
        poll_interval_seconds: 15,
    })
}

fn build_client_config(conn: &Connection, client_id: &str) -> io::Result<ClientConfig> {
    let version = current_config_version(conn)?;
    let settings = load_settings(conn)?;
    let row = conn
        .query_row(
            "SELECT client_id, device_name, assigned_ip, COALESCE(server_id, ''), tunnel_token, enabled, egress_ip
             FROM client_nodes WHERE client_id = ?1",
            params![client_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(to_io_error)?;

    let (client_id, device_name, assigned_ip, server_id, tunnel_token, enabled, egress_ip) =
        row.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "client not registered"))?;

    let server_endpoint = if server_id.is_empty() {
        String::new()
    } else {
        conn.query_row(
            "SELECT public_endpoint FROM server_nodes WHERE server_id = ?1",
            params![server_id.clone()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(to_io_error)?
        .unwrap_or_default()
    };

    Ok(ClientConfig {
        version,
        client_id,
        enabled: enabled && !server_endpoint.is_empty(),
        device_name,
        server_id,
        server_endpoint,
        tunnel_token,
        tun_name: settings_value(&settings, "tun_name").to_string(),
        tun_address: assigned_ip,
        tun_prefix: settings_value(&settings, "tun_prefix")
            .parse::<u8>()
            .unwrap_or(24),
        mtu: parse_optional_u16(settings_value(&settings, "mtu")),
        dns_server: settings_value(&settings, "tun_address").to_string(),
        route_mode: RouteMode::FullTunnel,
        egress_ip,
        poll_interval_seconds: 15,
    })
}

fn allocate_client_ip(conn: &Connection, cidr: &str, server_ip: &str) -> io::Result<String> {
    let (network, prefix) = parse_cidr(cidr)?;
    let network_u32 = u32::from(network);
    let host_count = if prefix == 32 {
        1
    } else {
        1u32 << (32 - prefix)
    };

    let mut used = HashSet::new();
    used.insert(server_ip.parse::<Ipv4Addr>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid server IP: {err}"),
        )
    })?);

    let mut stmt = conn
        .prepare("SELECT assigned_ip FROM client_nodes")
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(to_io_error)?;
    for row in rows {
        if let Ok(ip) = row.map_err(to_io_error)?.parse::<Ipv4Addr>() {
            used.insert(ip);
        }
    }

    let start_offset = if host_count > 16 { 10 } else { 2 };
    for offset in start_offset..host_count.saturating_sub(1) {
        let candidate = Ipv4Addr::from(network_u32 + offset);
        if !used.contains(&candidate) {
            return Ok(candidate.to_string());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no available client IPs in pool",
    ))
}

fn parse_cidr(value: &str) -> io::Result<(Ipv4Addr, u8)> {
    let (network, prefix) = value
        .split_once('/')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CIDR must contain '/'"))?;
    let network = network
        .parse::<Ipv4Addr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok((network, prefix))
}

fn parse_json_list(raw: &str) -> io::Result<Vec<String>> {
    serde_json::from_str::<Vec<String>>(raw).map_err(to_io_error)
}

fn to_json_list(values: &[String]) -> io::Result<String> {
    serde_json::to_string(values).map_err(to_io_error)
}

fn parse_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn bool_to_setting(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn bool_to_i64(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "yes" | "on")
}

fn parse_optional_i64(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<i64>().ok()
    }
}

fn parse_optional_u16(value: &str) -> Option<u16> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<u16>().ok()
    }
}

fn settings_value<'a>(settings: &'a HashMap<String, String>, key: &str) -> &'a str {
    settings.get(key).map(|value| value.as_str()).unwrap_or("")
}

fn empty_to_none(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.trim().to_string())
    }
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    encode_hex(&hasher.finalize())
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Clone)]
struct AgentSecurityState {
    last_seen: Option<DateTime<Utc>>,
    country: String,
    public_ip: String,
}

fn process_security_report(
    conn: &Connection,
    agent_id: &str,
    kind: &AgentKind,
    status: &AgentStatusReport,
) -> io::Result<()> {
    let previous = load_agent_security_state(conn, agent_id)?;

    if let Some(country) = clean_optional_text(status.country.as_deref()) {
        if let Some(previous) = &previous {
            if !previous.country.is_empty()
                && previous.country != country
                && previous_seen_within(previous, 120)
            {
                create_alert(
                    conn,
                    "WARN",
                    agent_id,
                    &format!(
                        "Country changed rapidly from {} to {}",
                        previous.country, country
                    ),
                );
            }
        }
    }

    if let Some(public_ip) = clean_optional_text(status.public_ip.as_deref()) {
        if let Some(previous) = &previous {
            if !previous.public_ip.is_empty()
                && previous.public_ip != public_ip
                && previous_seen_within(previous, 120)
            {
                create_alert(
                    conn,
                    "WARN",
                    agent_id,
                    &format!(
                        "Public IP changed rapidly from {} to {}",
                        previous.public_ip, public_ip
                    ),
                );
            }
        }

        if !known_public_ip(conn, public_ip)? {
            create_alert(
                conn,
                "WARN",
                agent_id,
                &format!("Unknown public IP detected: {public_ip}"),
            );
        }
    }

    let upload = status.upload_bytes.unwrap_or_default();
    let download = status.download_bytes.unwrap_or_default();
    if upload > 500_000_000 || download > 500_000_000 {
        create_alert(conn, "WARN", agent_id, "Unusual traffic spike detected");
    }

    if *kind == AgentKind::Client {
        record_client_session(conn, agent_id, previous.as_ref(), status)?;
    }

    Ok(())
}

fn load_agent_security_state(
    conn: &Connection,
    agent_id: &str,
) -> io::Result<Option<AgentSecurityState>> {
    conn.query_row(
        "SELECT COALESCE(last_seen, ''), COALESCE(current_country, ''), COALESCE(current_public_ip, '')
         FROM agents
         WHERE agent_id = ?1",
        params![agent_id],
        |row| {
            let last_seen: String = row.get(0)?;
            Ok(AgentSecurityState {
                last_seen: parse_timestamp(&last_seen),
                country: row.get(1)?,
                public_ip: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(to_io_error)
}

fn previous_seen_within(previous: &AgentSecurityState, seconds: i64) -> bool {
    previous
        .last_seen
        .map(|timestamp| Utc::now().signed_duration_since(timestamp).num_seconds() <= seconds)
        .unwrap_or(false)
}

fn record_client_session(
    conn: &Connection,
    agent_id: &str,
    previous: Option<&AgentSecurityState>,
    status: &AgentStatusReport,
) -> io::Result<()> {
    if previous
        .map(|state| previous_seen_within(state, 90))
        .unwrap_or(false)
    {
        return Ok(());
    }

    conn.execute(
        "INSERT INTO client_sessions (
            agent_id,
            connected_at,
            public_ip,
            country,
            status_message
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            agent_id,
            Utc::now().to_rfc3339(),
            status.public_ip.clone().unwrap_or_default(),
            status.country.clone().unwrap_or_default(),
            status.last_message.clone().unwrap_or_default(),
        ],
    )
    .map_err(to_io_error)?;

    let threshold = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let reconnects: i64 = conn
        .query_row(
            "SELECT COUNT(*)
             FROM client_sessions
             WHERE agent_id = ?1
             AND connected_at > ?2",
            params![agent_id, threshold],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if reconnects > 10 {
        create_alert(conn, "WARN", agent_id, "Excessive reconnect attempts");
    }

    Ok(())
}

fn known_public_ip(conn: &Connection, public_ip: &str) -> io::Result<bool> {
    let settings = load_settings(conn)?;
    let mut known = HashSet::new();

    if let Some(host) = endpoint_host(settings_value(&settings, "public_endpoint")) {
        known.insert(host);
    }

    for egress_ip in
        parse_json_list(settings_value(&settings, "egress_ips_json")).unwrap_or_default()
    {
        known.insert(egress_ip);
    }

    let mut stmt = conn
        .prepare("SELECT public_endpoint FROM server_nodes")
        .map_err(to_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(to_io_error)?;

    for row in rows {
        if let Some(host) = endpoint_host(&row.map_err(to_io_error)?) {
            known.insert(host);
        }
    }

    Ok(known.is_empty() || known.contains(public_ip))
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    let mut value = endpoint.trim();
    value = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    value = value.trim_matches('/');

    if value.is_empty() {
        return None;
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip().to_string());
    }

    value
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
        .or_else(|| Some(value.trim_matches(['[', ']']).to_string()))
}

fn clean_optional_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn option_u64_to_i64(value: Option<u64>) -> i64 {
    value.unwrap_or_default().min(i64::MAX as u64) as i64
}

fn create_alert(conn: &Connection, level: &str, agent_id: &str, message: &str) {
    if recent_alert_exists(conn, agent_id, message, 300).unwrap_or(false) {
        return;
    }

    let _ = conn.execute(
        "INSERT INTO security_alerts (
            timestamp,
            level,
            agent_id,
            message
        ) VALUES (?1, ?2, ?3, ?4)",
        params![Utc::now().to_rfc3339(), level, agent_id, message],
    );

    write_log(conn, level, &format!("[ALERT] {} - {}", agent_id, message));
}

fn recent_alert_exists(
    conn: &Connection,
    agent_id: &str,
    message: &str,
    seconds: i64,
) -> io::Result<bool> {
    let threshold = (Utc::now() - chrono::Duration::seconds(seconds)).to_rfc3339();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*)
             FROM security_alerts
             WHERE agent_id = ?1
             AND message = ?2
             AND timestamp > ?3",
            params![agent_id, message, threshold],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(count > 0)
}

fn internal_response(err: impl std::fmt::Display) -> Response {
    let body = format!(
        r#"<div class="page"><section class="card strong"><span class="eyebrow">Manager error</span><h1>Something went wrong inside NTZ Manager</h1><p class="lead">The request reached the manager, but part of the control-plane workflow failed.</p><pre class="error-block">{}</pre><a class="btn-secondary" href="/">Return to dashboard</a></section></div>"#,
        escape_html(&err.to_string())
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render_page("NTZ Manager Error", &body)),
    )
        .into_response()
}
fn write_log(conn: &Connection, level: &str, message: &str) {
    let _ = conn.execute(
        "INSERT INTO logs (
            timestamp,
            level,
            message
        ) VALUES (?1, ?2, ?3)",
        params![Utc::now().to_rfc3339(), level, message],
    );
}

fn api_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
}

fn redirect_response(path: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(path).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    response
}

fn simple_redirect_with_error(path: &str, message: &str) -> Response {
    let mut response = redirect_response(path);
    response.headers_mut().insert(
        "X-NTZ-Error",
        HeaderValue::from_str(message).unwrap_or_else(|_| HeaderValue::from_static("error")),
    );
    response
}

const MANAGER_STYLE: &str = r#"
:root{--bg:#f8f1e6;--bg-2:#e7f3ee;--bg-3:#fdf9f3;--card:#fffdf8;--card-soft:rgba(255,252,246,.88);--card-strong:rgba(255,255,255,.96);--ink:#1d2731;--muted:#5e6773;--line:#dbd4c8;--accent:#0f7a6d;--accent-deep:#0c6258;--accent-soft:#d8efe8;--info:#e7f1fb;--warn:#fff1dc;--danger:#fde7e3;--shadow:0 26px 60px rgba(22,33,43,.12)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;min-height:100vh;color:var(--ink);font-family:Aptos,"Segoe UI",Candara,sans-serif;background:radial-gradient(circle at top left,rgba(255,232,200,.96),transparent 28%),radial-gradient(circle at 92% 12%,rgba(210,236,227,.92),transparent 32%),radial-gradient(circle at 50% 100%,rgba(255,255,255,.9),transparent 38%),linear-gradient(180deg,var(--bg) 0%,var(--bg-2) 46%,var(--bg-3) 100%)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.page{max-width:1360px;margin:0 auto;padding:34px 20px 72px}
.hero,.layout,.login-layout,.stats,.list,.grid,.meta{display:grid;gap:20px}
.hero{grid-template-columns:minmax(0,1.18fr) minmax(320px,.82fr);align-items:stretch}
.layout{grid-template-columns:minmax(0,1.12fr) minmax(320px,.88fr);margin:28px 0}
.login-layout{grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);align-items:center;min-height:100vh}
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
.list{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}
.meta{grid-template-columns:repeat(2,minmax(0,1fr))}
.topbar,.section-head,.item-top,.form-actions{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.topbar{margin-bottom:28px}
.brand{max-width:760px}
.actions,.badges,.action-group{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.card{position:relative;background:linear-gradient(180deg,rgba(255,255,255,.86),rgba(255,249,242,.9));border:1px solid rgba(255,255,255,.74);border-radius:30px;padding:24px;box-shadow:var(--shadow);backdrop-filter:blur(12px)}
.card.strong{background:linear-gradient(180deg,var(--card-strong),var(--card))}
.card h1,.card h2,.card h3,.brand h1{margin:0;font-family:Cambria,Georgia,"Times New Roman",serif;letter-spacing:-.025em}
.card h2,.card h3{line-height:1.08}
.brand h1{font-size:clamp(2.3rem,4vw,3.7rem);line-height:1;max-width:12ch}
.eyebrow{display:inline-block;margin-bottom:10px;font-size:.76rem;font-weight:800;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.lead{font-size:1.02rem;color:var(--muted);line-height:1.68;max-width:62ch}
.muted,.field small,.note small,.action-copy{color:var(--muted);line-height:1.56}
.section-head .muted{max-width:54ch}
.item-top{padding-bottom:14px;border-bottom:1px solid rgba(29,39,49,.08)}
.item-top>div:first-child{flex:1 1 auto}
.pill{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:999px;font-size:.8rem;font-weight:800;letter-spacing:.01em}
.ok{background:var(--accent-soft);color:var(--accent-deep)}
.info{background:var(--info);color:#1b5476}
.warn{background:var(--warn);color:#8a4f06}
.muted-pill{background:rgba(29,39,49,.08);color:#4c5663}
.danger{background:var(--danger);color:#7d2d25}
.stat{border:1px solid rgba(29,39,49,.08);border-radius:24px;padding:18px;background:linear-gradient(180deg,rgba(255,255,255,.98),rgba(247,241,234,.94))}
.stat .value{font-family:Cambria,Georgia,"Times New Roman",serif;font-size:2.2rem;margin:10px 0 6px}
.field{display:flex;flex-direction:column;gap:8px}
.field span{font-weight:800}
.field input,.field select,.field textarea{width:100%;padding:13px 15px;border-radius:16px;border:1px solid var(--line);background:rgba(255,255,255,.95);font:inherit;color:var(--ink);box-shadow:inset 0 1px 0 rgba(255,255,255,.6)}
.field textarea{min-height:132px;resize:vertical}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:rgba(15,122,109,.5);box-shadow:0 0 0 4px rgba(15,122,109,.12)}
.toggle{border:1px solid var(--line);border-radius:20px;padding:15px 16px;background:rgba(248,242,235,.94)}
.toggle label{display:flex;align-items:center;gap:10px;font-weight:800;margin-bottom:6px}
.toggle input{width:18px;height:18px;accent-color:var(--accent)}
.btn,.btn-secondary,.btn-danger{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 18px;border-radius:999px;border:0;cursor:pointer;font:inherit;font-weight:800;transition:transform .16s ease,box-shadow .16s ease,background .16s ease}
.btn:hover,.btn-secondary:hover,.btn-danger:hover{transform:translateY(-1px);text-decoration:none}
.btn{background:linear-gradient(135deg,var(--accent),#21a08f);color:#fff;box-shadow:0 14px 28px rgba(15,122,109,.22)}
.btn-secondary{background:rgba(255,255,255,.84);border:1px solid rgba(29,39,49,.12);color:var(--ink)}
.btn-danger{background:linear-gradient(135deg,#c95a4d,#a93f32);color:#fff;box-shadow:0 12px 26px rgba(169,63,50,.2)}
.meta-card{border:1px solid rgba(29,39,49,.08);border-radius:20px;padding:14px 15px;background:rgba(255,255,255,.76)}
.meta-card strong{display:block;margin-bottom:7px;font-size:.76rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.note{border-radius:20px;padding:15px 16px;line-height:1.56;border:1px solid transparent}
.note.info{background:#edf6ff;border-color:#d8e9fb}
.note.success{background:var(--accent-soft);border-color:#c6e2d8}
.note.error{background:var(--danger);border-color:#f2c9c3}
.table-wrap{overflow:auto;border:1px solid rgba(29,39,49,.08);border-radius:22px;padding:0 18px;background:rgba(255,255,255,.56)}
.table{width:100%;min-width:640px;border-collapse:collapse;font-size:.95rem}
.table th{padding:16px 0 12px;text-align:left;font-size:.8rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.table td{padding:14px 0;border-top:1px solid rgba(29,39,49,.08);vertical-align:top}
.token{display:flex;gap:10px;align-items:center;flex-wrap:wrap;min-width:250px}
code{display:inline-block;padding:4px 8px;border-radius:10px;background:rgba(29,39,49,.06);font-size:.93em;overflow-wrap:anywhere}
.empty{border:1px dashed rgba(29,39,49,.18);border-radius:22px;padding:20px;background:rgba(255,255,255,.46);color:var(--muted)}
.steps{display:grid;gap:10px;padding-left:18px;margin:16px 0 0;color:var(--muted)}
.error-block{white-space:pre-wrap;overflow:auto;padding:16px;border-radius:18px;background:rgba(22,28,38,.94);color:#f8f7f3}
.form-actions{margin-top:18px;padding-top:18px;border-top:1px solid rgba(29,39,49,.08);align-items:center;flex-wrap:wrap}
.action-copy{margin:0;max-width:40ch}
.danger-inline{margin:0}
@media (max-width:1120px){.hero,.layout,.login-layout{grid-template-columns:1fr}}
@media (max-width:860px){.stats,.grid.two,.grid.three,.meta,.list{grid-template-columns:1fr}.page{padding:24px 16px 54px}}
@media (max-width:640px){.page{padding:18px 12px 40px}.card{padding:18px}.topbar,.section-head,.item-top,.form-actions{flex-direction:column}.action-group{width:100%}.action-group .btn,.action-group .btn-secondary,.action-group .btn-danger{flex:1 1 100%}.brand h1{max-width:none}.table-wrap{padding:0 12px}}
.live-grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:18px;
    margin-bottom:28px;
}

.live-card{
    padding:24px;
    border-radius:24px;
    backdrop-filter:blur(18px);
    border:1px solid rgba(255,255,255,0.08);
    background:rgba(255,255,255,0.04);
}

.live-card span{
    color:#94a3b8;
    font-size:14px;
}

.live-card h2{
    margin-top:10px;
    font-size:42px;
}

.live-card.online{
    box-shadow:0 0 40px rgba(34,197,94,0.18);
}

.live-card.active{
    box-shadow:0 0 40px rgba(59,130,246,0.18);
}

.live-card.offline{
    box-shadow:0 0 40px rgba(239,68,68,0.18);
}
.alerts-panel{
    margin-top:20px;
    display:grid;
    gap:12px;
}
.alert-row{
    display:flex;
    align-items:flex-start;
    gap:10px;
    padding:14px 16px;
    border-radius:18px;
    background:rgba(201,90,77,0.10);
    border:1px solid rgba(201,90,77,0.18);
    color:#6f2a23;
    font-size:14px;
    line-height:1.5;
}
.alert-icon{
    font-weight:900;
    color:#b73d31;
}
"#;

const MANAGER_SCRIPT: &str = r#"
function escapeClientHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

document.addEventListener("click", async (event) => {
  const commandButton = event.target.closest("[data-copy-command]");
  if (commandButton) {
    const kind = commandButton.dataset.kind || "client";
    const token = commandButton.dataset.token || "";
    const label = commandButton.dataset.label || (kind === "server" ? "ntz-server" : "ntz-client");
    const isWindows = navigator.platform.toLowerCase().includes("win");
    const exe = kind === "server"
      ? "sudo ./target/debug/ntz-proto"
      : isWindows
      ? ".\\target\\debug\\ntz-proto.exe"
      : "sudo ./target/debug/ntz-proto";
    const mode = kind === "server" ? "server" : "client";
    const nameFlag = kind === "server" ? "--node-name" : "--device-name";
    const quote = (value) => `"${String(value).replaceAll('"', '\\"')}"`;
    const command = `${exe} ${mode} --management-url ${quote(window.location.origin)} --enrollment-token ${quote(token)} ${nameFlag} ${quote(label)} --verbose`;
    const original = commandButton.textContent;
    try {
      await navigator.clipboard.writeText(command);
      commandButton.textContent = "Command copied";
    } catch (_err) {
      commandButton.textContent = "Copy failed";
    }
    setTimeout(() => commandButton.textContent = original, 1600);
    return;
  }

  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copy || "");
    button.textContent = "Copied";
  } catch (_err) {
    button.textContent = "Copy failed";
  }
  setTimeout(() => button.textContent = original, 1400);
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-confirm]");
  if (!form) return;
  const message = form.getAttribute("data-confirm") || "Are you sure?";
  if (!window.confirm(message)) {
    event.preventDefault();
  }
});


async function refreshLogs() {

    try {

        const response =
            await fetch("/api/logs");

        const logs =
            await response.json();

        const container =
            document.getElementById(
                "logs-container"
            );

        if (!container) return;

        if (!logs.length) {

            container.innerHTML =
                "No logs yet.";

            return;
        }

        container.innerHTML =
            logs
                .map(log =>
                    `<div style="margin-bottom:8px;">${escapeClientHtml(log)}</div>`
                )
                .join("");

        container.scrollTop =
            container.scrollHeight;

    } catch (err) {

        console.error(err);
    }
}

setInterval(
    refreshLogs,
    2000
);

refreshLogs();

async function refreshAlerts() {

    try {

        const response =
            await fetch("/api/alerts");

        const alerts =
            await response.json();

        const panel =
            document.getElementById(
                "alerts-panel"
            );

        if (!panel) return;

        if (!alerts.length) {

            panel.innerHTML =
                `<div class="empty">No alerts.</div>`;

            return;
        }

        panel.innerHTML =
            alerts.map(alert => `
                <div class="alert-row">
                    <span class="alert-icon">&#9888;</span>
                    <span>${escapeClientHtml(alert)}</span>
                </div>
            `).join("");

    } catch (err) {

        console.error(err);
    }
}

setInterval(
    refreshAlerts,
    5000
);

refreshAlerts();

"#;

fn render_page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>{}</title><style>{}</style></head><body>{}<script>{}</script></body></html>"#,
        escape_html(title),
        MANAGER_STYLE,
        body,
        MANAGER_SCRIPT
    )
}

fn render_input_field(label: &str, name: &str, kind: &str, value: &str, help: &str) -> String {
    format!(
        r#"<label class="field"><span>{}</span><input type="{}" name="{}" value="{}"/><small>{}</small></label>"#,
        escape_html(label),
        escape_html(kind),
        escape_html(name),
        escape_html(value),
        escape_html(help)
    )
}

fn render_select_field(label: &str, name: &str, options: &str, help: &str) -> String {
    format!(
        r#"<label class="field"><span>{}</span><select name="{}">{}</select><small>{}</small></label>"#,
        escape_html(label),
        escape_html(name),
        options,
        escape_html(help)
    )
}

fn render_textarea_field(label: &str, name: &str, value: &str, help: &str) -> String {
    format!(
        r#"<label class="field"><span>{}</span><textarea name="{}">{}</textarea><small>{}</small></label>"#,
        escape_html(label),
        escape_html(name),
        escape_html(value),
        escape_html(help)
    )
}

fn render_toggle_field(label: &str, name: &str, checked: bool, help: &str) -> String {
    format!(
        r#"<div class="toggle"><label><input type="checkbox" name="{}" {} /><span>{}</span></label><small>{}</small></div>"#,
        escape_html(name),
        if checked { "checked" } else { "" },
        escape_html(label),
        escape_html(help)
    )
}

fn render_card_actions(
    form_id: &str,
    save_label: &str,
    helper_text: &str,
    delete_action: &str,
    delete_label: &str,
    confirm_message: &str,
) -> String {
    format!(
        r#"<div class="form-actions"><p class="action-copy">{}</p><div class="action-group"><button class="btn" type="submit" form="{}">{}</button><form class="danger-inline" method="post" action="{}" data-confirm="{}"><button class="btn-danger" type="submit">{}</button></form></div></div>"#,
        escape_html(helper_text),
        escape_html(form_id),
        escape_html(save_label),
        escape_html(delete_action),
        escape_html(confirm_message),
        escape_html(delete_label),
    )
}

fn render_badge(label: &str, class_name: &str) -> String {
    format!(
        r#"<span class="pill {}">{}</span>"#,
        escape_html(class_name),
        escape_html(label)
    )
}

fn render_meta_card(label: &str, value_html: &str) -> String {
    format!(
        r#"<div class="meta-card"><strong>{}</strong>{}</div>"#,
        escape_html(label),
        value_html
    )
}

fn display_text(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn render_login(error: Option<&str>) -> String {
    let error_html = error
        .map(|message| {
            format!(
                r#"<div class="note error"><strong>Sign-in failed.</strong><div>{}</div></div>"#,
                escape_html(message)
            )
        })
        .unwrap_or_default();

    let body = format!(
        r#"<div class="page"><section class="login-layout"><div><span class="eyebrow">NTZ control plane</span><div class="brand"><h1>Manage enrollment, health, and tunnel policy from one cleaner dashboard.</h1></div><p class="lead">Create bootstrap tokens, watch agent heartbeats, and keep server or client assignments organized without digging through raw tables.</p><div class="card"><span class="eyebrow">What this portal does</span><ol class="steps"><li><strong>Create a server token</strong> and enroll your Linux VPN node.</li><li><strong>Create client tokens</strong> for Windows or Linux devices you want to manage.</li><li><strong>Review heartbeats</strong>, public endpoints, and assignments in one place.</li></ol></div></div><form class="card strong" method="post" action="/login"><span class="eyebrow">Administrator sign-in</span><h2>Open NTZ Manager</h2><p class="muted">Use the credentials configured when you started the manager service.</p>{}{}{}<button class="btn" type="submit">Open dashboard</button></form></section></div>"#,
        error_html,
        render_input_field(
            "Username",
            "username",
            "text",
            "",
            "Administrator account name."
        ),
        render_input_field(
            "Password",
            "password",
            "password",
            "",
            "Password for the manager portal."
        ),
    );

    render_page("NTZ Manager Login", &body)
}

fn render_dashboard(
    version: u64,
    settings: &HashMap<String, String>,
    servers: &[ServerRow],
    clients: &[ClientRow],
    tokens: &[TokenRow],
) -> String {
    let blocked = parse_json_list(settings_value(settings, "blocked_ips_json")).unwrap_or_default();
    let protected =
        parse_json_list(settings_value(settings, "protected_ips_json")).unwrap_or_default();
    let egress = parse_json_list(settings_value(settings, "egress_ips_json")).unwrap_or_default();

    let online_servers = servers
        .iter()
        .filter(|server| matches!(heartbeat_state(&server.last_seen), HeartbeatState::Online))
        .count();
    let assigned_clients = clients
        .iter()
        .filter(|client| !client.server_id.trim().is_empty())
        .count();
    let unused_tokens = tokens
        .iter()
        .filter(|token| token.used_at.trim().is_empty())
        .count();

    let stats_html = vec![
        format!(r#"<div class="stat"><div class="eyebrow">Config version</div><div class="value">v{version}</div><div class="muted">Every settings save increments the version agents pull.</div></div>"#),
        format!(r#"<div class="stat"><div class="eyebrow">Healthy servers</div><div class="value">{online_servers}/{}</div><div class="muted">Nodes with heartbeats in the last 45 seconds.</div></div>"#, servers.len()),
        format!(r#"<div class="stat"><div class="eyebrow">Assigned clients</div><div class="value">{assigned_clients}/{}</div><div class="muted">Enrolled devices already mapped to a server.</div></div>"#, clients.len()),
        format!(r#"<div class="stat"><div class="eyebrow">Tokens ready</div><div class="value">{unused_tokens}</div><div class="muted">Unused bootstrap tokens available right now.</div></div>"#),
    ]
    .join("");

    let settings_form = format!(
        r#"<form class="grid" method="post" action="/settings"><div class="grid two">{}{}</div><div class="grid three">{}{}{}</div><div class="grid three">{}{}{}</div>{}<div class="grid three">{}{}{}</div><div class="grid three">{}{}{}</div><button class="btn" type="submit">Save global settings</button></form>"#,
        render_input_field(
            "Server listen address",
            "listen_addr",
            "text",
            settings_value(settings, "listen_addr"),
            "UDP address the Linux server binds to."
        ),
        render_input_field(
            "Public endpoint",
            "public_endpoint",
            "text",
            settings_value(settings, "public_endpoint"),
            "Reachable IP:port clients use to reach the server."
        ),
        render_input_field(
            "TUN name",
            "tun_name",
            "text",
            settings_value(settings, "tun_name"),
            "Shared interface name pushed to agents."
        ),
        render_input_field(
            "Server TUN IP",
            "tun_address",
            "text",
            settings_value(settings, "tun_address"),
            "IPv4 address used on the server tunnel interface."
        ),
        render_input_field(
            "TUN prefix",
            "tun_prefix",
            "number",
            settings_value(settings, "tun_prefix"),
            "CIDR prefix for the tunnel network."
        ),
        render_input_field(
            "Client CIDR",
            "client_cidr",
            "text",
            settings_value(settings, "client_cidr"),
            "Pool used when assigning client tunnel addresses."
        ),
        render_input_field(
            "MTU",
            "mtu",
            "number",
            settings_value(settings, "mtu"),
            "Leave blank to keep the platform default."
        ),
        render_input_field(
            "Max clients",
            "max_clients",
            "number",
            settings_value(settings, "max_clients"),
            "Default concurrency cap for new server nodes."
        ),
        render_toggle_field(
            "Setup NAT automatically",
            "setup_nat",
            parse_bool(settings_value(settings, "setup_nat")),
            "Linux server nodes program routes and iptables when enabled."
        ),
        render_input_field(
            "NAT interface",
            "nat_iface",
            "text",
            settings_value(settings, "nat_iface"),
            "Linux WAN interface used for NAT and forwarding."
        ),
        render_input_field(
            "DoH upstream URL",
            "doh_url",
            "text",
            settings_value(settings, "doh_url"),
            "DNS-over-HTTPS endpoint used by the server-side DNS proxy."
        ),
        render_input_field(
            "DNS bind address",
            "dns_bind_addr",
            "text",
            settings_value(settings, "dns_bind_addr"),
            "Address the managed DNS proxy listens on."
        ),
        render_textarea_field(
            "Blocked destinations",
            "blocked_ips",
            &blocked.join("\n"),
            "One CIDR or IP per line. These destinations are dropped for tunnel clients."
        ),
        render_textarea_field(
            "Protected destinations",
            "protected_ips",
            &protected.join("\n"),
            "Sensitive networks you never want reachable from the VPN."
        ),
        render_textarea_field(
            "Egress IP pool",
            "egress_ips",
            &egress.join("\n"),
            "Optional source IPs used for per-client SNAT."
        ),
    );

    let token_rows = if tokens.is_empty() {
        "<tr><td colspan=\"5\"><div class=\"empty\">No bootstrap tokens yet. Create a server token first, then a client token for each device.</div></td></tr>".to_string()
    } else {
        tokens
            .iter()
            .map(render_token_row)
            .collect::<Vec<_>>()
            .join("")
    };

    let server_cards = if servers.is_empty() {
        r#"<div class="card"><div class="empty">No server nodes enrolled yet. Create a server token, run the Linux server agent, and this section will fill in automatically.</div></div>"#.to_string()
    } else {
        servers
            .iter()
            .map(|server| render_server_card(server, version))
            .collect::<Vec<_>>()
            .join("")
    };

    let client_cards = if clients.is_empty() {
        r#"<div class="card"><div class="empty">No client devices enrolled yet. Create a client token and run the client agent to populate this section.</div></div>"#.to_string()
    } else {
        clients
            .iter()
            .map(|client| render_client_card(client, servers, version))
            .collect::<Vec<_>>()
            .join("")
    };

    let logs_panel = r#"
<section class="card strong">
    <div class="section-head">
        <div>
            <span class="eyebrow">Live server logs</span>
            <h2>Real-time VPN activity</h2>
            <p class="muted">
                Heartbeats, client activity, status updates,
                and future connection events appear here.
            </p>
        </div>
    </div>

    <div
        id="logs-container"
        style="
            margin-top:20px;
            background:#0f172a;
            color:#00ff9d;
            border-radius:20px;
            padding:20px;
            height:320px;
            overflow-y:auto;
            font-family:Consolas, monospace;
            font-size:14px;
            border:1px solid rgba(255,255,255,0.08);
        "
    >
        Loading logs...
    </div>
</section>
"#;

    let alerts_panel = r#"
<section class="card strong">
    <div class="section-head">
        <div>
            <span class="eyebrow">Security center</span>
            <h2>Threat detection alerts</h2>
            <p class="muted">
                Impossible travel, reconnect abuse, unknown IPs,
                and traffic spikes surface here as agents report status.
            </p>
        </div>
    </div>

    <div id="alerts-panel" class="alerts-panel">
        <div class="empty">Loading alerts...</div>
    </div>
</section>
"#;

    let online_servers = servers
        .iter()
        .filter(|server| {
            parse_timestamp(&server.last_seen)
                .map(|timestamp| Utc::now().signed_duration_since(timestamp).num_seconds() < 60)
                .unwrap_or(false)
        })
        .count();

    let offline_servers = servers.len() - online_servers;

    let online_clients = clients
        .iter()
        .filter(|client| {
            parse_timestamp(&client.last_seen)
                .map(|timestamp| Utc::now().signed_duration_since(timestamp).num_seconds() < 60)
                .unwrap_or(false)
        })
        .count();

    let live_stats = format!(
        r#"
    <div class="live-grid">

        <div class="live-card online">
            <span>Online Clients</span>
            <h2>{}</h2>
        </div>

        <div class="live-card active">
            <span>Online Servers</span>
            <h2>{}</h2>
        </div>

        <div class="live-card offline">
            <span>Offline Servers</span>
            <h2>{}</h2>
        </div>

    </div>
    "#,
        online_clients, online_servers, offline_servers
    );

    let body = format!(
        r#"<div class="page"><header class="topbar"><div class="brand"><span class="eyebrow">NTZ control plane</span><h1>Operate your VPN network without fighting the interface.</h1><p class="lead">Create enrollment tokens, check node health, and keep client-to-server assignments tidy from one responsive dashboard.</p></div><div class="actions">{}<a class="btn-secondary" href="/logout">Logout</a></div></header>{}<section class="hero"><article class="card strong"><span class="eyebrow">Quick start</span><h2>Bring the network online in three steps</h2><p class="lead">The manager already stores your shared tunnel defaults. What usually matters most is keeping the public endpoint correct and making sure each client lands on the right server.</p><ol class="steps"><li><strong>Create a server token</strong> and enroll your Linux VPN host.</li><li><strong>Create client tokens</strong> for every device you want to manage.</li><li><strong>Review heartbeats</strong>, fix assignments, and confirm the public endpoint is reachable.</li></ol><div class="meta">{}{}</div></article><div class="stats">{}</div></section><div class="layout"><section class="card strong"><div class="section-head"><div><span class="eyebrow">Global profile</span><h2>Default network settings</h2></div><p class="muted">These values seed new server nodes and shape client allocation, DNS proxy behavior, and egress handling.</p></div>{}</section><section class="card"><div class="section-head"><div><span class="eyebrow">Enrollment</span><h2>Bootstrap tokens</h2></div><p class="muted">Tokens are single-use by design, so the table doubles as a clean audit trail.</p></div><form class="grid" method="post" action="/tokens"><div class="grid two">{}{}</div><button class="btn" type="submit">Create bootstrap token</button></form><div class="table-wrap"><table class="table"><thead><tr><th>Token</th><th>Type</th><th>Label</th><th>Created</th><th>Used</th></tr></thead><tbody>{}</tbody></table></div></section></div><section class="section-head"><div><span class="eyebrow">Linux nodes</span><h2>Server fleet</h2></div><p class="muted">Server cards show heartbeat freshness, applied config version, and connected client counts.</p></section><div class="list">{}</div><section class="section-head"><div><span class="eyebrow">Managed devices</span><h2>Client inventory</h2></div><p class="muted">Assign each client to the correct server and keep tunnel IPs or egress overrides readable.</p></section><div class="list">{}</div>{}{}</div>"#,
        render_badge(&format!("Config v{version}"), "info"),
        live_stats,
        render_meta_card("Public endpoint", &format!("<code>{}</code>", escape_html(&display_text(settings_value(settings, "public_endpoint"), "Not set")))),
        render_meta_card("Client pool", &format!("<code>{}</code>", escape_html(&display_text(settings_value(settings, "client_cidr"), "Not set")))),
        stats_html,
        settings_form,
        render_select_field("Token type", "kind", "<option value=\"server\">Server node</option><option value=\"client\">Client device</option>", "Server tokens enroll Linux nodes. Client tokens enroll end-user devices."),
        render_input_field("Friendly label", "label", "text", "lab-node", "Use a label that will still make sense later."),
        token_rows,
        server_cards,
        client_cards,
        alerts_panel,
        logs_panel,
    );

    render_page("NTZ Manager", &body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeartbeatState {
    Online,
    Stale,
    Offline,
    Pending,
}

fn heartbeat_state(last_seen: &str) -> HeartbeatState {
    match heartbeat_age_seconds(last_seen) {
        Some(age) if age <= 45 => HeartbeatState::Online,
        Some(age) if age <= 300 => HeartbeatState::Stale,
        Some(_) => HeartbeatState::Offline,
        None => HeartbeatState::Pending,
    }
}

fn heartbeat_age_seconds(last_seen: &str) -> Option<i64> {
    parse_timestamp(last_seen).map(|timestamp| {
        Utc::now()
            .signed_duration_since(timestamp)
            .num_seconds()
            .max(0)
    })
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn humanize_elapsed(seconds: i64) -> String {
    match seconds {
        0..=4 => "just now".to_string(),
        5..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

fn format_last_seen(last_seen: &str) -> String {
    match parse_timestamp(last_seen) {
        Some(timestamp) => {
            let age = Utc::now()
                .signed_duration_since(timestamp)
                .num_seconds()
                .max(0);
            format!(
                "{} ({})",
                humanize_elapsed(age),
                timestamp.format("%Y-%m-%d %H:%M UTC")
            )
        }
        None => "No heartbeat received yet".to_string(),
    }
}

fn format_timestamp(value: &str) -> String {
    parse_timestamp(value)
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| display_text(value, "Not yet"))
}

fn format_used_timestamp(value: &str) -> String {
    if value.trim().is_empty() {
        "Not used yet".to_string()
    } else {
        format_timestamp(value)
    }
}

fn render_heartbeat_badge(last_seen: &str) -> String {
    match heartbeat_state(last_seen) {
        HeartbeatState::Online => render_badge("Online", "ok"),
        HeartbeatState::Stale => render_badge("Stale", "warn"),
        HeartbeatState::Offline => render_badge("Offline", "muted-pill"),
        HeartbeatState::Pending => render_badge("Pending", "muted-pill"),
    }
}

fn render_enabled_badge(enabled: bool) -> String {
    if enabled {
        render_badge("Enabled", "ok")
    } else {
        render_badge("Disabled", "muted-pill")
    }
}

fn render_config_badge(applied_version: Option<u64>, desired_version: u64) -> String {
    match applied_version {
        Some(version) if version == desired_version => render_badge("Config current", "info"),
        Some(_) => render_badge("Needs refresh", "warn"),
        None => render_badge("Config pending", "muted-pill"),
    }
}

fn format_applied_version(applied_version: Option<u64>, desired_version: u64) -> String {
    match applied_version {
        Some(version) if version == desired_version => format!("v{version} (current)"),
        Some(version) => format!("v{version} (manager on v{desired_version})"),
        None => format!("Not reported yet (manager on v{desired_version})"),
    }
}

fn render_note(message: &str, error: &str) -> String {
    if !error.trim().is_empty() {
        let extra = if message.trim().is_empty() {
            String::new()
        } else {
            format!(r#"<small>Agent note: {}</small>"#, escape_html(message))
        };
        format!(
            r#"<div class="note error"><strong>Last error</strong><div>{}</div>{}</div>"#,
            escape_html(error),
            extra
        )
    } else if !message.trim().is_empty() {
        format!(
            r#"<div class="note success"><strong>Agent note</strong><div>{}</div></div>"#,
            escape_html(message)
        )
    } else {
        r#"<div class="note info"><strong>Waiting for status</strong><div>No detailed agent message has been reported yet.</div></div>"#.to_string()
    }
}

fn render_token_kind_badge(kind: &str) -> String {
    let label = if kind.trim().eq_ignore_ascii_case("server") {
        "Server"
    } else {
        "Client"
    };
    render_badge(label, "info")
}

fn render_token_state_badge(used_at: &str) -> String {
    if used_at.trim().is_empty() {
        render_badge("Ready", "ok")
    } else {
        render_badge("Used", "muted-pill")
    }
}

fn server_display_name(server_id: &str, servers: &[ServerRow]) -> String {
    let trimmed = server_id.trim();
    if trimmed.is_empty() {
        return "Unassigned".to_string();
    }

    servers
        .iter()
        .find(|server| server.server_id == trimmed)
        .map(|server| format!("{} ({})", server.node_name, server.server_id))
        .unwrap_or_else(|| trimmed.to_string())
}

fn render_server_select(selected_server_id: &str, servers: &[ServerRow]) -> String {
    let mut options = String::from(r#"<option value="">Unassigned</option>"#);
    for server in servers {
        let selected = if server.server_id == selected_server_id {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            r#"<option value="{}"{}>{}</option>"#,
            escape_html(&server.server_id),
            selected,
            escape_html(&format!("{} ({})", server.node_name, server.server_id))
        ));
    }
    options
}

fn render_token_row(token: &TokenRow) -> String {
    format!(
        r#"<tr><td><div class="token"><code>{}</code><button class="btn-secondary" type="button" data-copy="{}">Copy token</button><button class="btn-secondary" type="button" data-copy-command data-kind="{}" data-token="{}" data-label="{}">Copy run command</button></div></td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
        escape_html(&token.token),
        escape_html(&token.token),
        escape_html(&token.kind),
        escape_html(&token.token),
        escape_html(&token.label),
        render_token_kind_badge(&token.kind),
        render_token_state_badge(&token.used_at),
        escape_html(&token.label),
        escape_html(&format_timestamp(&token.created_at)),
        escape_html(&format_used_timestamp(&token.used_at)),
    )
}

fn render_server_card(server: &ServerRow, desired_version: u64) -> String {
    let form_id = format!("server-form-{}", server.server_id);
    let meta = vec![
        render_meta_card(
            "Server ID",
            &format!("<code>{}</code>", escape_html(&server.server_id)),
        ),
        render_meta_card(
            "Last heartbeat",
            &escape_html(&format_last_seen(&server.last_seen)),
        ),
        render_meta_card(
            "Public endpoint",
            &format!(
                "<code>{}</code>",
                escape_html(&display_text(&server.public_endpoint, "Not set"))
            ),
        ),
        render_meta_card(
            "Connected clients",
            &escape_html(&server.connected_clients.to_string()),
        ),
        render_meta_card(
            "Applied config",
            &escape_html(&format_applied_version(
                server.current_version,
                desired_version,
            )),
        ),
        render_meta_card(
            "NAT interface",
            &format!(
                "<code>{}</code>",
                escape_html(&display_text(&server.nat_iface, "Not set"))
            ),
        ),
    ]
    .join("");

    format!(
        r#"<article class="card"><div class="item-top"><div><span class="eyebrow">Server node</span><h3>{}</h3><p class="muted">Managed Linux tunnel server with policy pushed from the control plane.</p></div><div class="badges">{}{}{} </div></div><div class="meta">{}</div>{}<form id="{}" class="grid" method="post" action="/servers/{}">{}<div class="grid two">{}{}{}{} </div></form>{}</article>"#,
        escape_html(&server.node_name),
        render_enabled_badge(server.enabled),
        render_heartbeat_badge(&server.last_seen),
        render_config_badge(server.current_version, desired_version),
        meta,
        render_note(&server.last_message, &server.last_error),
        escape_html(&form_id),
        escape_html(&server.server_id),
        render_toggle_field(
            "Server enabled",
            "enabled",
            server.enabled,
            "Disable a node here if it should stay enrolled but stop accepting managed traffic."
        ),
        render_input_field(
            "Listen address",
            "listen_addr",
            "text",
            &server.listen_addr,
            "UDP bind address on the Linux host."
        ),
        render_input_field(
            "Public endpoint",
            "public_endpoint",
            "text",
            &server.public_endpoint,
            "Reachable address clients should dial."
        ),
        render_input_field(
            "NAT interface",
            "nat_iface",
            "text",
            &server.nat_iface,
            "Linux WAN interface used for forwarding and NAT."
        ),
        render_input_field(
            "Max clients",
            "max_clients",
            "number",
            &server.max_clients.to_string(),
            "Maximum active client sessions for this node."
        ),
        render_card_actions(
            &form_id,
            "Save server",
            "Update this node's reachability details here, or remove it once the server has been retired.",
            &format!("/servers/{}/delete", server.server_id),
            "Remove server",
            &format!(
                "Remove server '{}' and unassign any clients linked to it?",
                server.node_name
            ),
        ),
    )
}

fn render_client_card(client: &ClientRow, servers: &[ServerRow], desired_version: u64) -> String {
    let form_id = format!("client-form-{}", client.client_id);
    let meta = vec![
        render_meta_card(
            "Client ID",
            &format!("<code>{}</code>", escape_html(&client.client_id)),
        ),
        render_meta_card(
            "Assigned server",
            &escape_html(&server_display_name(&client.server_id, servers)),
        ),
        render_meta_card(
            "Tunnel IP",
            &format!(
                "<code>{}</code>",
                escape_html(&display_text(&client.assigned_ip, "Not set"))
            ),
        ),
        render_meta_card(
            "Egress IP",
            &format!(
                "<code>{}</code>",
                escape_html(&display_text(&client.egress_ip, "Not set"))
            ),
        ),
        render_meta_card(
            "Last heartbeat",
            &escape_html(&format_last_seen(&client.last_seen)),
        ),
        render_meta_card(
            "Applied config",
            &escape_html(&format_applied_version(
                client.current_version,
                desired_version,
            )),
        ),
    ]
    .join("");

    format!(
        r#"<article class="card"><div class="item-top"><div><span class="eyebrow">Client device</span><h3>{}</h3><p class="muted">Managed endpoint that receives tunnel assignment, DNS settings, and server mapping.</p></div><div class="badges">{}{}{} </div></div><div class="meta">{}</div>{}<form id="{}" class="grid" method="post" action="/clients/{}">{}<div class="grid two">{}{}{} </div></form>{}</article>"#,
        escape_html(&client.device_name),
        render_enabled_badge(client.enabled),
        render_heartbeat_badge(&client.last_seen),
        render_config_badge(client.current_version, desired_version),
        meta,
        render_note(&client.last_message, &client.last_error),
        escape_html(&form_id),
        escape_html(&client.client_id),
        render_toggle_field(
            "Client enabled",
            "enabled",
            client.enabled,
            "Disable a device here if it should stay enrolled but no longer receive an active tunnel config."
        ),
        render_input_field("Assigned IP", "assigned_ip", "text", &client.assigned_ip, "Static tunnel IP pushed to the device."),
        render_select_field(
            "Assigned server",
            "server_id",
            &render_server_select(&client.server_id, servers),
            "Choose which enrolled server should accept this client."
        ),
        render_input_field("Egress IP override", "egress_ip", "text", &client.egress_ip, "Optional per-client SNAT address."),
        render_card_actions(
            &form_id,
            "Save client",
            "Adjust assignment details here, or remove the record if the device should enroll from scratch later.",
            &format!("/clients/{}/delete", client.client_id),
            "Remove client",
            &format!(
                "Remove client '{}' from the manager? The device will need to enroll again to come back.",
                client.device_name
            ),
        ),
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_trims_and_drops_blank_lines() {
        let parsed = parse_lines(" 10.0.0.1 \n\n10.0.0.2/32 \n");
        assert_eq!(
            parsed,
            vec!["10.0.0.1".to_string(), "10.0.0.2/32".to_string()]
        );
    }

    #[test]
    fn allocate_client_ip_skips_server_address_and_existing_clients() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE client_nodes (
                client_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                assigned_ip TEXT NOT NULL,
                server_id TEXT,
                tunnel_token TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                egress_ip TEXT
            );",
        )
        .expect("schema");

        let first = allocate_client_ip(&conn, "10.44.0.0/24", "10.44.0.1").expect("first IP");
        assert_eq!(first, "10.44.0.10");

        conn.execute(
            "INSERT INTO client_nodes (client_id, device_name, assigned_ip, server_id, tunnel_token, enabled, egress_ip)
             VALUES (?1, ?2, ?3, NULL, ?4, 1, NULL)",
            params!["client-1", "test-device", first, "token-1"],
        )
        .expect("insert existing client");

        let second = allocate_client_ip(&conn, "10.44.0.0/24", "10.44.0.1").expect("second IP");
        assert_eq!(second, "10.44.0.11");
    }

    #[test]
    fn delete_server_record_unassigns_clients_and_removes_agent() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                node_name TEXT NOT NULL,
                agent_secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                current_version INTEGER,
                last_seen TEXT,
                last_error TEXT NOT NULL DEFAULT '',
                last_message TEXT NOT NULL DEFAULT '',
                connected_clients INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE server_nodes (
                server_id TEXT PRIMARY KEY,
                node_name TEXT NOT NULL,
                listen_addr TEXT NOT NULL,
                public_endpoint TEXT NOT NULL,
                tun_name TEXT NOT NULL,
                tun_address TEXT NOT NULL,
                tun_prefix INTEGER NOT NULL,
                mtu INTEGER,
                client_cidr TEXT NOT NULL,
                nat_iface TEXT,
                setup_nat INTEGER NOT NULL DEFAULT 1,
                max_clients INTEGER NOT NULL,
                egress_ips_json TEXT NOT NULL,
                blocked_ips_json TEXT NOT NULL,
                protected_ips_json TEXT NOT NULL,
                doh_url TEXT NOT NULL,
                dns_bind_addr TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
             );
             CREATE TABLE client_nodes (
                client_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                assigned_ip TEXT NOT NULL,
                server_id TEXT,
                tunnel_token TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                egress_ip TEXT
             );",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('config_version', '7')",
            [],
        )
        .expect("config version");
        conn.execute(
            "INSERT INTO agents (agent_id, kind, node_name, agent_secret, enabled, current_version, last_seen, last_error, last_message, connected_clients)
             VALUES (?1, 'server', 'vpn-1', 'secret', 1, NULL, NULL, '', '', 0)",
            params!["server-1"],
        )
        .expect("agent");
        conn.execute(
            "INSERT INTO server_nodes (server_id, node_name, listen_addr, public_endpoint, tun_name, tun_address, tun_prefix, mtu, client_cidr, nat_iface, setup_nat, max_clients, egress_ips_json, blocked_ips_json, protected_ips_json, doh_url, dns_bind_addr, enabled)
             VALUES (?1, 'vpn-1', '0.0.0.0:9000', '192.168.1.10:9000', 'ntz0', '10.44.0.1', 24, 1400, '10.44.0.0/24', 'ens33', 1, 32, '[]', '[]', '[]', 'https://1.1.1.1/dns-query', '10.44.0.1:53', 1)",
            params!["server-1"],
        )
        .expect("server node");
        conn.execute(
            "INSERT INTO client_nodes (client_id, device_name, assigned_ip, server_id, tunnel_token, enabled, egress_ip)
             VALUES (?1, 'client-1', '10.44.0.10', ?2, 'token-1', 1, NULL)",
            params!["client-1", "server-1"],
        )
        .expect("client node");

        delete_server_record(&conn, "server-1").expect("delete server");

        let remaining_servers: i64 = conn
            .query_row("SELECT COUNT(*) FROM server_nodes", [], |row| row.get(0))
            .expect("remaining servers");
        let remaining_agents: i64 = conn
            .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
            .expect("remaining agents");
        let reassigned_server: Option<String> = conn
            .query_row(
                "SELECT server_id FROM client_nodes WHERE client_id = 'client-1'",
                [],
                |row| row.get(0),
            )
            .expect("client assignment");
        let version = current_config_version(&conn).expect("version");

        assert_eq!(remaining_servers, 0);
        assert_eq!(remaining_agents, 0);
        assert_eq!(reassigned_server, None);
        assert_eq!(version, 8);
    }

    #[test]
    fn delete_client_record_removes_client_and_agent() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                node_name TEXT NOT NULL,
                agent_secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                current_version INTEGER,
                last_seen TEXT,
                last_error TEXT NOT NULL DEFAULT '',
                last_message TEXT NOT NULL DEFAULT '',
                connected_clients INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE client_nodes (
                client_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                assigned_ip TEXT NOT NULL,
                server_id TEXT,
                tunnel_token TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                egress_ip TEXT
             );",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('config_version', '4')",
            [],
        )
        .expect("config version");
        conn.execute(
            "INSERT INTO agents (agent_id, kind, node_name, agent_secret, enabled, current_version, last_seen, last_error, last_message, connected_clients)
             VALUES (?1, 'client', 'client-1', 'secret', 1, NULL, NULL, '', '', 0)",
            params!["client-1"],
        )
        .expect("agent");
        conn.execute(
            "INSERT INTO client_nodes (client_id, device_name, assigned_ip, server_id, tunnel_token, enabled, egress_ip)
             VALUES (?1, 'client-1', '10.44.0.10', NULL, 'token-1', 1, NULL)",
            params!["client-1"],
        )
        .expect("client node");

        delete_client_record(&conn, "client-1").expect("delete client");

        let remaining_clients: i64 = conn
            .query_row("SELECT COUNT(*) FROM client_nodes", [], |row| row.get(0))
            .expect("remaining clients");
        let remaining_agents: i64 = conn
            .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
            .expect("remaining agents");
        let version = current_config_version(&conn).expect("version");

        assert_eq!(remaining_clients, 0);
        assert_eq!(remaining_agents, 0);
        assert_eq!(version, 5);
    }
}
