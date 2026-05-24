use crate::agent_state::{load_agent_state, save_agent_state};
use crate::models::{
    AgentKind, EnrollmentRequest, EnrollmentResponse, HeartbeatRequest, HeartbeatResponse,
    PersistedAgentState, StatusRequest, StatusResponse,
};
use chrono::Utc;
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use std::io;
use std::path::{Path, PathBuf};

pub struct AgentBootstrap {
    pub kind: AgentKind,
    pub management_url: String,
    pub enrollment_token: String,
    pub node_name: String,
    pub state_dir: PathBuf,
}

#[derive(Clone)]
pub struct ManagerHttpClient {
    base_url: String,
    inner: Client,
}

impl ManagerHttpClient {
    pub fn new(base_url: &str) -> io::Result<Self> {
        let inner = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(to_io_error)?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            inner,
        })
    }

    pub fn enroll(&self, request: &EnrollmentRequest) -> io::Result<EnrollmentResponse> {
        self.post_json("/api/agent/enroll", request)
    }

    pub fn heartbeat(&self, request: &HeartbeatRequest) -> io::Result<HeartbeatResponse> {
        self.post_json("/api/agent/heartbeat", request)
    }

    pub fn status(&self, request: &StatusRequest) -> io::Result<StatusResponse> {
        self.post_json("/api/agent/status", request)
    }

    fn post_json<TReq, TResp>(&self, path: &str, request: &TReq) -> io::Result<TResp>
    where
        TReq: serde::Serialize,
        TResp: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .inner
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(request)
            .send()
            .map_err(to_io_error)?;

        if !response.status().is_success() {
            let status = response.status();
            let detail = response
                .text()
                .ok()
                .and_then(|body| extract_management_error(&body))
                .unwrap_or_else(|| status.to_string());
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("management server returned {detail}"),
            ));
        }

        response.json::<TResp>().map_err(to_io_error)
    }
}

pub fn load_or_enroll(
    bootstrap: &AgentBootstrap,
) -> io::Result<(PersistedAgentState, ManagerHttpClient)> {
    let client = ManagerHttpClient::new(&bootstrap.management_url)?;
    if let Some(state) = load_agent_state(Path::new(&bootstrap.state_dir))? {
        return Ok((state, client));
    }

    let enrollment = client.enroll(&EnrollmentRequest {
        kind: bootstrap.kind.clone(),
        enrollment_token: bootstrap.enrollment_token.clone(),
        node_name: bootstrap.node_name.clone(),
    })?;

    let state = PersistedAgentState {
        agent_id: enrollment.agent_id,
        agent_secret: enrollment.agent_secret,
        kind: bootstrap.kind.clone(),
        enrolled_at: Utc::now().to_rfc3339(),
    };

    save_agent_state(Path::new(&bootstrap.state_dir), &state)?;
    Ok((state, client))
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn extract_management_error(body: &str) -> Option<String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(error) = json.get("error").and_then(|value| value.as_str()) {
            return Some(error.trim().to_string());
        }
    }

    let collapsed = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}
