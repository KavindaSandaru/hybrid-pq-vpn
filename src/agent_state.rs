use crate::models::PersistedAgentState;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "agent_state.json";

pub fn ensure_state_dir(state_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(state_dir)
}

pub fn load_agent_state(state_dir: &Path) -> io::Result<Option<PersistedAgentState>> {
    let path = state_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(path)?;
    let state = serde_json::from_str::<PersistedAgentState>(&contents)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(Some(state))
}

pub fn save_agent_state(state_dir: &Path, state: &PersistedAgentState) -> io::Result<()> {
    ensure_state_dir(state_dir)?;
    let payload = serde_json::to_string_pretty(state)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    fs::write(state_path(state_dir), payload)
}

pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}
