use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const DEFAULT_DIR: &str = ".turbo-tunnel";
const STATE_FILE: &str = "state.toml";
const AGENT_KEY_FILE: &str = "agent.key";
const TENANT_KEY_FILE: &str = "tenant.key";

/// Resolved default paths anchored at the turbo-tunnel state directory.
pub struct DefaultPaths {
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub agent_key: PathBuf,
    pub tenant_key: PathBuf,
    pub agent_config: PathBuf,
}

impl DefaultPaths {
    /// Compute defaults from `$HOME`. Falls back to `.` when `$HOME` is
    /// unset so containerized deployments can still run.
    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        let state_dir = home.join(DEFAULT_DIR);
        Self {
            state_file: std::env::var_os("TURBO_STATE").map_or_else(|| state_dir.join(STATE_FILE), PathBuf::from),
            agent_key: state_dir.join(AGENT_KEY_FILE),
            tenant_key: state_dir.join(TENANT_KEY_FILE),
            agent_config: state_dir.join("agent.toml"),
            state_dir,
        }
    }
}

/// The on-disk shape of `state.toml`.
///
/// Each field is optional in deserialization so older state files remain
/// readable as new fields are added. Serialized output skips `None`s.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientState {
    /// Where the hub lives. Used as the default for `turbo-cli --hub-url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_url: Option<String>,

    /// Path to the tenant signing key (Ed25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_key_path: Option<PathBuf>,

    /// Path to the agent (iroh) key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_path: Option<PathBuf>,

    /// Hex-encoded iroh `EndpointIds` of trusted edges. Populated by
    /// `turbo-agent init` from the invite redemption response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_edges: Vec<String>,

    /// Hex-encoded tenant public key -- convenient for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl ClientState {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let state: Self = toml::from_str(&content)?;
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let state = ClientState {
            hub_url: Some("https://hub.example".into()),
            tenant_key_path: Some(PathBuf::from("/keys/tenant.key")),
            agent_key_path: Some(PathBuf::from("/keys/agent.key")),
            trusted_edges: vec!["abc123".into()],
            tenant_id: Some("deadbeef".into()),
        };
        let dir = std::env::temp_dir().join(format!("turbo-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.toml");
        state.save(&path).unwrap();
        let loaded = ClientState::load(&path).unwrap();
        assert_eq!(loaded.hub_url, state.hub_url);
        assert_eq!(loaded.trusted_edges, state.trusted_edges);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_returns_default() {
        let path = std::env::temp_dir().join(format!("missing-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let loaded = ClientState::load(&path).unwrap();
        assert!(loaded.hub_url.is_none());
        assert!(loaded.trusted_edges.is_empty());
    }
}
