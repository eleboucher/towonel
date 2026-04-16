use std::path::PathBuf;

use serde::Deserialize;
use turbo_common::client_state::{ClientState, DefaultPaths};

#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Hex-encoded iroh EndpointIds of trusted edges. May be omitted when
    /// `~/.turbo-tunnel/state.toml` already carries the list (written by
    /// `turbo-agent init`).
    #[serde(default)]
    pub trusted_edges: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IdentityConfig {
    /// Path to the agent's iroh secret key. Defaults to
    /// `~/.turbo-tunnel/agent.key` or whatever state.toml provides.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    /// The hostname this service handles (SNI match at the edge).
    pub hostname: String,
    /// Where to forward traffic locally.
    pub origin: String,
}

/// Fully resolved agent settings after merging `agent.toml` and `state.toml`.
pub struct ResolvedConfig {
    pub key_path: PathBuf,
    pub services: Vec<ServiceConfig>,
    pub trusted_edges: Vec<String>,
}

impl AgentConfig {
    /// Load config from TOML, then override with `TURBO_AGENT_*` env vars.
    ///
    /// ```text
    /// TURBO_AGENT_SERVICES='[{"hostname":"app.eu","origin":"127.0.0.1:8080"}]'
    /// TURBO_AGENT_IDENTITY_KEY_PATH=/keys/agent.key
    /// TURBO_AGENT_TRUSTED_EDGES='["abc123"]'
    /// ```
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let mut config: Self = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)?
        } else {
            Self::default()
        };

        if let Ok(v) = std::env::var("TURBO_AGENT_SERVICES") {
            config.services = serde_json::from_str(&v)?;
        }
        if let Ok(v) = std::env::var("TURBO_AGENT_IDENTITY_KEY_PATH") {
            config.identity.key_path = Some(v.into());
        }
        if let Ok(v) = std::env::var("TURBO_AGENT_TRUSTED_EDGES") {
            config.trusted_edges = serde_json::from_str(&v)?;
        }
        Ok(config)
    }

    /// Merge this agent config with `state.toml`. Fields set in the agent
    /// config win; state.toml fills in gaps. Errors only on missing
    /// agent key path (the one field we can't default to nothing).
    pub fn resolve(self, state: &ClientState) -> anyhow::Result<ResolvedConfig> {
        let defaults = DefaultPaths::from_env();
        let key_path = self
            .identity
            .key_path
            .or_else(|| state.agent_key_path.clone())
            .unwrap_or(defaults.agent_key);

        let trusted_edges = if !self.trusted_edges.is_empty() {
            self.trusted_edges
        } else {
            state.trusted_edges.clone()
        };

        Ok(ResolvedConfig {
            key_path,
            services: self.services,
            trusted_edges,
        })
    }
}
