use std::path::PathBuf;

use serde::Deserialize;
use towonel_common::client_state::{ClientState, DefaultPaths};
use towonel_common::tls_policy::TlsMode;

#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Hex-encoded iroh `EndpointIds` of trusted edges. May be omitted when
    /// `~/.towonel/state.toml` already carries the list (written by
    /// `towonel-agent init`).
    #[serde(default)]
    pub trusted_edges: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IdentityConfig {
    /// Path to the agent's iroh secret key. Defaults to
    /// `~/.towonel/agent.key` or whatever state.toml provides.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    /// Do not prepend any PROXY header.
    None,
    /// Prepend `HAProxy` PROXY v2 header to the origin stream.
    V2,
}

impl ProxyProtocol {
    /// Default for a service when the user didn't pin `proxy_protocol`.
    /// Derived from [`TlsMode`]:
    /// - [`TlsMode::Passthrough`] → [`ProxyProtocol::V2`] (the only L4 mechanism
    ///   left to convey the client IP once envoy terminates TLS itself)
    /// - [`TlsMode::Terminate`] → [`ProxyProtocol::None`] (edge already
    ///   handshook; bytes reaching origin are HTTP — a PROXY prefix would
    ///   corrupt envoy's HTTP listener)
    pub const fn default_for_tls_mode(mode: TlsMode) -> Self {
        match mode {
            TlsMode::Passthrough => Self::V2,
            TlsMode::Terminate => Self::None,
        }
    }
}

/// A service the agent exposes. The edge routes to it by SNI-matching
/// `hostname` on its TLS listeners.
#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    /// The hostname this service handles (SNI match at the edge).
    pub hostname: String,
    /// Where to forward traffic locally.
    pub origin: String,
    /// TLS SNI to send when connecting to the origin over HTTPS.
    /// When set, the agent wraps the TCP connection with TLS using this
    /// name (like Cloudflare Tunnel's `originServerName`).
    /// When absent, the agent connects over plain TCP.
    #[serde(default)]
    pub origin_server_name: Option<String>,
    /// How the edge should handle TLS for this hostname. Defaults to
    /// passthrough — the agent/origin terminates. Set to `terminate` to
    /// have the edge handshake and forward plaintext.
    #[serde(default)]
    pub tls_mode: towonel_common::tls_policy::TlsMode,
    /// PROXY protocol header prepended to the origin connection. When
    /// omitted, defaults derive from `tls_mode`: passthrough → v2 (only L4
    /// way to convey client IP), terminate → none (bytes are HTTP, PROXY
    /// would corrupt the origin's HTTP listener).
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
}

impl ServiceConfig {
    /// Resolve the effective PROXY protocol mode for this service, using
    /// the explicit value if set, otherwise the [`TlsMode`]-derived default.
    pub fn resolved_proxy_protocol(&self) -> ProxyProtocol {
        self.proxy_protocol
            .unwrap_or_else(|| ProxyProtocol::default_for_tls_mode(self.tls_mode))
    }
}

impl Default for ProxyProtocol {
    /// Backstop for callers that don't have a `TlsMode` available. Prefer
    /// [`ProxyProtocol::default_for_tls_mode`] in service-aware code paths.
    fn default() -> Self {
        Self::V2
    }
}

/// Fully resolved agent settings after merging `agent.toml` and `state.toml`.
pub struct ResolvedConfig {
    pub key_path: PathBuf,
    pub services: Vec<ServiceConfig>,
    pub trusted_edges: Vec<String>,
    pub hub_url: Option<String>,
    pub tenant_key_path: Option<PathBuf>,
}

impl AgentConfig {
    /// Load config from TOML, then override with `TOWONEL_AGENT_*` env vars.
    ///
    /// ```text
    /// TOWONEL_AGENT_SERVICES='[{"hostname":"app.eu","origin":"127.0.0.1:8080"}]'
    /// TOWONEL_AGENT_IDENTITY_KEY_PATH=/keys/agent.key
    /// TOWONEL_AGENT_TRUSTED_EDGES='["abc123"]'
    /// ```
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let mut config: Self = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)?
        } else {
            Self::default()
        };

        if let Ok(v) = std::env::var("TOWONEL_AGENT_SERVICES") {
            config.services = serde_json::from_str(&v)?;
        }
        if let Ok(v) = std::env::var("TOWONEL_AGENT_IDENTITY_KEY_PATH") {
            config.identity.key_path = Some(v.into());
        }
        if let Ok(v) = std::env::var("TOWONEL_AGENT_TRUSTED_EDGES") {
            config.trusted_edges = serde_json::from_str(&v)?;
        }
        Ok(config)
    }

    /// Merge this agent config with `state.toml`. Fields set in the agent
    /// config win; state.toml fills in gaps. Errors only on missing
    /// agent key path (the one field we can't default to nothing).
    pub fn resolve(self, state: &ClientState) -> ResolvedConfig {
        let defaults = DefaultPaths::from_env();
        let key_path = self
            .identity
            .key_path
            .or_else(|| state.agent_key_path.clone())
            .unwrap_or(defaults.agent_key);

        let trusted_edges = if self.trusted_edges.is_empty() {
            state.trusted_edges.clone()
        } else {
            self.trusted_edges
        };

        ResolvedConfig {
            key_path,
            services: self.services,
            trusted_edges,
            hub_url: state.hub_url.clone(),
            tenant_key_path: state.tenant_key_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::tls_policy::TlsMode;

    #[test]
    fn services_json_env_var_parses_tls_mode() {
        let json = r#"[
            {"hostname":"*.bob.example","origin":"127.0.0.1:8080",
             "tls_mode":{"mode":"terminate"}},
            {"hostname":"api.example.eu","origin":"127.0.0.1:9000"}
        ]"#;
        let services: Vec<ServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(services.len(), 2);
        assert!(matches!(services[0].tls_mode, TlsMode::Terminate));
        assert_eq!(services[1].tls_mode, TlsMode::Passthrough);
    }

    #[test]
    fn services_json_parses_proxy_protocol() {
        let json = r#"[
            {"hostname":"app.a","origin":"127.0.0.1:80","proxy_protocol":"none"},
            {"hostname":"app.b","origin":"127.0.0.1:80"}
        ]"#;
        let services: Vec<ServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(services[0].proxy_protocol, Some(ProxyProtocol::None));
        assert_eq!(services[0].resolved_proxy_protocol(), ProxyProtocol::None);
        assert_eq!(services[1].proxy_protocol, None);
        assert_eq!(services[1].resolved_proxy_protocol(), ProxyProtocol::V2);
    }

    #[test]
    fn proxy_protocol_default_derives_from_tls_mode() {
        let svc_passthrough: ServiceConfig =
            serde_json::from_str(r#"{"hostname":"a.example","origin":"127.0.0.1:443"}"#).unwrap();
        assert_eq!(
            svc_passthrough.resolved_proxy_protocol(),
            ProxyProtocol::V2,
            "passthrough should default to PROXY v2 (only L4 way to convey client IP)"
        );

        let svc_terminate: ServiceConfig = serde_json::from_str(
            r#"{"hostname":"b.example","origin":"127.0.0.1:80","tls_mode":{"mode":"terminate"}}"#,
        )
        .unwrap();
        assert_eq!(
            svc_terminate.resolved_proxy_protocol(),
            ProxyProtocol::None,
            "terminate should default to no PROXY (origin gets HTTP, PROXY would corrupt it)"
        );
    }
}
