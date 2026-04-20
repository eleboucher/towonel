use serde::Deserialize;
use towonel_common::tls_policy::TlsMode;

/// Agent-side routing config: the list of services this agent serves.
/// Identity, hub URL, and trusted edges come from the invite token.
#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
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
    pub hostname: String,
    pub origin: String,
    #[serde(default)]
    pub origin_server_name: Option<String>,
    #[serde(default)]
    pub tls_mode: towonel_common::tls_policy::TlsMode,
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
}

impl ServiceConfig {
    pub fn resolved_proxy_protocol(&self) -> ProxyProtocol {
        self.proxy_protocol
            .unwrap_or_else(|| ProxyProtocol::default_for_tls_mode(self.tls_mode))
    }
}

#[allow(clippy::derivable_impls)]
impl Default for ProxyProtocol {
    /// Intentional manual impl: the `V2` default is a deliberate policy
    /// decision (only L4 way to convey client IP in passthrough mode), not
    /// just the first variant.
    fn default() -> Self {
        Self::V2
    }
}

impl AgentConfig {
    /// Load `services` from `TOWONEL_AGENT_SERVICES` (JSON-encoded array).
    /// Empty when the env var is unset — the agent runs, it just won't
    /// publish any TLS-termination hints.
    pub fn load() -> anyhow::Result<Self> {
        let services = std::env::var("TOWONEL_AGENT_SERVICES")
            .ok()
            .map(|v| serde_json::from_str::<Vec<ServiceConfig>>(&v))
            .transpose()?
            .unwrap_or_default();
        Ok(Self { services })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::tls_policy::TlsMode;

    #[test]
    fn services_json_env_var_parses_tls_mode() {
        let json = r#"[
            {"hostname":"*.bob.example.eu","origin":"127.0.0.1:8080",
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
        assert_eq!(svc_passthrough.resolved_proxy_protocol(), ProxyProtocol::V2);

        let svc_terminate: ServiceConfig = serde_json::from_str(
            r#"{"hostname":"b.example","origin":"127.0.0.1:80","tls_mode":{"mode":"terminate"}}"#,
        )
        .unwrap();
        assert_eq!(svc_terminate.resolved_proxy_protocol(), ProxyProtocol::None);
    }
}
