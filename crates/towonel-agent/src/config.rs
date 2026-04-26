use serde::Deserialize;
use towonel_common::tls_policy::TlsMode;

/// Agent-side routing config: the list of services this agent serves.
/// Identity, hub URL, and trusted edges come from the invite token.
#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub tcp_services: Vec<TcpServiceConfig>,
}

/// `listen_port` is the public port the edge will bind on the agent's behalf
/// (the agent self-publishes the binding so the VPS admin doesn't configure
/// anything). The edge tags forwarded streams with `tcp:<name>` in the
/// PROXY v2 Authority TLV; this agent dispatches on that prefix.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpServiceConfig {
    pub name: String,
    pub origin: String,
    pub listen_port: u16,
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
    /// Load `services` from `TOWONEL_AGENT_SERVICES` and `tcp_services` from
    /// `TOWONEL_AGENT_TCP_SERVICES` (each JSON-encoded array). Empty when the
    /// env var is unset.
    pub fn load() -> anyhow::Result<Self> {
        let services = std::env::var("TOWONEL_AGENT_SERVICES")
            .ok()
            .map(|v| serde_json::from_str::<Vec<ServiceConfig>>(&v))
            .transpose()?
            .unwrap_or_default();
        let tcp_services = std::env::var("TOWONEL_AGENT_TCP_SERVICES")
            .ok()
            .map(|v| serde_json::from_str::<Vec<TcpServiceConfig>>(&v))
            .transpose()?
            .unwrap_or_default();

        let cfg = Self {
            services,
            tcp_services,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject configs where two TCP services would map to the same port (the
    /// hub would accept only one), or where a TCP service name collides with a
    /// hostname (the agent's stream dispatcher would pick one arbitrarily).
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut seen_tcp = std::collections::HashSet::new();
        let mut seen_port = std::collections::HashSet::new();
        for svc in &self.tcp_services {
            if svc.name.is_empty() {
                anyhow::bail!("tcp_service name must not be empty");
            }
            if svc.listen_port == 0 {
                anyhow::bail!("tcp_service `{}` listen_port must not be 0", svc.name);
            }
            if !seen_tcp.insert(svc.name.as_str()) {
                anyhow::bail!("duplicate tcp_service name `{}`", svc.name);
            }
            if !seen_port.insert(svc.listen_port) {
                anyhow::bail!(
                    "duplicate tcp_service listen_port {} (used by `{}`)",
                    svc.listen_port,
                    svc.name
                );
            }
        }
        let hostnames: std::collections::HashSet<&str> =
            self.services.iter().map(|s| s.hostname.as_str()).collect();
        for svc in &self.tcp_services {
            if hostnames.contains(svc.name.as_str()) {
                anyhow::bail!(
                    "tcp_service name `{}` collides with a configured hostname",
                    svc.name
                );
            }
        }
        Ok(())
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

    #[test]
    fn tcp_services_json_parses() {
        let json = r#"[
            {"name":"forgejo-ssh","origin":"forgejo:22","listen_port":2222},
            {"name":"prom-write","origin":"victoriametrics:8428","listen_port":9090}
        ]"#;
        let svcs: Vec<TcpServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].name, "forgejo-ssh");
        assert_eq!(svcs[0].origin, "forgejo:22");
        assert_eq!(svcs[0].listen_port, 2222);
    }

    #[test]
    fn validate_rejects_duplicate_tcp_service_names() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: vec![
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:22".into(),
                    listen_port: 2222,
                },
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:23".into(),
                    listen_port: 2223,
                },
            ],
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn validate_rejects_duplicate_listen_ports() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: vec![
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:22".into(),
                    listen_port: 2222,
                },
                TcpServiceConfig {
                    name: "metrics".into(),
                    origin: "127.0.0.1:9000".into(),
                    listen_port: 2222,
                },
            ],
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate"), "got: {err}");
        assert!(err.contains("listen_port"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_tcp_service_name() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: vec![TcpServiceConfig {
                name: String::new(),
                origin: "127.0.0.1:22".into(),
                listen_port: 2222,
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_listen_port() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: vec![TcpServiceConfig {
                name: "ssh".into(),
                origin: "127.0.0.1:22".into(),
                listen_port: 0,
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_hostname_collision() {
        let cfg = AgentConfig {
            services: vec![ServiceConfig {
                hostname: "ssh".into(),
                origin: "127.0.0.1:8080".into(),
                origin_server_name: None,
                tls_mode: TlsMode::default(),
                proxy_protocol: None,
            }],
            tcp_services: vec![TcpServiceConfig {
                name: "ssh".into(),
                origin: "127.0.0.1:22".into(),
                listen_port: 2222,
            }],
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("collides"), "got: {err}");
    }
}
