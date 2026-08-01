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
    #[serde(default)]
    pub udp_services: Vec<UdpServiceConfig>,
}

/// `listen_port` is the public port the edge will bind on the agent's behalf
/// (the agent self-publishes the binding so the VPS admin doesn't configure
/// anything). The edge tags forwarded streams with `tcp:<name>` / `udp:<name>`
/// in the PROXY v2 Authority TLV; this agent dispatches on that prefix.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpServiceConfig {
    pub name: String,
    pub origin: String,
    pub listen_port: u16,
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
}

impl TcpServiceConfig {
    pub fn resolved_proxy_protocol(&self) -> ProxyProtocol {
        self.proxy_protocol.unwrap_or(ProxyProtocol::None)
    }
}

/// UDP counterpart of [`TcpServiceConfig`]. Exactly one of `listen_port`
/// (single port) or `listen_port_range` (`[start, end]`, inclusive) must be
/// set. A range forwards each edge port to the origin host at the *same* port,
/// so `origin` is host-only (no `:port`) for ranges. `idle_timeout_secs` sizes
/// the edge session-reap window (`None` → edge default of 60s).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpServiceConfig {
    pub name: String,
    pub origin: String,
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Inclusive `[start, end]` — deserialized from a two-element JSON array.
    #[serde(default)]
    pub listen_port_range: Option<(u16, u16)>,
    #[serde(default)]
    pub idle_timeout_secs: Option<u32>,
}

impl UdpServiceConfig {
    /// Effective inclusive `(port_start, port_end)`. `None` when the config is
    /// invalid (both or neither port field set); [`AgentConfig::validate`]
    /// rejects that before this is consulted at publish time.
    pub const fn port_span(&self) -> Option<(u16, u16)> {
        match (self.listen_port, self.listen_port_range) {
            (Some(p), None) => Some((p, p)),
            (None, Some(range)) => Some(range),
            _ => None,
        }
    }

    pub const fn is_range(&self) -> bool {
        self.listen_port_range.is_some()
    }
}

/// Matches the hub's `MAX_UDP_IDLE_TIMEOUT_SECS`; validated agent-side too so a
/// misconfig fails at boot rather than at publish.
const MAX_UDP_IDLE_TIMEOUT_SECS: u32 = 3600;

/// Matches the hub's default `TOWONEL_HUB_MAX_UDP_PORT_RANGE`. Fail-fast on the
/// agent; the hub stays authoritative (it may be configured lower).
const MAX_UDP_PORT_RANGE: u16 = 512;

/// True when `origin` carries an explicit `:port` (an `ip:port` socket address
/// or a `hostname:port`). A bare IPv6 literal parses as `IpAddr` and is not
/// treated as having a port.
fn origin_has_port(origin: &str) -> bool {
    use std::net::{IpAddr, SocketAddr};
    if origin.parse::<SocketAddr>().is_ok() {
        return true;
    }
    if origin.parse::<IpAddr>().is_ok() {
        return false;
    }
    origin
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
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
    pub const fn default_for_tls_mode(mode: TlsMode) -> Self {
        match mode {
            TlsMode::Passthrough => Self::V2,
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

impl Default for ProxyProtocol {
    /// Intentional manual impl: the `V2` default is a deliberate policy
    /// decision (only L4 way to convey client IP in passthrough mode), not
    /// just the first variant.
    fn default() -> Self {
        Self::V2
    }
}

impl AgentConfig {
    /// Load `services` from `TOWONEL_AGENT_SERVICES`, `tcp_services` from
    /// `TOWONEL_AGENT_TCP_SERVICES`, and `udp_services` from
    /// `TOWONEL_AGENT_UDP_SERVICES` (each JSON-encoded array). Empty when the
    /// env var is unset.
    pub fn load() -> anyhow::Result<Self> {
        let cfg = Self {
            services: load_json_env("TOWONEL_AGENT_SERVICES")?,
            tcp_services: load_json_env("TOWONEL_AGENT_TCP_SERVICES")?,
            udp_services: load_json_env("TOWONEL_AGENT_UDP_SERVICES")?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject configs where two services in the same protocol would map to the
    /// same `listen_port` (the hub would accept only one), or where a service
    /// name collides with a hostname (the agent's stream dispatcher would pick
    /// one arbitrarily). TCP and UDP have independent port and name namespaces:
    /// the wire format tags each stream with `tcp:` / `udp:` so the dispatcher
    /// looks up names in protocol-specific maps.
    pub fn validate(&self) -> anyhow::Result<()> {
        let hostnames: std::collections::HashSet<&str> =
            self.services.iter().map(|s| s.hostname.as_str()).collect();
        validate_raw_services("tcp_service", &self.tcp_services, &hostnames)?;
        validate_raw_udp_services(&self.udp_services, &hostnames)?;
        Ok(())
    }
}

/// Parse a JSON-encoded array from env var `name`; empty when unset.
fn load_json_env<T: serde::de::DeserializeOwned>(name: &str) -> anyhow::Result<Vec<T>> {
    let parsed = std::env::var(name)
        .ok()
        .map(|v| serde_json::from_str::<Vec<T>>(&v))
        .transpose()?
        .unwrap_or_default();
    Ok(parsed)
}

fn validate_raw_services(
    label: &str,
    services: &[TcpServiceConfig],
    hostnames: &std::collections::HashSet<&str>,
) -> anyhow::Result<()> {
    let mut names = std::collections::HashSet::new();
    let mut ports = std::collections::HashSet::new();
    for svc in services {
        if svc.name.is_empty() {
            anyhow::bail!("{label} name must not be empty");
        }
        if svc.listen_port == 0 {
            anyhow::bail!("{label} `{}` listen_port must not be 0", svc.name);
        }
        if !names.insert(svc.name.as_str()) {
            anyhow::bail!("duplicate {label} name `{}`", svc.name);
        }
        if !ports.insert(svc.listen_port) {
            anyhow::bail!(
                "duplicate {label} listen_port {} (used by `{}`)",
                svc.listen_port,
                svc.name
            );
        }
        if hostnames.contains(svc.name.as_str()) {
            anyhow::bail!(
                "{label} name `{}` collides with a configured hostname",
                svc.name
            );
        }
    }
    Ok(())
}

/// UDP variant of [`validate_raw_services`]: enforces the single-vs-range
/// port shape, host-only origins for ranges, the idle-timeout bound, and
/// non-overlapping port intervals across all UDP services.
fn validate_raw_udp_services(
    services: &[UdpServiceConfig],
    hostnames: &std::collections::HashSet<&str>,
) -> anyhow::Result<()> {
    let label = "udp_service";
    let mut names = std::collections::HashSet::new();
    // (start, end, service name) for the cross-service overlap check.
    let mut spans: Vec<(u16, u16, &str)> = Vec::new();
    for svc in services {
        if svc.name.is_empty() {
            anyhow::bail!("{label} name must not be empty");
        }
        let (start, end) = match (svc.listen_port, svc.listen_port_range) {
            (Some(_), Some(_)) => anyhow::bail!(
                "{label} `{}` sets both listen_port and listen_port_range; use exactly one",
                svc.name
            ),
            (None, None) => anyhow::bail!(
                "{label} `{}` must set listen_port or listen_port_range",
                svc.name
            ),
            (Some(p), None) => (p, p),
            (None, Some((s, e))) => (s, e),
        };
        if start == 0 {
            anyhow::bail!("{label} `{}` listen_port must not be 0", svc.name);
        }
        if svc.is_range() {
            if end < start {
                anyhow::bail!(
                    "{label} `{}` listen_port_range end {end} must be >= start {start}",
                    svc.name
                );
            }
            let count = u32::from(end - start) + 1;
            if count > u32::from(MAX_UDP_PORT_RANGE) {
                anyhow::bail!(
                    "{label} `{}` range spans {count} ports, over the limit of {MAX_UDP_PORT_RANGE}",
                    svc.name
                );
            }
            if origin_has_port(&svc.origin) {
                anyhow::bail!(
                    "{label} `{}` origin `{}` must be host-only (no :port) for a port range",
                    svc.name,
                    svc.origin
                );
            }
        }
        if let Some(secs) = svc.idle_timeout_secs
            && (secs == 0 || secs > MAX_UDP_IDLE_TIMEOUT_SECS)
        {
            anyhow::bail!(
                "{label} `{}` idle_timeout_secs {secs} must be between 1 and {MAX_UDP_IDLE_TIMEOUT_SECS}",
                svc.name
            );
        }
        if !names.insert(svc.name.as_str()) {
            anyhow::bail!("duplicate {label} name `{}`", svc.name);
        }
        if hostnames.contains(svc.name.as_str()) {
            anyhow::bail!(
                "{label} name `{}` collides with a configured hostname",
                svc.name
            );
        }
        spans.push((start, end, svc.name.as_str()));
    }

    spans.sort_by_key(|(start, _, _)| *start);
    for ((a_start, a_end, a_name), (b_start, b_end, b_name)) in
        spans.iter().zip(spans.iter().skip(1))
    {
        if b_start <= a_end {
            anyhow::bail!(
                "{label} port ranges overlap: `{a_name}` ({a_start}-{a_end}) and `{b_name}` ({b_start}-{b_end})"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::tls_policy::TlsMode;

    #[test]
    fn services_json_env_var_legacy_terminate_maps_to_passthrough() {
        let json = r#"[
            {"hostname":"*.bob.example.eu","origin":"127.0.0.1:8080",
             "tls_mode":{"mode":"terminate"}},
            {"hostname":"api.example.eu","origin":"127.0.0.1:9000"}
        ]"#;
        let services: Vec<ServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].tls_mode, TlsMode::Passthrough);
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
    }

    #[test]
    fn tcp_services_json_parses() {
        let json = r#"[
            {"name":"forgejo-ssh","origin":"forgejo:22","listen_port":2222,"proxy_protocol":"v2"},
            {"name":"prom-write","origin":"victoriametrics:8428","listen_port":9090}
        ]"#;
        let svcs: Vec<TcpServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].name, "forgejo-ssh");
        assert_eq!(svcs[0].origin, "forgejo:22");
        assert_eq!(svcs[0].listen_port, 2222);
        assert_eq!(svcs[0].resolved_proxy_protocol(), ProxyProtocol::V2);
        assert_eq!(svcs[1].resolved_proxy_protocol(), ProxyProtocol::None);
    }

    #[test]
    fn validate_rejects_duplicate_tcp_service_names() {
        let cfg = AgentConfig {
            services: Vec::new(),
            udp_services: Vec::new(),
            tcp_services: vec![
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:22".into(),
                    listen_port: 2222,
                    proxy_protocol: None,
                },
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:23".into(),
                    listen_port: 2223,
                    proxy_protocol: None,
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
            udp_services: Vec::new(),
            tcp_services: vec![
                TcpServiceConfig {
                    name: "ssh".into(),
                    origin: "127.0.0.1:22".into(),
                    listen_port: 2222,
                    proxy_protocol: None,
                },
                TcpServiceConfig {
                    name: "metrics".into(),
                    origin: "127.0.0.1:9000".into(),
                    listen_port: 2222,
                    proxy_protocol: None,
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
            udp_services: Vec::new(),
            tcp_services: vec![TcpServiceConfig {
                name: String::new(),
                origin: "127.0.0.1:22".into(),
                listen_port: 2222,
                proxy_protocol: None,
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_listen_port() {
        let cfg = AgentConfig {
            services: Vec::new(),
            udp_services: Vec::new(),
            tcp_services: vec![TcpServiceConfig {
                name: "ssh".into(),
                origin: "127.0.0.1:22".into(),
                listen_port: 0,
                proxy_protocol: None,
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_distinct_udp_service() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: Vec::new(),
            udp_services: vec![UdpServiceConfig {
                name: "dns".into(),
                origin: "127.0.0.1:5353".into(),
                listen_port: Some(5353),
                listen_port_range: None,
                idle_timeout_secs: None,
            }],
        };
        cfg.validate().expect("valid udp_service should pass");
    }

    #[test]
    fn udp_services_json_parses() {
        let json = r#"[
            {"name":"dns","origin":"127.0.0.1:5353","listen_port":5353},
            {"name":"wg","origin":"10.0.0.1:51820","listen_port":51820}
        ]"#;
        let svcs: Vec<UdpServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].name, "dns");
        assert_eq!(svcs[0].listen_port, Some(5353));
        assert_eq!(svcs[0].idle_timeout_secs, None);
        assert_eq!(svcs[1].listen_port, Some(51820));
    }

    #[test]
    fn udp_services_json_parses_idle_timeout() {
        let json = r#"[{"name":"turn","origin":"10.0.0.5:3478","listen_port":3478,"idle_timeout_secs":300}]"#;
        let svcs: Vec<UdpServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(svcs[0].idle_timeout_secs, Some(300));
    }

    #[test]
    fn udp_range_json_parses() {
        let json =
            r#"[{"name":"turn-relay","origin":"10.0.0.5","listen_port_range":[49160,49660]}]"#;
        let svcs: Vec<UdpServiceConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(svcs[0].listen_port_range, Some((49160, 49660)));
        assert_eq!(svcs[0].port_span(), Some((49160, 49660)));
        assert!(svcs[0].is_range());
    }

    fn udp_svc(f: impl FnOnce(&mut UdpServiceConfig)) -> AgentConfig {
        let mut svc = UdpServiceConfig {
            name: "svc".into(),
            origin: "10.0.0.5".into(),
            listen_port: None,
            listen_port_range: None,
            idle_timeout_secs: None,
        };
        f(&mut svc);
        AgentConfig {
            services: Vec::new(),
            tcp_services: Vec::new(),
            udp_services: vec![svc],
        }
    }

    #[test]
    fn validate_rejects_out_of_range_idle_timeout() {
        assert!(
            udp_svc(|s| {
                s.origin = "10.0.0.5:3478".into();
                s.listen_port = Some(3478);
                s.idle_timeout_secs = Some(0);
            })
            .validate()
            .is_err()
        );
        assert!(
            udp_svc(|s| {
                s.origin = "10.0.0.5:3478".into();
                s.listen_port = Some(3478);
                s.idle_timeout_secs = Some(3601);
            })
            .validate()
            .is_err()
        );
    }

    #[test]
    fn validate_rejects_both_port_and_range() {
        let err = udp_svc(|s| {
            s.listen_port = Some(3478);
            s.listen_port_range = Some((49160, 49660));
        })
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("exactly one"), "got: {err}");
    }

    #[test]
    fn validate_rejects_neither_port_nor_range() {
        let err = udp_svc(|_| {}).validate().unwrap_err().to_string();
        assert!(err.contains("must set listen_port"), "got: {err}");
    }

    #[test]
    fn validate_rejects_inverted_range() {
        assert!(
            udp_svc(|s| s.listen_port_range = Some((49660, 49160)))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_rejects_oversized_range() {
        assert!(
            udp_svc(|s| s.listen_port_range = Some((10000, 10000 + 512)))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_rejects_origin_with_port_for_range() {
        let err = udp_svc(|s| {
            s.origin = "10.0.0.5:3478".into();
            s.listen_port_range = Some((49160, 49660));
        })
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("host-only"), "got: {err}");
    }

    #[test]
    fn validate_accepts_ipv6_host_only_range_origin() {
        udp_svc(|s| {
            s.origin = "fe80::1".into();
            s.listen_port_range = Some((49160, 49260));
        })
        .validate()
        .expect("bare IPv6 host-only origin should pass");
    }

    #[test]
    fn validate_rejects_overlapping_udp_ranges() {
        let cfg = AgentConfig {
            services: Vec::new(),
            tcp_services: Vec::new(),
            udp_services: vec![
                UdpServiceConfig {
                    name: "a".into(),
                    origin: "10.0.0.5".into(),
                    listen_port: None,
                    listen_port_range: Some((49160, 49200)),
                    idle_timeout_secs: None,
                },
                UdpServiceConfig {
                    name: "b".into(),
                    origin: "10.0.0.6".into(),
                    listen_port: Some(49180),
                    listen_port_range: None,
                    idle_timeout_secs: None,
                },
            ],
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("overlap"), "got: {err}");
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
                proxy_protocol: None,
            }],
            udp_services: Vec::new(),
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("collides"), "got: {err}");
    }
}
