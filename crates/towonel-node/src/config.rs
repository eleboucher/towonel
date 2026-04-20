use std::path::PathBuf;

use serde::Deserialize;

/// Which database driver the hub talks to. `sqlite` is the single-node
/// default; `postgres` is for multi-node deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbDriver {
    Sqlite,
    Postgres,
}

impl DbDriver {
    const fn default_max_open_conns(self) -> u32 {
        match self {
            Self::Sqlite => 4,
            Self::Postgres => 25,
        }
    }

    const fn default_max_idle_conns(self) -> u32 {
        match self {
            Self::Sqlite => 4,
            Self::Postgres => 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub driver: DbDriver,
    pub dsn: Option<String>,
    pub max_open_conns: Option<u32>,
    pub max_idle_conns: Option<u32>,
}

impl DatabaseConfig {
    /// Resolve the driver URL fed to `SeaORM`'s `Database::connect`.
    pub fn connection_url(&self) -> anyhow::Result<String> {
        match self.driver {
            DbDriver::Postgres => self
                .dsn
                .clone()
                .ok_or_else(|| anyhow::anyhow!("TOWONEL_HUB_DB_DSN is required for postgres")),
            DbDriver::Sqlite => {
                let raw = self.dsn.as_deref().unwrap_or("hub.db");
                Ok(if raw.starts_with("sqlite:") {
                    raw.to_string()
                } else {
                    format!("sqlite://{raw}?mode=rwc")
                })
            }
        }
    }

    pub fn max_open(&self) -> u32 {
        self.max_open_conns
            .unwrap_or_else(|| self.driver.default_max_open_conns())
    }

    pub fn max_idle(&self) -> u32 {
        self.max_idle_conns
            .unwrap_or_else(|| self.driver.default_max_idle_conns())
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            driver: DbDriver::Sqlite,
            dsn: None,
            max_open_conns: None,
            max_idle_conns: None,
        }
    }
}

/// Best-effort password redaction for Postgres URLs. Used for log lines
/// only — never parse the result back into a connection URL.
pub fn redact_db_url(url: &str) -> String {
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return url.to_string();
    }
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some("***"));
    }
    parsed.to_string()
}

#[derive(Debug)]
pub struct NodeConfig {
    pub identity: IdentityConfig,
    pub hub: HubConfig,
    pub edge: EdgeConfig,
    pub tenants: Vec<TenantEntry>,
}

#[derive(Debug)]
pub struct IdentityConfig {
    pub key_path: PathBuf,
}

#[derive(Debug)]
pub struct HubConfig {
    pub enabled: bool,
    pub database: DatabaseConfig,
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub operator_api_key_path: PathBuf,
    pub public_url: Option<String>,
    pub peers: Vec<FederationPeer>,
    pub federation: FederationConfig,
    pub dns_webhook_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeer {
    pub url: String,
    #[serde(default)]
    pub node_id: Option<String>,
}

/// Operator-selected operations that push state to peers synchronously rather
/// than relying on the 15 s async reconciliation loop.
#[derive(Debug, Default)]
pub struct FederationConfig {
    pub synchronous_operations: Vec<String>,
}

impl FederationConfig {
    pub fn sync_invite_redeem(&self) -> bool {
        self.synchronous_operations
            .iter()
            .any(|s| s == SYNC_OP_INVITE_REDEEM)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for op in &self.synchronous_operations {
            if op != SYNC_OP_INVITE_REDEEM {
                anyhow::bail!(
                    "hub.federation.synchronous_operations: unknown op {op:?}; known: [{SYNC_OP_INVITE_REDEEM:?}]"
                );
            }
        }
        Ok(())
    }
}

const SYNC_OP_INVITE_REDEEM: &str = "invite_redeem";

#[derive(Debug)]
pub struct EdgeConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub hub_urls: Vec<String>,
    pub public_addresses: Vec<String>,
    pub tls: Option<TlsConfig>,
    /// Number of TCP accept workers sharing `listen_addr` via `SO_REUSEPORT`
    /// on Unix. Raise to scale accept across cores under bursty load.
    pub listen_workers: usize,
}

#[derive(Debug)]
pub struct TlsConfig {
    pub cert_dir: PathBuf,
    pub acme_email: Option<String>,
    pub acme_staging: bool,
    pub http_listen_addr: String,
}

/// Operator-configured tenant allowlist entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub pq_public_key: String,
    pub name: String,
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub agent_node_ids: Vec<String>,
    #[serde(default)]
    pub direct_addresses: Vec<String>,
}

/// Flat env representation. Field names map to `TOWONEL_<UPPER>`:
/// `hub_listen_addr` reads `TOWONEL_HUB_LISTEN_ADDR`, etc. JSON-shaped
/// entries are read as raw strings and parsed afterwards.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawEnv {
    identity_key_path: Option<PathBuf>,

    hub_enabled: Option<bool>,
    hub_listen_addr: Option<String>,
    hub_health_listen_addr: Option<String>,
    hub_operator_api_key_path: Option<PathBuf>,
    hub_public_url: Option<String>,
    hub_dns_webhook_url: Option<String>,
    hub_db_driver: Option<DbDriver>,
    hub_db_dsn: Option<String>,
    hub_db_max_open_conns: Option<u32>,
    hub_db_max_idle_conns: Option<u32>,
    hub_peers: Option<String>,
    hub_sync_operations: Vec<String>,

    edge_enabled: Option<bool>,
    edge_listen_addr: Option<String>,
    edge_health_listen_addr: Option<String>,
    edge_hub_urls: Vec<String>,
    edge_public_addresses: Vec<String>,
    edge_listen_workers: Option<usize>,
    edge_tls_cert_dir: Option<PathBuf>,
    edge_tls_acme_email: Option<String>,
    edge_tls_acme_staging: Option<bool>,
    edge_tls_http_listen_addr: Option<String>,

    tenants: Option<String>,

    allow_unpinned_federation_peers: Option<bool>,
}

impl NodeConfig {
    /// Load from `TOWONEL_*` env vars. Lists are CSV; structured values
    /// (`TOWONEL_HUB_PEERS`, `TOWONEL_TENANTS`) are JSON. The README lists
    /// every knob.
    pub fn load() -> anyhow::Result<Self> {
        let raw: RawEnv = envy::prefixed("TOWONEL_").from_env()?;
        let allow_unpinned = raw.allow_unpinned_federation_peers.unwrap_or(false);
        let c = Self::from_raw(raw)?;
        c.validate(allow_unpinned)?;
        Ok(c)
    }

    fn from_raw(r: RawEnv) -> anyhow::Result<Self> {
        let tls = build_tls(&r);
        let identity = IdentityConfig {
            key_path: r
                .identity_key_path
                .ok_or_else(|| anyhow::anyhow!("TOWONEL_IDENTITY_KEY_PATH is required"))?,
        };
        let edge = EdgeConfig {
            enabled: r.edge_enabled.unwrap_or(true),
            listen_addr: r
                .edge_listen_addr
                .unwrap_or_else(|| "0.0.0.0:443".to_string()),
            health_listen_addr: r
                .edge_health_listen_addr
                .unwrap_or_else(|| "0.0.0.0:9090".to_string()),
            hub_urls: trim_entries(r.edge_hub_urls),
            public_addresses: trim_entries(r.edge_public_addresses),
            tls,
            listen_workers: r.edge_listen_workers.unwrap_or(1),
        };

        let hub = HubConfig {
            enabled: r.hub_enabled.unwrap_or(true),
            database: DatabaseConfig {
                driver: r.hub_db_driver.unwrap_or(DbDriver::Sqlite),
                dsn: r.hub_db_dsn,
                max_open_conns: r.hub_db_max_open_conns,
                max_idle_conns: r.hub_db_max_idle_conns,
            },
            listen_addr: r
                .hub_listen_addr
                .unwrap_or_else(|| "0.0.0.0:8443".to_string()),
            health_listen_addr: r
                .hub_health_listen_addr
                .unwrap_or_else(|| "0.0.0.0:9091".to_string()),
            operator_api_key_path: r
                .hub_operator_api_key_path
                .unwrap_or_else(|| PathBuf::from("operator.key")),
            public_url: r.hub_public_url,
            peers: parse_json_opt("TOWONEL_HUB_PEERS", r.hub_peers.as_deref())?.unwrap_or_default(),
            federation: FederationConfig {
                synchronous_operations: trim_entries(r.hub_sync_operations),
            },
            dns_webhook_url: r.hub_dns_webhook_url,
        };

        let tenants = parse_json_opt("TOWONEL_TENANTS", r.tenants.as_deref())?.unwrap_or_default();

        Ok(Self {
            identity,
            hub,
            edge,
            tenants,
        })
    }

    fn validate(&self, allow_unpinned: bool) -> anyhow::Result<()> {
        for peer in &self.hub.peers {
            require_https(&peer.url, "federation peer URL")?;
            match &peer.node_id {
                Some(id) if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                Some(id) => {
                    anyhow::bail!(
                        "federation peer node_id must be 64 hex chars: got {id:?} for {}",
                        peer.url
                    );
                }
                None if allow_unpinned => {
                    tracing::warn!(
                        peer = %peer.url,
                        "federation peer has no pinned node_id and TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS=true; bootstrap will trust the first /v1/health response (MITM-able)"
                    );
                }
                None => {
                    anyhow::bail!(
                        "federation peer {} has no pinned node_id — set node_id, or set TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS=true to override (not recommended)",
                        peer.url
                    );
                }
            }
        }
        for url in &self.edge.hub_urls {
            require_https(url, "hub_urls entry")?;
        }
        if let Some(url) = &self.hub.dns_webhook_url {
            require_https(url, "dns_webhook_url")?;
        }
        self.hub.federation.validate()?;
        Ok(())
    }
}

fn build_tls(r: &RawEnv) -> Option<TlsConfig> {
    let any = r.edge_tls_cert_dir.is_some()
        || r.edge_tls_acme_email.is_some()
        || r.edge_tls_acme_staging.is_some()
        || r.edge_tls_http_listen_addr.is_some();
    if !any {
        return None;
    }
    Some(TlsConfig {
        cert_dir: r
            .edge_tls_cert_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/data/certs")),
        acme_email: r.edge_tls_acme_email.clone(),
        acme_staging: r.edge_tls_acme_staging.unwrap_or(false),
        http_listen_addr: r
            .edge_tls_http_listen_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0:80".to_string()),
    })
}

fn trim_entries(v: Vec<String>) -> Vec<String> {
    v.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_json_opt<T: serde::de::DeserializeOwned>(
    key: &str,
    raw: Option<&str>,
) -> anyhow::Result<Option<T>> {
    raw.map(|s| serde_json::from_str::<T>(s).map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

fn require_https(url: &str, context: &str) -> anyhow::Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!("{context} must use https://: got {url:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_sync_invite_redeem_recognised() {
        let cfg = FederationConfig {
            synchronous_operations: vec!["invite_redeem".to_string()],
        };
        assert!(cfg.validate().is_ok());
        assert!(cfg.sync_invite_redeem());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn federation_unknown_sync_op_rejected() {
        let cfg = FederationConfig {
            synchronous_operations: vec!["delete_tenant".to_string()],
        };
        let err = cfg.validate().expect_err("unknown op must be rejected");
        assert!(err.to_string().contains("delete_tenant"));
    }

    #[test]
    fn trim_entries_normalizes_csv() {
        let got = trim_entries(vec![
            "https://a.example.eu".into(),
            " https://b.example.eu ".into(),
            String::new(),
        ]);
        assert_eq!(
            got,
            vec![
                "https://a.example.eu".to_string(),
                "https://b.example.eu".to_string(),
            ],
        );
    }
}
