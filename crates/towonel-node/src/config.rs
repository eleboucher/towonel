use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use towonel_common::invite::EdgeInviteToken;

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
pub enum IdentitySource {
    KeyFile(PathBuf),
    /// Seed extracted from `TOWONEL_EDGE_INVITE_TOKEN`. Wrapped in
    /// [`zeroize::Zeroizing`] so the plaintext bytes are wiped when the
    /// config is dropped.
    EdgeInviteSeed(zeroize::Zeroizing<[u8; 32]>),
}

#[derive(Debug)]
pub struct IdentityConfig {
    pub source: IdentitySource,
}

impl IdentityConfig {
    pub async fn load_secret_key_async(&self) -> anyhow::Result<iroh::SecretKey> {
        match &self.source {
            IdentitySource::KeyFile(path) => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    towonel_common::identity::load_or_generate_secret_key(&path)
                })
                .await
                .context("identity-load task panicked")?
            }
            IdentitySource::EdgeInviteSeed(seed) => Ok(iroh::SecretKey::from_bytes(seed)),
        }
    }
}

#[derive(Debug)]
pub struct HubConfig {
    pub enabled: bool,
    pub database: DatabaseConfig,
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub operator_api_key_path: PathBuf,
    pub public_url: Option<String>,
    /// Keyed-hash key for invite secrets. Loaded from
    /// [`crate::hub::INVITE_HASH_KEY_ENV`] during `NodeConfig::load` so a
    /// missing/invalid value fails startup before DB migrations run.
    /// `Arc` so downstream `HubParams` can cheaply share it without re-reading env.
    pub invite_hash_key: Option<std::sync::Arc<towonel_common::invite::InviteHashKey>>,
}

#[derive(Debug)]
pub struct EdgeConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub hub_url: Option<String>,
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
    edge_invite_token: Option<String>,

    hub_enabled: Option<bool>,
    hub_listen_addr: Option<String>,
    hub_health_listen_addr: Option<String>,
    hub_operator_api_key_path: Option<PathBuf>,
    hub_public_url: Option<String>,
    hub_db_driver: Option<DbDriver>,
    hub_db_dsn: Option<String>,
    hub_db_max_open_conns: Option<u32>,
    hub_db_max_idle_conns: Option<u32>,

    edge_enabled: Option<bool>,
    edge_listen_addr: Option<String>,
    edge_health_listen_addr: Option<String>,
    edge_hub_url: Option<String>,
    /// Deprecated alias for `edge_hub_url`; kept so existing deployments
    /// still boot. Prefer `TOWONEL_EDGE_HUB_URL` (no `S`).
    edge_hub_urls: Option<String>,
    edge_public_addresses: Vec<String>,
    edge_listen_workers: Option<usize>,
    edge_tls_cert_dir: Option<PathBuf>,
    edge_tls_acme_email: Option<String>,
    edge_tls_acme_staging: Option<bool>,
    edge_tls_http_listen_addr: Option<String>,

    tenants: Option<String>,
}

impl NodeConfig {
    /// Load from `TOWONEL_*` env vars. Lists are CSV; structured values
    /// (`TOWONEL_TENANTS`) are JSON. The README lists every knob.
    pub fn load() -> anyhow::Result<Self> {
        let raw: RawEnv = envy::prefixed("TOWONEL_").from_env()?;
        let c = Self::from_raw(raw)?;
        c.validate()?;
        Ok(c)
    }

    fn from_raw(r: RawEnv) -> anyhow::Result<Self> {
        let tls = build_tls(&r);

        let edge_invite = r
            .edge_invite_token
            .as_deref()
            .map(|raw| {
                EdgeInviteToken::decode(raw.trim())
                    .map_err(|e| anyhow::anyhow!("invalid TOWONEL_EDGE_INVITE_TOKEN: {e}"))
            })
            .transpose()?;

        let identity = IdentityConfig {
            source: match (&edge_invite, r.identity_key_path) {
                (Some(token), _) => {
                    IdentitySource::EdgeInviteSeed(zeroize::Zeroizing::new(token.node_seed))
                }
                (None, Some(path)) => IdentitySource::KeyFile(path),
                (None, None) => {
                    anyhow::bail!(
                        "identity source missing: set TOWONEL_IDENTITY_KEY_PATH, \
                         or provide a TOWONEL_EDGE_INVITE_TOKEN issued by the hub"
                    );
                }
            },
        };

        let hub_url_explicit = r
            .edge_hub_url
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let alias = r
                    .edge_hub_urls
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())?;
                tracing::warn!(
                    "TOWONEL_EDGE_HUB_URLS is deprecated; rename to TOWONEL_EDGE_HUB_URL"
                );
                Some(alias)
            });
        let hub_url = hub_url_explicit.or_else(|| {
            edge_invite
                .as_ref()
                .map(|t| t.hub_url.trim_end_matches('/').to_string())
        });

        let edge = EdgeConfig {
            enabled: r.edge_enabled.unwrap_or(true),
            listen_addr: r
                .edge_listen_addr
                .unwrap_or_else(|| "0.0.0.0:443".to_string()),
            health_listen_addr: r
                .edge_health_listen_addr
                .unwrap_or_else(|| "0.0.0.0:9090".to_string()),
            hub_url,
            public_addresses: trim_entries(r.edge_public_addresses),
            tls,
            listen_workers: r.edge_listen_workers.unwrap_or(1),
        };

        let hub_enabled = r.hub_enabled.unwrap_or(true);
        // Validate the invite-hash key upfront so a missing or malformed env
        // var fails startup loudly, before any DB work. Edge-only nodes don't
        // need it (they never verify invite secrets).
        let invite_hash_key = if hub_enabled {
            Some(std::sync::Arc::new(crate::hub::load_invite_hash_key()?))
        } else {
            None
        };

        let hub = HubConfig {
            enabled: hub_enabled,
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
            invite_hash_key,
        };

        let tenants = parse_json_opt("TOWONEL_TENANTS", r.tenants.as_deref())?.unwrap_or_default();

        Ok(Self {
            identity,
            hub,
            edge,
            tenants,
        })
    }

    fn validate(&self) -> anyhow::Result<()> {
        if let Some(url) = &self.edge.hub_url {
            require_https(url, "hub_url")?;
        }
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
