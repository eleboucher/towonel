use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use ipnet::IpNet;
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
        _ = parsed.set_password(Some("***"));
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
    /// PROXY protocol v2 ingress. Configured via `TOWONEL_EDGE_PROXY_PROTOCOL`
    /// (bool) and `TOWONEL_EDGE_PROXY_PROTOCOL_TRUSTED` (CSV CIDRs).
    pub proxy_protocol: ProxyProtocolConfig,
}

#[derive(Debug, Clone)]
pub struct ProxyProtocolConfig {
    pub enabled: bool,
    pub trusted: Vec<IpNet>,
}

impl Default for ProxyProtocolConfig {
    // Seed `trusted` so `..Default::default()` callers don't end up with an
    // empty allowlist and a silently no-op feature.
    fn default() -> Self {
        Self {
            enabled: false,
            trusted: default_trusted_cidrs(),
        }
    }
}

impl ProxyProtocolConfig {
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.enabled && self.trusted.iter().any(|net| net.contains(&ip))
    }
}

/// RFC1918 private ranges + loopback + link-local + unique-local IPv6,
/// matching what a co-located reverse proxy (Caddy in the same docker network)
/// would normally come from.
fn default_trusted_cidrs() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

fn parse_cidr_list(raw: &str) -> anyhow::Result<Vec<IpNet>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>()
                .map_err(|e| anyhow::anyhow!("invalid CIDR {s:?}: {e}"))
        })
        .collect()
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
    /// Base directory whose subpaths supply defaults for every path-shaped
    /// env var below (identity key, hub DB, operator key, TLS cert dir,
    /// invite-hash key). Per-var env vars always win. The node Dockerfile
    /// pins this to `/data`.
    data_dir: Option<PathBuf>,

    identity_key_path: Option<PathBuf>,
    edge_invite_token: Option<String>,

    /// Hex-encoded 32-byte invite-hash key. Optional once
    /// `invite_hash_key_path` (or `data_dir`) is set — the hub then
    /// reads/generates the key on disk.
    invite_hash_key: Option<String>,
    /// File-backed fallback for [`Self::invite_hash_key`]. When unset and
    /// `data_dir` is set, defaults to `${DATA_DIR}/invite_hash.key`.
    invite_hash_key_path: Option<PathBuf>,

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
    /// Addresses (`host:port`) the hub advertises to agents/clients. When
    /// the node sits behind a reverse proxy, this is the **proxy's** public
    /// address, not the edge process's listen address — the two only match
    /// in a direct deployment. Plural because operators may publish more
    /// than one endpoint (e.g. anycast IPs, IPv4 + IPv6).
    edge_advertised_addresses: Vec<String>,
    /// Deprecated alias for `edge_advertised_addresses`. The old name was
    /// ambiguous: "public" sounded like "the edge's listen address," but
    /// it always meant "the address clients reach." Kept so existing
    /// deployments still boot; the new name surfaces a deprecation warning.
    edge_public_addresses: Vec<String>,
    edge_listen_workers: Option<usize>,
    edge_proxy_protocol: Option<bool>,
    edge_proxy_protocol_trusted: Option<String>,
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
        let RawEnv {
            data_dir,
            identity_key_path,
            edge_invite_token,
            invite_hash_key,
            invite_hash_key_path,
            hub_enabled,
            hub_listen_addr,
            hub_health_listen_addr,
            hub_operator_api_key_path,
            hub_public_url,
            hub_db_driver,
            hub_db_dsn,
            hub_db_max_open_conns,
            hub_db_max_idle_conns,
            edge_enabled,
            edge_listen_addr,
            edge_health_listen_addr,
            edge_hub_url,
            edge_hub_urls,
            edge_advertised_addresses,
            edge_public_addresses,
            edge_listen_workers,
            edge_proxy_protocol,
            edge_proxy_protocol_trusted,
            tenants,
            ..
        } = r;

        let edge_invite = edge_invite_token
            .as_deref()
            .map(|raw| {
                EdgeInviteToken::decode(raw.trim())
                    .map_err(|e| anyhow::anyhow!("invalid TOWONEL_EDGE_INVITE_TOKEN: {e}"))
            })
            .transpose()?;

        let identity_key_path =
            identity_key_path.or_else(|| data_dir.as_ref().map(|d| d.join("node.key")));

        let identity = IdentityConfig {
            source: match (&edge_invite, identity_key_path) {
                (Some(token), _) => {
                    IdentitySource::EdgeInviteSeed(zeroize::Zeroizing::new(token.node_seed))
                }
                (None, Some(path)) => IdentitySource::KeyFile(path),
                (None, None) => {
                    anyhow::bail!(
                        "identity source missing: set TOWONEL_IDENTITY_KEY_PATH, \
                         TOWONEL_DATA_DIR (defaults to ${{DATA_DIR}}/node.key), \
                         or provide a TOWONEL_EDGE_INVITE_TOKEN issued by the hub"
                    );
                }
            },
        };

        let hub_url = resolve_hub_url(edge_hub_url, edge_hub_urls, edge_invite.as_ref());

        let hub = build_hub_config(HubInputs {
            enabled: hub_enabled,
            listen_addr: hub_listen_addr,
            health_listen_addr: hub_health_listen_addr,
            operator_api_key_path: hub_operator_api_key_path,
            public_url: hub_public_url.clone(),
            db_driver: hub_db_driver,
            db_dsn: hub_db_dsn,
            db_max_open_conns: hub_db_max_open_conns,
            db_max_idle_conns: hub_db_max_idle_conns,
            invite_hash_key,
            invite_hash_key_path,
            data_dir: data_dir.as_deref(),
        })?;

        let proxy_protocol = ProxyProtocolConfig {
            enabled: edge_proxy_protocol.unwrap_or(false),
            trusted: edge_proxy_protocol_trusted
                .as_deref()
                .map(parse_cidr_list)
                .transpose()?
                .unwrap_or_else(default_trusted_cidrs),
        };

        let public_addresses = resolve_advertised_addresses(
            edge_advertised_addresses,
            edge_public_addresses,
            hub_public_url.as_deref(),
        );

        let edge = EdgeConfig {
            enabled: edge_enabled.unwrap_or(true),
            listen_addr: edge_listen_addr.unwrap_or_else(|| "0.0.0.0:443".to_string()),
            health_listen_addr: edge_health_listen_addr
                .unwrap_or_else(|| "0.0.0.0:9090".to_string()),
            hub_url,
            public_addresses,
            tls,
            listen_workers: edge_listen_workers.unwrap_or(1),
            proxy_protocol,
        };

        let tenants = parse_json_opt("TOWONEL_TENANTS", tenants.as_deref())?.unwrap_or_default();

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
    let default_cert_dir = r
        .data_dir
        .as_ref()
        .map_or_else(|| PathBuf::from("/data/certs"), |d| d.join("certs"));
    Some(TlsConfig {
        cert_dir: r.edge_tls_cert_dir.clone().unwrap_or(default_cert_dir),
        acme_email: r.edge_tls_acme_email.clone(),
        acme_staging: r.edge_tls_acme_staging.unwrap_or(false),
        http_listen_addr: r
            .edge_tls_http_listen_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0:80".to_string()),
    })
}

/// Owned slice of [`RawEnv`] consumed by [`build_hub_config`]. Splitting this
/// out lets `from_raw` destructure `RawEnv` once and avoids partial-move
/// errors when later code paths consume neighbouring fields.
struct HubInputs<'a> {
    enabled: Option<bool>,
    listen_addr: Option<String>,
    health_listen_addr: Option<String>,
    operator_api_key_path: Option<PathBuf>,
    public_url: Option<String>,
    db_driver: Option<DbDriver>,
    db_dsn: Option<String>,
    db_max_open_conns: Option<u32>,
    db_max_idle_conns: Option<u32>,
    invite_hash_key: Option<String>,
    invite_hash_key_path: Option<PathBuf>,
    data_dir: Option<&'a Path>,
}

/// Assemble [`HubConfig`], applying `data_dir` cascade defaults to every
/// path-shaped hub setting and loading (or generating) the invite-hash key.
/// Pulled out of [`NodeConfig::from_raw`] both to keep that function under
/// the clippy `too_many_lines` limit and because hub setup is independently
/// testable from edge setup.
fn build_hub_config(inputs: HubInputs<'_>) -> anyhow::Result<HubConfig> {
    let HubInputs {
        enabled,
        listen_addr,
        health_listen_addr,
        operator_api_key_path,
        public_url,
        db_driver,
        db_dsn,
        db_max_open_conns,
        db_max_idle_conns,
        invite_hash_key,
        invite_hash_key_path,
        data_dir,
    } = inputs;

    let hub_enabled = enabled.unwrap_or(true);
    let driver = db_driver.unwrap_or(DbDriver::Sqlite);
    let dsn = db_dsn.or_else(|| match driver {
        DbDriver::Sqlite => data_dir.map(|d| d.join("hub.db").to_string_lossy().into_owned()),
        DbDriver::Postgres => None,
    });
    let operator_api_key_path = operator_api_key_path
        .or_else(|| data_dir.map(|d| d.join("operator.key")))
        .unwrap_or_else(|| PathBuf::from("operator.key"));
    let invite_hash_key_path =
        invite_hash_key_path.or_else(|| data_dir.map(|d| d.join("invite_hash.key")));

    // Validate the invite-hash key upfront so a missing or malformed value
    // fails startup loudly, before any DB work. Edge-only nodes don't need
    // it (they never verify invite secrets).
    let invite_hash_key = if hub_enabled {
        Some(std::sync::Arc::new(
            crate::hub::load_or_generate_invite_hash_key(
                invite_hash_key.as_deref(),
                invite_hash_key_path.as_deref(),
            )?,
        ))
    } else {
        None
    };

    Ok(HubConfig {
        enabled: hub_enabled,
        database: DatabaseConfig {
            driver,
            dsn,
            max_open_conns: db_max_open_conns,
            max_idle_conns: db_max_idle_conns,
        },
        listen_addr: listen_addr.unwrap_or_else(|| "0.0.0.0:8443".to_string()),
        health_listen_addr: health_listen_addr.unwrap_or_else(|| "0.0.0.0:9091".to_string()),
        operator_api_key_path,
        public_url,
        invite_hash_key,
    })
}

/// Resolve the hub URL the edge uses to reach the hub. Honors the deprecated
/// `TOWONEL_EDGE_HUB_URLS` alias with a one-time warning, then falls back to
/// the URL embedded in the edge invite token if present.
fn resolve_hub_url(
    primary: Option<String>,
    deprecated_alias: Option<String>,
    edge_invite: Option<&EdgeInviteToken>,
) -> Option<String> {
    let explicit = primary
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let alias = deprecated_alias
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())?;
            tracing::warn!("TOWONEL_EDGE_HUB_URLS is deprecated; rename to TOWONEL_EDGE_HUB_URL");
            Some(alias)
        });
    explicit.or_else(|| edge_invite.map(|t| t.hub_url.trim_end_matches('/').to_string()))
}

/// Resolve the addresses the hub advertises to agents and clients.
///
/// Resolution order:
/// 1. `TOWONEL_EDGE_ADVERTISED_ADDRESSES` (canonical name) if non-empty.
/// 2. `TOWONEL_EDGE_PUBLIC_ADDRESSES` (deprecated alias) with a one-time
///    warning so legacy compose files keep booting.
/// 3. `<host>:443` derived from `TOWONEL_HUB_PUBLIC_URL` host. Covers the
///    common single-DNS deployment where the hub and the public edge
///    endpoint share a hostname; multi-DNS operators set the addresses
///    explicitly.
///
/// The `:443` derivation assumes the public endpoint is on the standard
/// HTTPS port. Operators whose public endpoint is on a different port
/// (e.g. when the reverse proxy itself listens elsewhere) must set the
/// addresses explicitly.
fn resolve_advertised_addresses(
    advertised: Vec<String>,
    deprecated_public: Vec<String>,
    hub_public_url: Option<&str>,
) -> Vec<String> {
    let primary = trim_entries(advertised);
    if !primary.is_empty() {
        return primary;
    }
    let alias = trim_entries(deprecated_public);
    if !alias.is_empty() {
        tracing::warn!(
            "TOWONEL_EDGE_PUBLIC_ADDRESSES is deprecated; rename to \
             TOWONEL_EDGE_ADVERTISED_ADDRESSES — the address agents/clients \
             reach (typically your reverse proxy), not the edge's listen address"
        );
        return alias;
    }
    let Some(url_str) = hub_public_url else {
        return Vec::new();
    };
    let Ok(url) = url::Url::parse(url_str) else {
        return Vec::new();
    };
    let Some(host) = url.host_str() else {
        return Vec::new();
    };
    vec![format!("{host}:443")]
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
    fn proxy_protocol_disabled_is_never_trusted() {
        let cfg = ProxyProtocolConfig {
            enabled: false,
            trusted: default_trusted_cidrs(),
        };
        assert!(!cfg.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(!cfg.is_trusted("172.21.0.5".parse().unwrap()));
    }

    #[test]
    fn proxy_protocol_default_trusts_private_and_loopback() {
        let cfg = ProxyProtocolConfig {
            enabled: true,
            trusted: default_trusted_cidrs(),
        };
        assert!(cfg.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(cfg.is_trusted("10.0.0.5".parse().unwrap()));
        assert!(cfg.is_trusted("172.21.0.5".parse().unwrap()));
        assert!(cfg.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(cfg.is_trusted("::1".parse().unwrap()));
        assert!(!cfg.is_trusted("8.8.8.8".parse().unwrap()));
        assert!(!cfg.is_trusted("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn proxy_protocol_custom_cidr_list_overrides_default() {
        let cfg = ProxyProtocolConfig {
            enabled: true,
            trusted: parse_cidr_list("10.0.0.0/24, 192.0.2.5/32").unwrap(),
        };
        assert!(cfg.is_trusted("10.0.0.7".parse().unwrap()));
        assert!(cfg.is_trusted("192.0.2.5".parse().unwrap()));
        assert!(!cfg.is_trusted("10.0.1.1".parse().unwrap()));
        assert!(!cfg.is_trusted("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_list_rejects_garbage() {
        parse_cidr_list("not-a-cidr").unwrap_err();
    }

    // `default_trusted_cidrs` filter_maps `.parse().ok()`, which would silently
    // drop a typo'd literal. Pinning the count guards against that.
    #[test]
    fn default_trusted_cidrs_parses_every_literal() {
        assert_eq!(default_trusted_cidrs().len(), 8);
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

    #[test]
    fn resolve_advertised_uses_canonical_when_set() {
        let got = resolve_advertised_addresses(
            vec!["tunnel.example.com:443".into()],
            vec!["legacy.example.com:443".into()],
            Some("https://hub.example.com"),
        );
        assert_eq!(got, vec!["tunnel.example.com:443".to_string()]);
    }

    #[test]
    fn resolve_advertised_falls_back_to_deprecated_alias() {
        let got = resolve_advertised_addresses(
            Vec::new(),
            vec!["legacy.example.com:443".into()],
            Some("https://hub.example.com"),
        );
        // Deprecated alias is honored (deployments don't break on upgrade) but
        // emits a warning; the derived hub-url fallback is not used because
        // the alias took precedence.
        assert_eq!(got, vec!["legacy.example.com:443".to_string()]);
    }

    #[test]
    fn resolve_advertised_falls_back_to_hub_url_host() {
        let got =
            resolve_advertised_addresses(Vec::new(), Vec::new(), Some("https://hub.example.com"));
        assert_eq!(got, vec!["hub.example.com:443".to_string()]);
    }

    #[test]
    fn resolve_advertised_strips_url_port_and_path() {
        let got = resolve_advertised_addresses(
            Vec::new(),
            Vec::new(),
            Some("https://hub.example.com:8443/v1"),
        );
        assert_eq!(got, vec!["hub.example.com:443".to_string()]);
    }

    #[test]
    fn resolve_advertised_empty_when_no_hub_url() {
        let got = resolve_advertised_addresses(Vec::new(), Vec::new(), None);
        assert!(got.is_empty());
    }

    #[test]
    fn resolve_advertised_empty_on_unparsable_hub_url() {
        let got = resolve_advertised_addresses(Vec::new(), Vec::new(), Some("not-a-url"));
        assert!(got.is_empty());
    }

    fn unique_data_dir(label: &str) -> PathBuf {
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).expect("rng");
        let mut p = std::env::temp_dir();
        p.push(format!(
            "towonel-cfg-{label}-{}-{}",
            std::process::id(),
            hex::encode(rand),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn base_raw_env(invite_hex: &str) -> RawEnv {
        RawEnv {
            invite_hash_key: Some(invite_hex.into()),
            ..RawEnv::default()
        }
    }

    #[test]
    fn data_dir_cascades_into_path_defaults() {
        let dir = unique_data_dir("cascade");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            edge_tls_acme_email: Some("ops@example.com".into()),
            ..base_raw_env(&"11".repeat(32))
        })
        .unwrap();

        match cfg.identity.source {
            IdentitySource::KeyFile(p) => assert_eq!(p, dir.join("node.key")),
            IdentitySource::EdgeInviteSeed(_) => panic!("expected KeyFile"),
        }
        assert_eq!(
            cfg.hub.database.dsn.as_deref(),
            Some(dir.join("hub.db").to_string_lossy().as_ref()),
        );
        assert_eq!(cfg.hub.operator_api_key_path, dir.join("operator.key"));
        let tls = cfg.edge.tls.expect("TLS expected when acme_email set");
        assert_eq!(tls.cert_dir, dir.join("certs"));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn explicit_paths_override_data_dir_cascade() {
        let dir = unique_data_dir("override");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            identity_key_path: Some(PathBuf::from("/custom/node.key")),
            hub_db_dsn: Some("/custom/hub.db".into()),
            hub_operator_api_key_path: Some(PathBuf::from("/custom/operator.key")),
            edge_tls_cert_dir: Some(PathBuf::from("/custom/certs")),
            edge_tls_acme_email: Some("ops@example.com".into()),
            ..base_raw_env(&"22".repeat(32))
        })
        .unwrap();

        match cfg.identity.source {
            IdentitySource::KeyFile(p) => assert_eq!(p, PathBuf::from("/custom/node.key")),
            IdentitySource::EdgeInviteSeed(_) => panic!("expected KeyFile"),
        }
        assert_eq!(cfg.hub.database.dsn.as_deref(), Some("/custom/hub.db"));
        assert_eq!(
            cfg.hub.operator_api_key_path,
            PathBuf::from("/custom/operator.key")
        );
        let tls = cfg.edge.tls.unwrap();
        assert_eq!(tls.cert_dir, PathBuf::from("/custom/certs"));
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn data_dir_does_not_synthesize_postgres_dsn() {
        let dir = unique_data_dir("pg");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            hub_db_driver: Some(DbDriver::Postgres),
            ..base_raw_env(&"33".repeat(32))
        })
        .unwrap();
        assert!(
            cfg.hub.database.dsn.is_none(),
            "postgres DSN must not be derived from DATA_DIR"
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn missing_identity_without_data_dir_errors_with_helpful_message() {
        let err = NodeConfig::from_raw(base_raw_env(&"44".repeat(32))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("TOWONEL_IDENTITY_KEY_PATH"), "got: {msg}");
        assert!(msg.contains("TOWONEL_DATA_DIR"), "got: {msg}");
    }

    #[test]
    fn data_dir_unset_preserves_legacy_defaults() {
        let cfg = NodeConfig::from_raw(RawEnv {
            identity_key_path: Some(PathBuf::from("/legacy/node.key")),
            ..base_raw_env(&"55".repeat(32))
        })
        .unwrap();
        assert!(
            cfg.hub.database.dsn.is_none(),
            "sqlite DSN defaults stay None"
        );
        assert_eq!(
            cfg.hub.operator_api_key_path,
            PathBuf::from("operator.key"),
            "operator key path cwd-relative when DATA_DIR unset"
        );
        assert!(cfg.edge.tls.is_none(), "TLS stays off without TLS envs");
    }

    #[test]
    fn explicit_invite_hash_key_path_overrides_data_dir_cascade() {
        let dir = unique_data_dir("ihk-override");
        let explicit = dir.join("custom-subdir").join("override.key");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            invite_hash_key_path: Some(explicit.clone()),
            ..RawEnv::default()
        })
        .unwrap();

        assert!(cfg.hub.invite_hash_key.is_some());
        assert!(
            explicit.exists(),
            "explicit invite-hash-key path must be used (not ${{DATA_DIR}}/invite_hash.key)"
        );
        assert!(
            !dir.join("invite_hash.key").exists(),
            "data_dir default must not be written when explicit path is set"
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn data_dir_cascades_invite_hash_key_path_when_env_unset() {
        let dir = unique_data_dir("ihk");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            ..RawEnv::default()
        })
        .unwrap();
        // hub_enabled defaults to true, so the invite hash key was resolved
        // via the file fallback path under data_dir.
        assert!(cfg.hub.invite_hash_key.is_some());
        let path = dir.join("invite_hash.key");
        assert!(
            path.exists(),
            "invite-hash key file should be generated at ${{DATA_DIR}}/invite_hash.key"
        );
        drop(std::fs::remove_dir_all(&dir));
    }
}
