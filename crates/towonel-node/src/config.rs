use std::env;
use std::path::PathBuf;
use std::str::FromStr;

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

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub driver: DbDriver,
    /// Postgres connection string (required when driver is `postgres`).
    /// Ignored for `SQLite` unless you want to override the default path
    /// (in which case pass a path or `sqlite://...` URL).
    pub dsn: Option<String>,
    /// Max open connections. Defaults: 4 for sqlite, 25 for postgres.
    pub max_open_conns: Option<u32>,
    /// Max idle connections. Defaults: 4 for sqlite, 10 for postgres.
    pub max_idle_conns: Option<u32>,
}

impl DatabaseConfig {
    /// Resolve the driver URL fed to `SeaORM`'s `Database::connect`.
    pub fn connection_url(&self) -> anyhow::Result<String> {
        match self.driver {
            DbDriver::Postgres => {
                let dsn = self.dsn.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("database.dsn is required when driver is postgres")
                })?;
                Ok(dsn.clone())
            }
            DbDriver::Sqlite => {
                let raw = self.dsn.as_deref().unwrap_or("hub.db");
                if raw.starts_with("sqlite:") {
                    Ok(raw.to_string())
                } else {
                    Ok(format!("sqlite://{raw}?mode=rwc"))
                }
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
    /// Bind address for the hub's private health + Prometheus `/metrics`
    /// listener. Kept off the public API port so `/metrics` never leaves the
    /// internal network and the `requests_total` counter isn't polluted by
    /// scrape traffic.
    pub health_listen_addr: String,
    /// Path to a file containing the operator API key. If missing, a fresh
    /// random key is generated on first boot. The key protects the invite
    /// management endpoints (create, list, revoke). Never commit this file.
    pub operator_api_key_path: PathBuf,
    /// Public URL of the hub, used as the `hub_url` embedded in invite
    /// tokens. Defaults to `https://<listen_addr>`. Operators running
    /// behind a reverse proxy should set this to the externally reachable
    /// URL so tenants can resolve it.
    pub public_url: Option<String>,
    /// Federation peers. Pinning `node_id` closes an MITM window at first
    /// contact; unpinned bootstrap is gated behind
    /// `TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS=1`.
    pub peers: Vec<FederationPeer>,
    pub federation: FederationConfig,
    /// Optional webhook URL for DNS automation. When set, the hub POSTs a
    /// JSON payload to this URL whenever the set of active hostnames changes
    /// (hostname added or removed). The operator points this at a small
    /// sidecar that calls their DNS provider's API (Cloudflare, Route53, etc).
    ///
    /// Payload: `{ "added": ["app.example.eu"], "removed": ["old.example.eu"] }`
    pub dns_webhook_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeer {
    pub url: String,
    /// 64-hex iroh node id of the peer. When set, the hub refuses to trust
    /// any other node id returned by this peer's `/v1/health`.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// Operator-selected operations that push state to peers before returning
/// the HTTP response, rather than relying on the 15 s async reconciliation
/// loop. Closes the consistency window for the named ops.
#[derive(Debug, Default)]
pub struct FederationConfig {
    /// Known values: `"invite_redeem"`. Unknown values fail at load time.
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
    /// on Unix. Raise (e.g. `num_cpus`) to scale accept across cores under
    /// bursty load. Ignored on non-Unix platforms.
    pub listen_workers: usize,
}

#[derive(Debug)]
pub struct TlsConfig {
    /// Directory for PEM cert/key pairs. ACME writes here automatically;
    /// operators can also drop user-provided certs here (named `{hostname}.crt`
    /// + `{hostname}.key`).
    pub cert_dir: PathBuf,
    /// ACME email for Let's Encrypt account registration. Required for
    /// on-demand issuance; missing email disables ACME (certs must be
    /// user-provided).
    pub acme_email: Option<String>,
    /// Use Let's Encrypt staging (for testing, avoids rate limits).
    pub acme_staging: bool,
    /// Bind address for the HTTP-01 challenge server (default ":80").
    pub http_listen_addr: String,
}

/// Operator-configured tenant allowlist entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    /// Hex-encoded tenant id (SHA-256 of the tenant's ML-DSA-65 public key).
    /// Required for hub mode, optional in edge-only mode where the edge
    /// routes by `agent_node_ids` directly.
    #[serde(default)]
    pub id: String,
    /// Base64url-encoded ML-DSA-65 public key (2606 chars). Required for hub
    /// mode; the hub verifies tenant signatures against this key. Must
    /// round-trip: `sha256(decode(pq_public_key)) == hex_decode(id)`.
    #[serde(default)]
    pub pq_public_key: String,
    /// Human-readable alias (operator-local, not part of the protocol).
    pub name: String,
    /// Hostname patterns this tenant is allowed to claim. TLS mode is not
    /// configured here — the agent publishes it via `SetHostnameTls` entries.
    pub hostnames: Vec<String>,
    /// Hex-encoded iroh `EndpointIds` of agents serving this tenant.
    #[serde(default)]
    pub agent_node_ids: Vec<String>,
    /// Optional direct socket addresses for agents (e.g. for Docker/e2e where
    /// relay discovery is unavailable). Each entry is a `"host:port"` string.
    /// When present, the edge will use these to connect without relay.
    #[serde(default)]
    pub direct_addresses: Vec<String>,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database: DatabaseConfig::default(),
            listen_addr: "0.0.0.0:8443".to_string(),
            health_listen_addr: "0.0.0.0:9091".to_string(),
            operator_api_key_path: PathBuf::from("operator.key"),
            public_url: None,
            peers: Vec::new(),
            federation: FederationConfig::default(),
            dns_webhook_url: None,
        }
    }
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0:443".to_string(),
            health_listen_addr: "0.0.0.0:9090".to_string(),
            hub_urls: Vec::new(),
            public_addresses: Vec::new(),
            tls: None,
            listen_workers: 1,
        }
    }
}

fn require_https(url: &str, context: &str) -> anyhow::Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!("{context} must use https://: got {url:?}");
    }
    Ok(())
}

impl NodeConfig {
    /// Load from `TOWONEL_*` env vars. Section separator is `__`;
    /// underscores in field names are preserved. `TOWONEL_IDENTITY__KEY_PATH`
    /// is required. Lists accept CSV or JSON; structured lists
    /// (`TOWONEL_HUB__PEERS`, `TOWONEL_TENANTS`) are JSON only. See the
    /// README for the full catalog of knobs.
    pub fn load() -> anyhow::Result<Self> {
        let key_path = env_required("TOWONEL_IDENTITY__KEY_PATH")?;

        let mut c = Self {
            identity: IdentityConfig {
                key_path: PathBuf::from(key_path),
            },
            hub: HubConfig::default(),
            edge: EdgeConfig::default(),
            tenants: Vec::new(),
        };

        apply_hub_env(&mut c.hub)?;
        apply_edge_env(&mut c.edge)?;

        if let Some(v) = env_json::<Vec<FederationPeer>>("TOWONEL_HUB__PEERS")? {
            c.hub.peers = v;
        }
        if let Some(v) = env_json::<Vec<TenantEntry>>("TOWONEL_TENANTS")? {
            c.tenants = v;
        }

        validate(&c)?;
        Ok(c)
    }
}

fn apply_hub_env(h: &mut HubConfig) -> anyhow::Result<()> {
    if let Some(v) = env_bool("TOWONEL_HUB__ENABLED")? {
        h.enabled = v;
    }
    if let Ok(v) = env::var("TOWONEL_HUB__LISTEN_ADDR") {
        h.listen_addr = v;
    }
    if let Ok(v) = env::var("TOWONEL_HUB__HEALTH_LISTEN_ADDR") {
        h.health_listen_addr = v;
    }
    if let Ok(v) = env::var("TOWONEL_HUB__OPERATOR_API_KEY_PATH") {
        h.operator_api_key_path = PathBuf::from(v);
    }
    if let Ok(v) = env::var("TOWONEL_HUB__PUBLIC_URL") {
        h.public_url = Some(v);
    }
    if let Ok(v) = env::var("TOWONEL_HUB__DNS_WEBHOOK_URL") {
        h.dns_webhook_url = Some(v);
    }

    if let Ok(v) = env::var("TOWONEL_HUB__DATABASE__DRIVER") {
        h.database.driver = match v.as_str() {
            "sqlite" => DbDriver::Sqlite,
            "postgres" => DbDriver::Postgres,
            other => {
                anyhow::bail!(
                    "TOWONEL_HUB__DATABASE__DRIVER: unknown driver {other:?} (expected sqlite|postgres)"
                );
            }
        };
    }
    if let Ok(v) = env::var("TOWONEL_HUB__DATABASE__DSN") {
        h.database.dsn = Some(v);
    }
    if let Some(v) = env_parse::<u32>("TOWONEL_HUB__DATABASE__MAX_OPEN_CONNS")? {
        h.database.max_open_conns = Some(v);
    }
    if let Some(v) = env_parse::<u32>("TOWONEL_HUB__DATABASE__MAX_IDLE_CONNS")? {
        h.database.max_idle_conns = Some(v);
    }

    if let Some(v) = env_list("TOWONEL_HUB__FEDERATION__SYNCHRONOUS_OPERATIONS")? {
        h.federation.synchronous_operations = v;
    }
    Ok(())
}

fn apply_edge_env(e: &mut EdgeConfig) -> anyhow::Result<()> {
    if let Some(v) = env_bool("TOWONEL_EDGE__ENABLED")? {
        e.enabled = v;
    }
    if let Ok(v) = env::var("TOWONEL_EDGE__LISTEN_ADDR") {
        e.listen_addr = v;
    }
    if let Ok(v) = env::var("TOWONEL_EDGE__HEALTH_LISTEN_ADDR") {
        e.health_listen_addr = v;
    }
    if let Some(v) = env_list("TOWONEL_EDGE__HUB_URLS")? {
        e.hub_urls = v;
    }
    if let Some(v) = env_list("TOWONEL_EDGE__PUBLIC_ADDRESSES")? {
        e.public_addresses = v;
    }
    if let Some(v) = env_parse::<usize>("TOWONEL_EDGE__LISTEN_WORKERS")? {
        e.listen_workers = v;
    }
    apply_tls_env(&mut e.tls)?;
    Ok(())
}

fn apply_tls_env(tls: &mut Option<TlsConfig>) -> anyhow::Result<()> {
    let cert_dir = env::var("TOWONEL_EDGE__TLS__CERT_DIR").ok();
    let acme_email = env::var("TOWONEL_EDGE__TLS__ACME_EMAIL").ok();
    let acme_staging = env_bool("TOWONEL_EDGE__TLS__ACME_STAGING")?;
    let http_listen_addr = env::var("TOWONEL_EDGE__TLS__HTTP_LISTEN_ADDR").ok();

    if cert_dir.is_none()
        && acme_email.is_none()
        && acme_staging.is_none()
        && http_listen_addr.is_none()
    {
        return Ok(());
    }

    let t = tls.get_or_insert_with(|| TlsConfig {
        cert_dir: PathBuf::from("/data/certs"),
        acme_email: None,
        acme_staging: false,
        http_listen_addr: "0.0.0.0:80".to_string(),
    });
    if let Some(v) = cert_dir {
        t.cert_dir = PathBuf::from(v);
    }
    if let Some(v) = acme_email {
        t.acme_email = Some(v);
    }
    if let Some(v) = acme_staging {
        t.acme_staging = v;
    }
    if let Some(v) = http_listen_addr {
        t.http_listen_addr = v;
    }
    Ok(())
}

fn validate(c: &NodeConfig) -> anyhow::Result<()> {
    let allow_unpinned = env::var("TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    for peer in &c.hub.peers {
        require_https(&peer.url, "federation peer URL")?;
        match &peer.node_id {
            Some(id) => {
                if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    anyhow::bail!(
                        "federation peer node_id must be 64 hex chars: got {id:?} for {}",
                        peer.url
                    );
                }
            }
            None if allow_unpinned => {
                tracing::warn!(
                    peer = %peer.url,
                    "federation peer has no pinned node_id and TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS=1; bootstrap will trust the first /v1/health response (MITM-able)"
                );
            }
            None => {
                anyhow::bail!(
                    "federation peer {} has no pinned node_id — set node_id to close the MITM window, or set TOWONEL_ALLOW_UNPINNED_FEDERATION_PEERS=1 to override (not recommended)",
                    peer.url
                );
            }
        }
    }
    for url in &c.edge.hub_urls {
        require_https(url, "hub_urls entry")?;
    }
    if let Some(url) = &c.hub.dns_webhook_url {
        require_https(url, "dns_webhook_url")?;
    }
    c.hub.federation.validate()?;
    Ok(())
}

fn env_required(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("required env var {key} is not set"))
}

fn env_bool(key: &str) -> anyhow::Result<Option<bool>> {
    env::var(key)
        .ok()
        .map(|v| parse_bool(&v).map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

fn env_parse<T: FromStr>(key: &str) -> anyhow::Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    env::var(key)
        .ok()
        .map(|v| v.parse::<T>().map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

fn env_list(key: &str) -> anyhow::Result<Option<Vec<String>>> {
    env::var(key)
        .ok()
        .map(|v| parse_list(&v).map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

fn env_json<T: serde::de::DeserializeOwned>(key: &str) -> anyhow::Result<Option<T>> {
    env::var(key)
        .ok()
        .map(|v| serde_json::from_str(&v).map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

fn parse_bool(raw: &str) -> anyhow::Result<bool> {
    match raw.trim() {
        "1" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "false" | "FALSE" | "False" => Ok(false),
        other => anyhow::bail!("expected true/false/1/0, got {other:?}"),
    }
}

fn parse_list(raw: &str) -> anyhow::Result<Vec<String>> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(Into::into);
    }
    Ok(trimmed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
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
    fn parse_list_accepts_csv() {
        let got =
            parse_list("https://a.example.eu, https://b.example.eu ,https://c.example.eu").unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], "https://a.example.eu");
    }

    #[test]
    fn parse_list_accepts_json() {
        let got = parse_list(r#"["https://a.example.eu","https://b.example.eu"]"#).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn parse_list_ignores_empty_csv_entries() {
        let got = parse_list(",a,,b,").unwrap();
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn parse_bool_accepts_common_forms() {
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("1").unwrap());
        assert!(!parse_bool("false").unwrap());
        assert!(!parse_bool("0").unwrap());
        assert!(parse_bool("nope").is_err());
    }
}
