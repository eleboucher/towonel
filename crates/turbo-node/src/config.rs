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

/// Database section of the hub config.
///
/// Maps to the `[hub.database]` TOML table and the `TURBO_HUB__DATABASE__*`
/// env vars. The `dsn` is required when `driver = "postgres"`; for `SQLite`
/// it defaults to a local `hub.db` file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DatabaseConfig {
    #[serde(default = "default_driver")]
    pub driver: DbDriver,
    /// Postgres connection string (required when driver is `postgres`).
    /// Ignored for `SQLite` unless you want to override the default path
    /// (in which case pass a path or `sqlite://...` URL).
    #[serde(default)]
    pub dsn: Option<String>,
    /// Max open connections. Defaults: 4 for sqlite, 25 for postgres.
    #[serde(default)]
    pub max_open_conns: Option<u32>,
    /// Max idle connections. Defaults: 4 for sqlite, 10 for postgres.
    #[serde(default)]
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
            driver: default_driver(),
            dsn: None,
            max_open_conns: None,
            max_idle_conns: None,
        }
    }
}

const fn default_driver() -> DbDriver {
    DbDriver::Sqlite
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

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub identity: IdentityConfig,
    #[serde(default)]
    pub hub: HubConfig,
    #[serde(default)]
    pub edge: EdgeConfig,
    #[serde(default)]
    pub tenants: Vec<TenantEntry>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    /// Path to the node's Ed25519 private key file.
    pub key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct HubConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default = "default_hub_listen")]
    pub listen_addr: String,
    /// Path to a file containing the operator API key. If missing, a fresh
    /// random key is generated on first boot. The key protects the invite
    /// management endpoints (create, list, revoke). Never commit this file.
    #[serde(default = "default_operator_key_path")]
    pub operator_api_key_path: PathBuf,
    /// Public URL of the hub, used as the `hub_url` embedded in invite
    /// tokens. Defaults to `https://<listen_addr>`. Operators running
    /// behind a reverse proxy should set this to the externally reachable
    /// URL so tenants can resolve it.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Peer hub URLs for federation (option A — bidirectional HTTPS
    /// replication). Each peer's iroh `node_id` is discovered at boot by
    /// querying `GET /v1/health`; the URL is where this hub pushes its own
    /// state. TOML: `peer_urls = ["https://hub-b.example.eu:8443"]`.
    /// Env: `TURBO_HUB__PEER_URLS=https://a,https://b` (CSV or JSON).
    #[serde(default)]
    pub peer_urls: Vec<String>,
    #[serde(default)]
    pub federation: FederationConfig,
    /// Optional webhook URL for DNS automation. When set, the hub POSTs a
    /// JSON payload to this URL whenever the set of active hostnames changes
    /// (hostname added or removed). The operator points this at a small
    /// sidecar that calls their DNS provider's API (Cloudflare, Route53, etc).
    ///
    /// Payload: `{ "added": ["app.example.eu"], "removed": ["old.example.eu"] }`
    #[serde(default)]
    pub dns_webhook_url: Option<String>,
}

/// Operator-selected operations that push state to peers before returning
/// the HTTP response, rather than relying on the 15 s async reconciliation
/// loop. Closes the consistency window for the named ops.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// Known values: `"invite_redeem"`. Unknown values fail at load time.
    #[serde(default)]
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

/// Edge-mode settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_edge_listen")]
    pub listen_addr: String,
    #[serde(default = "default_health_listen")]
    pub health_listen_addr: String,
    #[serde(default)]
    pub hub_urls: Vec<String>,
    #[serde(default)]
    pub public_addresses: Vec<String>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Directory for PEM cert/key pairs. ACME writes here automatically;
    /// operators can also drop user-provided certs here (named `{hostname}.crt`
    /// + `{hostname}.key`).
    #[serde(default = "default_cert_dir")]
    pub cert_dir: std::path::PathBuf,
    /// ACME email for Let's Encrypt account registration. Required for
    /// on-demand issuance; missing email disables ACME (certs must be
    /// user-provided).
    pub acme_email: Option<String>,
    /// Use Let's Encrypt staging (for testing, avoids rate limits).
    #[serde(default)]
    pub acme_staging: bool,
    /// Bind address for the HTTP-01 challenge server (default ":80").
    #[serde(default = "default_http_listen")]
    pub http_listen_addr: String,
}

fn default_cert_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/data/certs")
}

fn default_http_listen() -> String {
    "0.0.0.0:80".to_string()
}

/// Operator-configured tenant allowlist entry.
#[derive(Debug, Deserialize)]
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

const fn default_true() -> bool {
    true
}

fn default_hub_listen() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_edge_listen() -> String {
    "0.0.0.0:443".to_string()
}

fn default_health_listen() -> String {
    "0.0.0.0:9090".to_string()
}

fn default_operator_key_path() -> PathBuf {
    PathBuf::from("operator.key")
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database: DatabaseConfig::default(),
            listen_addr: default_hub_listen(),
            operator_api_key_path: default_operator_key_path(),
            public_url: None,
            peer_urls: Vec::new(),
            federation: FederationConfig::default(),
            dns_webhook_url: None,
        }
    }
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: default_edge_listen(),
            health_listen_addr: default_health_listen(),
            hub_urls: Vec::new(),
            public_addresses: Vec::new(),
            tls: None,
        }
    }
}

type StringListSetter = fn(&mut NodeConfig, Vec<String>);

/// String-list env vars that figment can't natively parse because the
/// prefixed-env provider treats every value as a scalar. Each entry names
/// both the env var and where to assign the result on [`NodeConfig`].
const STRING_LIST_ENVS: &[(&str, StringListSetter)] = &[
    ("TURBO_EDGE__PUBLIC_ADDRESSES", |c, v| {
        c.edge.public_addresses = v;
    }),
    ("TURBO_EDGE__HUB_URLS", |c, v| c.edge.hub_urls = v),
    ("TURBO_HUB__PEER_URLS", |c, v| c.hub.peer_urls = v),
];

/// Parse a list-valued env var. Accepts JSON (`["a","b"]`) for backwards
/// compat and CSV (`a,b,c`) for Kubernetes-friendly YAML. Empty strings and
/// whitespace around commas are ignored.
fn parse_list_env(value: &str) -> anyhow::Result<Vec<String>> {
    let trimmed = value.trim();
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

fn require_https(url: &str, context: &str) -> anyhow::Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!("{context} must use https://: got {url:?}");
    }
    Ok(())
}

impl NodeConfig {
    /// Load config from TOML (optional — missing file is fine for env-only
    /// deployments like Kubernetes), then layer `TURBO_*` env-var overrides
    /// on top. Section/field separator is `__` so single-underscore field
    /// names like `listen_addr` stay readable:
    ///
    /// ```text
    /// TURBO_IDENTITY__KEY_PATH=/var/lib/turbo-tunnel/node.key
    /// TURBO_HUB__LISTEN_ADDR=0.0.0.0:8443
    /// TURBO_HUB__DATABASE__DRIVER=postgres
    /// TURBO_HUB__DATABASE__DSN=postgresql://...
    /// # String lists: CSV (preferred in K8s) or JSON.
    /// TURBO_HUB__PEER_URLS=https://hub-b.example.eu:8443,https://hub-c.example.eu:8443
    /// TURBO_EDGE__HUB_URLS=https://hub-a.example.eu:8443
    /// # Complex structured lists: JSON only.
    /// TURBO_TENANTS='[{"name":"alice","hostnames":["app.alice.test"],...}]'
    /// ```
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        use figment::Figment;
        use figment::providers::{Env, Format, Toml};

        let list_env_names: Vec<&str> = STRING_LIST_ENVS.iter().map(|(name, _)| *name).collect();
        let figment_filter_keys: Vec<String> = list_env_names
            .iter()
            .chain(&["TURBO_TENANTS"])
            .map(|name| {
                name.trim_start_matches("TURBO_")
                    .to_lowercase()
                    .replace("__", ".")
            })
            .collect();

        let mut config: Self = Figment::new()
            .merge(Toml::file(path))
            .merge(
                Env::prefixed("TURBO_")
                    .split("__")
                    .filter(move |key| !figment_filter_keys.contains(&key.to_string())),
            )
            .extract()
            .map_err(|e| anyhow::anyhow!("failed to load config: {e}"))?;

        for (name, setter) in STRING_LIST_ENVS {
            if let Ok(v) = std::env::var(name) {
                setter(&mut config, parse_list_env(&v)?);
            }
        }
        if let Ok(v) = std::env::var("TURBO_TENANTS") {
            config.tenants = serde_json::from_str(&v)?;
        }

        for url in &config.hub.peer_urls {
            require_https(url, "federation peer URL")?;
        }
        for url in &config.edge.hub_urls {
            require_https(url, "hub_urls entry")?;
        }
        if let Some(url) = &config.hub.dns_webhook_url {
            require_https(url, "dns_webhook_url")?;
        }

        config.hub.federation.validate()?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = r#"
        [identity]
        key_path = "node.key"
    "#;

    #[test]
    #[allow(clippy::expect_used)]
    fn hub_urls_array_loads() {
        let toml_str = format!(
            r#"{IDENTITY}
            [edge]
            hub_urls = ["https://hub-a.example.eu:8443", "https://hub-b.example.eu:8443"]
            "#
        );
        let config: NodeConfig =
            toml::from_str(&toml_str).expect("valid hub_urls array should parse");
        assert_eq!(
            config.edge.hub_urls,
            vec![
                "https://hub-a.example.eu:8443".to_string(),
                "https://hub-b.example.eu:8443".to_string(),
            ]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_hub_url_scalar_is_rejected() {
        let toml_str = format!(
            r#"{IDENTITY}
            [edge]
            hub_url = "https://legacy.example.eu:8443"
            "#
        );
        let err =
            toml::from_str::<NodeConfig>(&toml_str).expect_err("scalar hub_url must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("hub_url"),
            "error should name the offending field, got: {msg}"
        );
    }

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
    #[allow(clippy::expect_used)]
    fn parse_list_env_accepts_csv() {
        let out =
            parse_list_env("https://a.example.eu, https://b.example.eu , https://c.example.eu")
                .expect("csv parses");
        assert_eq!(
            out,
            vec![
                "https://a.example.eu".to_string(),
                "https://b.example.eu".to_string(),
                "https://c.example.eu".to_string(),
            ]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_list_env_accepts_json() {
        let out = parse_list_env(r#"["https://a.example.eu","https://b.example.eu"]"#)
            .expect("json parses");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "https://a.example.eu");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_list_env_ignores_empty_csv_entries() {
        let out = parse_list_env(",a,,b,").expect("csv parses");
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn parse_list_env_empty_string_is_empty_list() {
        assert!(parse_list_env("").unwrap_or_default().is_empty());
    }
}
