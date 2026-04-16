use std::path::PathBuf;

use serde::Deserialize;

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
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
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
    /// Peer hubs for federation (option A — bidirectional HTTPS replication).
    /// Each peer's iroh node_id authenticates inbound federation pushes; its
    /// URL is where this hub pushes its own state.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Optional webhook URL for DNS automation. When set, the hub POSTs a
    /// JSON payload to this URL whenever the set of active hostnames changes
    /// (hostname added or removed). The operator points this at a small
    /// sidecar that calls their DNS provider's API (Cloudflare, Route53, etc).
    ///
    /// Payload: `{ "added": ["app.example.eu"], "removed": ["old.example.eu"] }`
    #[serde(default)]
    pub dns_webhook_url: Option<String>,
}

/// A federation peer: a remote hub that mirrors this hub's state.
///
/// The peer's iroh `node_id` is **not** configured by the operator — the
/// hub discovers it on boot by querying the peer's `GET /v1/health`. This
/// turns peering into a one-line config: just the URL. If the peer's
/// node_id later changes (key rotation), federation rejects and the
/// operator gets a clear error.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Base URL of the peer hub (e.g. `"https://hub-b.example.eu:8443"`).
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct EdgeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_edge_listen")]
    pub listen_addr: String,
    #[serde(default = "default_health_listen")]
    pub health_listen_addr: String,
    #[serde(default)]
    pub hub_url: Option<String>,
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
    /// Hex-encoded iroh EndpointIds of agents serving this tenant.
    #[serde(default)]
    pub agent_node_ids: Vec<String>,
    /// Optional direct socket addresses for agents (e.g. for Docker/e2e where
    /// relay discovery is unavailable). Each entry is a `"host:port"` string.
    /// When present, the edge will use these to connect without relay.
    #[serde(default)]
    pub direct_addresses: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_db_path() -> PathBuf {
    PathBuf::from("hub.db")
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
            db_path: default_db_path(),
            listen_addr: default_hub_listen(),
            operator_api_key_path: default_operator_key_path(),
            public_url: None,
            peers: Vec::new(),
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
            hub_url: None,
            public_addresses: Vec::new(),
            tls: None,
        }
    }
}

impl NodeConfig {
    /// Load config from TOML, then layer `TURBO_*` env-var overrides on
    /// top. Section/field separator in env-var names is `__` (double
    /// underscore), so single-underscore field names like `listen_addr`
    /// stay readable. Examples:
    ///
    /// ```text
    /// TURBO_HUB__LISTEN_ADDR=0.0.0.0:8443
    /// TURBO_HUB__OPERATOR_API_KEY_PATH=/run/secrets/operator.key
    /// TURBO_HUB__PEERS='[{"url":"https://hub-b.example.eu:8443"}]'
    /// TURBO_EDGE__HUB_URL=https://hub-a.example.eu:8443
    /// TURBO_IDENTITY__KEY_PATH=/var/lib/turbo-tunnel/node.key
    /// ```
    ///
    /// Lists (`peers`, `tenants`) take JSON in a single env var. Scalar
    /// fields take their natural string form.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        use figment::Figment;
        use figment::providers::{Env, Format, Toml};
        let json_keys = ["edge.public_addresses", "hub.peers", "tenants"];
        let mut config: Self = Figment::new()
            .merge(Toml::file(path))
            .merge(
                Env::prefixed("TURBO_")
                    .split("__")
                    .filter(move |key| !json_keys.contains(&key.as_str())),
            )
            .extract()
            .map_err(|e| anyhow::anyhow!("failed to load config: {e}"))?;

        if let Ok(v) = std::env::var("TURBO_EDGE__PUBLIC_ADDRESSES") {
            config.edge.public_addresses = serde_json::from_str(&v)?;
        }
        if let Ok(v) = std::env::var("TURBO_HUB__PEERS") {
            config.hub.peers = serde_json::from_str(&v)?;
        }

        for peer in &config.hub.peers {
            if !peer.url.starts_with("https://") {
                anyhow::bail!("federation peer URL must use https://: got {:?}", peer.url);
            }
        }

        if let Some(ref url) = config.hub.dns_webhook_url
            && !url.starts_with("https://")
        {
            anyhow::bail!("dns_webhook_url must use https://: got {:?}", url);
        }

        Ok(config)
    }
}
