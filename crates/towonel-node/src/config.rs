use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use ipnet::IpNet;
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
        _ = parsed.set_password(Some("***"));
    }
    // libpq DSNs also accept the password as a query param (?password=,
    // ?sslpassword=); scrub those too.
    if parsed.query().is_some() {
        const SECRET_QUERY_KEYS: &[&str] = &["password", "sslpassword"];
        let scrubbed: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                let value = if SECRET_QUERY_KEYS.iter().any(|s| k.eq_ignore_ascii_case(s)) {
                    "***".to_string()
                } else {
                    v.into_owned()
                };
                (k.into_owned(), value)
            })
            .collect();
        let mut serializer = parsed.query_pairs_mut();
        serializer.clear();
        serializer.extend_pairs(scrubbed);
        drop(serializer);
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
    pub inline_hex: Option<String>,
    pub key_path: Option<PathBuf>,
}

impl IdentityConfig {
    pub async fn load_secret_key_async(&self) -> anyhow::Result<iroh::SecretKey> {
        if let Some(hex) = self
            .inline_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Some(p) = self.key_path.as_deref()
                && p.exists()
            {
                let on_disk = std::fs::read_to_string(p).map_err(|e| {
                    anyhow::anyhow!(
                        "TOWONEL_IDENTITY_KEY is set but TOWONEL_IDENTITY_KEY_PATH ({}) is unreadable: {e}",
                        p.display()
                    )
                })?;
                if on_disk.trim() != hex {
                    anyhow::bail!(
                        "TOWONEL_IDENTITY_KEY is set but disagrees with the contents of \
                         TOWONEL_IDENTITY_KEY_PATH ({}); remove one to disambiguate",
                        p.display()
                    );
                }
            }
            let bytes = hex::decode(hex)
                .map_err(|e| anyhow::anyhow!("TOWONEL_IDENTITY_KEY is not valid hex: {e}"))?;
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|e| {
                anyhow::anyhow!("TOWONEL_IDENTITY_KEY must be 32 bytes (64 hex chars): {e}")
            })?;
            return Ok(iroh::SecretKey::from(arr));
        }
        let path = self
            .key_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("identity source missing"))?;
        tokio::task::spawn_blocking(move || {
            towonel_common::identity::load_or_generate_secret_key(&path)
        })
        .await
        .context("identity-load task panicked")?
    }
}

#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "config flags map 1:1 to TOWONEL_HUB_* env vars; grouping into sub-structs would obscure the env surface"
)]
pub struct HubConfig {
    pub enabled: bool,
    pub database: DatabaseConfig,
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub operator_api_key_path: PathBuf,
    pub operator_api_key: Option<String>,
    pub public_url: Option<String>,
    /// Keyed-hash key for invite secrets. Loaded from
    /// [`crate::hub::INVITE_HASH_KEY_ENV`] during `NodeConfig::load` so a
    /// missing/invalid value fails startup before DB migrations run.
    /// `Arc` so downstream `HubParams` can cheaply share it without re-reading env.
    pub invite_hash_key: Option<std::sync::Arc<towonel_common::invite::InviteHashKey>>,
    /// AEAD KEK wrapping hub signing-key private bytes in `hub_signing_keys`.
    /// Loaded from [`crate::hub::HUB_KEK_ENV`].
    pub hub_kek: Option<std::sync::Arc<towonel_common::kek::HubKek>>,
    /// When unset, the hub does not accept remote edges.
    pub link_listen_addr: Option<String>,
    /// Must match `TOWONEL_EDGE_HUB_LINK_PSK` on every edge.
    pub link_psk: Option<std::sync::Arc<[u8; 32]>>,
    /// When set, the hub serves its API over TLS-ALPN-01 ACME on
    /// `listen_addr`. Operators set `TOWONEL_HUB_TLS_ACME_EMAIL` to enable.
    pub tls: Option<TlsConfig>,
    /// Mounts the web account/session routes (`/v1/auth/*`, `/v1/signup-invites`,
    /// `/v1/users`). Off by default so self-hosters who only use the CLI +
    /// operator-key flow get zero behavior change. Toggled via
    /// `TOWONEL_HUB_WEB_ENABLED`.
    pub web_enabled: bool,
    /// `TOWONEL_HUB_PORTS_REQUIRE_RESERVATION`.
    pub ports_require_reservation: bool,
    /// Per-user port reservation quota. `0` means unlimited. `TOWONEL_HUB_USER_PORT_QUOTA`.
    pub user_port_quota: i64,
    /// Reverse-proxy source ranges whose `X-Forwarded-For` is trusted when
    /// keying rate-limit / login-lockout counters. Empty (the default) means
    /// `X-Forwarded-For` is never honored and the immediate TCP peer is always
    /// used — fail closed so a private-range peer can't spoof the key.
    /// `TOWONEL_HUB_TRUSTED_PROXIES` (CSV CIDRs).
    pub trusted_proxies: Vec<IpNet>,
    /// Per-IP rate limit on the public auth/bootstrap surface.
    /// `TOWONEL_HUB_RATE_LIMIT_PER_SEC` / `TOWONEL_HUB_RATE_LIMIT_BURST`.
    pub rate_limit: RateLimitConfig,
    /// Active/passive leader election among hubs sharing one Postgres.
    /// `TOWONEL_HUB_LEADER_ELECTION` (default `true`). Ignored for `SQLite`
    /// (single instance is always leader).
    pub leader_election: bool,
    /// Optional DSN for the leader-election connection, pointing at the
    /// Postgres **primary directly** (bypassing any pooler). Falls back to
    /// the main DSN when unset. `TOWONEL_HUB_LEADER_DB_DSN`.
    pub leader_db_dsn: Option<String>,
    pub oidc: OidcConfig,
    pub console_url: Option<String>,
    pub mail: Option<MailConfig>,
    pub webauthn_rp_id: Option<String>,
}

/// Per-IP rate limit for the public surface.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub per_second: u32,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 5,
            burst: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub api_key: String,
    pub api_secret: zeroize::Zeroizing<String>,
    pub from_email: String,
    pub from_name: String,
    pub sandbox: bool,
}

#[derive(Debug, Default, Clone)]
pub struct OidcConfig {
    pub codeberg: Option<OidcProviderConfig>,
}

#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: zeroize::Zeroizing<String>,
    pub redirect_uri: String,
}

/// Default UDP port for the iroh QUIC socket. Operators rarely need
/// to override this; matches the example in the README and examples/.
pub const DEFAULT_IROH_PORT: u16 = 51820;

#[derive(Debug)]
pub struct EdgeConfig {
    pub enabled: bool,
    pub listen_addr: String,
    /// Optional plain-HTTP listener (Host-header routing, ACME HTTP-01).
    /// Unset means no HTTP listener.
    pub http_listen_addr: Option<String>,
    pub health_listen_addr: String,
    pub hub_link_addr: Option<String>,
    pub hub_link_psk: Option<std::sync::Arc<[u8; 32]>>,
    pub public_addresses: Vec<String>,
    /// Raw public IPs (no port) used for port reservation matching.
    pub public_ips: Vec<String>,
    /// Pinned UDP port for the iroh QUIC socket. Operators forward this
    /// port through their firewall so agents can reach the edge.
    pub iroh_port: u16,
    /// Number of TCP accept workers sharing `listen_addr` via `SO_REUSEPORT`
    /// on Unix. Raise to scale accept across cores under bursty load.
    pub listen_workers: usize,
    /// PROXY protocol v2 ingress. Configured via `TOWONEL_EDGE_PROXY_PROTOCOL`
    /// (bool) and `TOWONEL_EDGE_PROXY_PROTOCOL_TRUSTED` (CSV CIDRs).
    pub proxy_protocol: ProxyProtocolConfig,
    pub tcp_services: bool,
    pub udp_services: bool,
    pub max_connections_per_tenant: usize,
    /// Region this edge serves, from `TOWONEL_EDGE_REGION` (default `EU`).
    pub region: String,
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

fn build_rate_limit(
    per_second: Option<u32>,
    burst: Option<u32>,
) -> anyhow::Result<RateLimitConfig> {
    let defaults = RateLimitConfig::default();
    let cfg = RateLimitConfig {
        per_second: per_second.unwrap_or(defaults.per_second),
        burst: burst.unwrap_or(defaults.burst),
    };
    if cfg.per_second == 0 {
        anyhow::bail!("TOWONEL_HUB_RATE_LIMIT_PER_SEC must be greater than 0");
    }
    if cfg.burst == 0 {
        anyhow::bail!("TOWONEL_HUB_RATE_LIMIT_BURST must be greater than 0");
    }
    Ok(cfg)
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

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_dir: PathBuf,
    pub acme_email: Option<String>,
    pub acme_staging: bool,
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
    /// Base directory supplying defaults for every path-shaped env var below.
    data_dir: Option<PathBuf>,

    identity_key: Option<String>,
    identity_key_path: Option<PathBuf>,

    invite_hash_key: Option<String>,
    invite_hash_key_path: Option<PathBuf>,

    hub_kek: Option<String>,
    hub_kek_path: Option<PathBuf>,

    hub_enabled: Option<bool>,
    hub_listen_addr: Option<String>,
    hub_health_listen_addr: Option<String>,
    hub_operator_api_key: Option<String>,
    hub_operator_api_key_path: Option<PathBuf>,
    hub_public_url: Option<String>,
    hub_webauthn_rp_id: Option<String>,
    hub_db_driver: Option<DbDriver>,
    hub_db_dsn: Option<String>,
    hub_leader_election: Option<bool>,
    hub_leader_db_dsn: Option<String>,
    hub_db_max_open_conns: Option<u32>,
    hub_db_max_idle_conns: Option<u32>,
    hub_link_listen_addr: Option<String>,
    hub_link_psk: Option<String>,
    hub_web_enabled: Option<bool>,
    hub_ports_require_reservation: Option<bool>,
    hub_user_port_quota: Option<i64>,
    hub_trusted_proxies: Option<String>,
    hub_rate_limit_per_sec: Option<u32>,
    hub_rate_limit_burst: Option<u32>,
    hub_oidc_codeberg_issuer: Option<String>,
    hub_oidc_codeberg_client_id: Option<String>,
    hub_oidc_codeberg_client_secret: Option<String>,
    hub_oidc_codeberg_redirect_uri: Option<String>,
    hub_console_url: Option<String>,

    mail_mailjet_api_key: Option<String>,
    mail_mailjet_api_secret: Option<String>,
    mail_from_email: Option<String>,
    mail_from_name: Option<String>,
    mail_sandbox: Option<bool>,

    edge_enabled: Option<bool>,
    edge_listen_addr: Option<String>,
    edge_http_listen_addr: Option<String>,
    edge_health_listen_addr: Option<String>,
    edge_hub_link_addr: Option<String>,
    edge_hub_link_psk: Option<String>,
    /// `host:port` advertised to agents/clients — the reverse proxy's
    /// public address when one fronts the edge, not the edge's listen addr.
    edge_advertised_addresses: Vec<String>,
    /// Deprecated alias for `edge_advertised_addresses`.
    edge_public_addresses: Vec<String>,
    /// Raw public IPs (no port) for port reservation matching — e.g. `1.2.3.4,5.6.7.8`.
    edge_public_ips: Vec<String>,
    edge_iroh_port: Option<u16>,
    edge_listen_workers: Option<usize>,
    edge_proxy_protocol: Option<bool>,
    edge_proxy_protocol_trusted: Option<String>,
    edge_tcp_services: Option<bool>,
    edge_udp_services: Option<bool>,
    edge_max_connections_per_tenant: Option<usize>,
    edge_region: Option<String>,

    hub_tls_cert_dir: Option<PathBuf>,
    hub_tls_acme_email: Option<String>,
    hub_tls_acme_staging: Option<bool>,

    tenants: Option<String>,
}

impl NodeConfig {
    /// Load from `TOWONEL_*` env vars. Lists are CSV; structured values
    /// (`TOWONEL_TENANTS`) are JSON. The README lists every knob.
    pub fn load() -> anyhow::Result<Self> {
        let raw: RawEnv = envy::prefixed("TOWONEL_").from_env()?;
        Self::from_raw(raw)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "single linear flat-env destructure; splitting hides which fields feed which struct"
    )]
    fn from_raw(r: RawEnv) -> anyhow::Result<Self> {
        let hub_tls = build_hub_tls(&r);
        let RawEnv {
            data_dir,
            identity_key,
            identity_key_path,
            invite_hash_key,
            invite_hash_key_path,
            hub_kek,
            hub_kek_path,
            hub_enabled,
            hub_listen_addr,
            hub_health_listen_addr,
            hub_operator_api_key,
            hub_operator_api_key_path,
            hub_public_url,
            hub_webauthn_rp_id,
            hub_db_driver,
            hub_db_dsn,
            hub_leader_election,
            hub_leader_db_dsn,
            hub_db_max_open_conns,
            hub_db_max_idle_conns,
            hub_link_listen_addr,
            hub_link_psk,
            hub_web_enabled,
            hub_ports_require_reservation,
            hub_user_port_quota,
            hub_trusted_proxies,
            hub_rate_limit_per_sec,
            hub_rate_limit_burst,
            hub_oidc_codeberg_issuer,
            hub_oidc_codeberg_client_id,
            hub_oidc_codeberg_client_secret,
            hub_oidc_codeberg_redirect_uri,
            hub_console_url,
            mail_mailjet_api_key,
            mail_mailjet_api_secret,
            mail_from_email,
            mail_from_name,
            mail_sandbox,
            edge_enabled,
            edge_listen_addr,
            edge_http_listen_addr,
            edge_health_listen_addr,
            edge_hub_link_addr,
            edge_hub_link_psk,
            edge_advertised_addresses,
            edge_public_addresses,
            edge_public_ips,
            edge_iroh_port,
            edge_listen_workers,
            edge_proxy_protocol,
            edge_proxy_protocol_trusted,
            edge_tcp_services,
            edge_udp_services,
            edge_max_connections_per_tenant,
            edge_region,
            tenants,
            ..
        } = r;

        let inline_identity = identity_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let key_path = identity_key_path.or_else(|| data_dir.as_ref().map(|d| d.join("node.key")));
        if inline_identity.is_none() && key_path.is_none() {
            anyhow::bail!(
                "identity source missing: set TOWONEL_IDENTITY_KEY (32 hex bytes), \
                 TOWONEL_IDENTITY_KEY_PATH, or TOWONEL_DATA_DIR (defaults to \
                 ${{DATA_DIR}}/node.key)"
            );
        }
        let identity = IdentityConfig {
            inline_hex: inline_identity,
            key_path,
        };

        let hub_link_psk = hub_link_psk
            .as_deref()
            .map(|raw| parse_psk_hex(raw, "TOWONEL_HUB_LINK_PSK"))
            .transpose()?
            .map(std::sync::Arc::new);

        let oidc = OidcConfig {
            codeberg: build_oidc_provider(
                "TOWONEL_HUB_OIDC_CODEBERG",
                "https://codeberg.org",
                hub_oidc_codeberg_issuer,
                hub_oidc_codeberg_client_id,
                hub_oidc_codeberg_client_secret,
                hub_oidc_codeberg_redirect_uri,
            )?,
        };

        let console_url = hub_console_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(url) = console_url.as_deref() {
            validate_console_url(url)?;
        }
        let mail = build_mail_config(
            mail_mailjet_api_key,
            mail_mailjet_api_secret,
            mail_from_email,
            mail_from_name,
            mail_sandbox,
        )?;

        let hub = build_hub_config(HubInputs {
            enabled: hub_enabled,
            listen_addr: hub_listen_addr,
            health_listen_addr: hub_health_listen_addr,
            operator_api_key: hub_operator_api_key,
            operator_api_key_path: hub_operator_api_key_path,
            public_url: hub_public_url.clone(),
            db_driver: hub_db_driver,
            db_dsn: hub_db_dsn,
            leader_election: hub_leader_election,
            leader_db_dsn: hub_leader_db_dsn,
            db_max_open_conns: hub_db_max_open_conns,
            db_max_idle_conns: hub_db_max_idle_conns,
            invite_hash_key,
            invite_hash_key_path,
            hub_kek,
            hub_kek_path,
            link_listen_addr: hub_link_listen_addr,
            link_psk: hub_link_psk,
            tls: hub_tls,
            web_enabled: hub_web_enabled,
            ports_require_reservation: hub_ports_require_reservation,
            user_port_quota: hub_user_port_quota,
            trusted_proxies: hub_trusted_proxies,
            rate_limit_per_sec: hub_rate_limit_per_sec,
            rate_limit_burst: hub_rate_limit_burst,
            oidc,
            console_url,
            mail,
            webauthn_rp_id: hub_webauthn_rp_id,
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

        let edge_hub_link_psk = edge_hub_link_psk
            .as_deref()
            .map(|raw| parse_psk_hex(raw, "TOWONEL_EDGE_HUB_LINK_PSK"))
            .transpose()?
            .map(std::sync::Arc::new);
        if let Some(addr) = edge_hub_link_addr.as_deref() {
            validate_host_port("TOWONEL_EDGE_HUB_LINK_ADDR", addr)?;
        }

        let edge_listen_addr = edge_listen_addr.unwrap_or_else(|| "0.0.0.0:443".to_string());
        let edge_health_listen_addr =
            edge_health_listen_addr.unwrap_or_else(|| "0.0.0.0:9090".to_string());
        validate_socket_addr("TOWONEL_EDGE_LISTEN_ADDR", &edge_listen_addr)?;
        if let Some(addr) = edge_http_listen_addr.as_deref() {
            validate_socket_addr("TOWONEL_EDGE_HTTP_LISTEN_ADDR", addr)?;
        }
        validate_socket_addr("TOWONEL_EDGE_HEALTH_LISTEN_ADDR", &edge_health_listen_addr)?;
        let max_connections_per_tenant = edge_max_connections_per_tenant.unwrap_or(1_000);
        if max_connections_per_tenant == 0 {
            // Enforcement rejects when current >= max, so 0 would reject every
            // connection rather than mean "unlimited" — refuse it explicitly.
            anyhow::bail!("TOWONEL_EDGE_MAX_CONNECTIONS_PER_TENANT must be greater than 0");
        }
        let edge = EdgeConfig {
            enabled: edge_enabled.unwrap_or(true),
            listen_addr: edge_listen_addr,
            http_listen_addr: edge_http_listen_addr,
            health_listen_addr: edge_health_listen_addr,
            hub_link_addr: edge_hub_link_addr,
            hub_link_psk: edge_hub_link_psk,
            public_addresses,
            public_ips: resolve_public_ips(edge_public_ips),
            iroh_port: edge_iroh_port.unwrap_or(DEFAULT_IROH_PORT),
            listen_workers: edge_listen_workers.unwrap_or(1),
            proxy_protocol,
            tcp_services: edge_tcp_services.unwrap_or(true),
            udp_services: edge_udp_services.unwrap_or(true),
            max_connections_per_tenant,
            // Uppercased so region matching is case-insensitive.
            region: edge_region
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(towonel_common::DEFAULT_REGION)
                .to_uppercase(),
        };

        let tenants = parse_json_opt("TOWONEL_TENANTS", tenants.as_deref())?.unwrap_or_default();

        Ok(Self {
            identity,
            hub,
            edge,
            tenants,
        })
    }
}

fn build_hub_tls(r: &RawEnv) -> Option<TlsConfig> {
    let any = r.hub_tls_cert_dir.is_some()
        || r.hub_tls_acme_email.is_some()
        || r.hub_tls_acme_staging.is_some();
    if !any {
        return None;
    }
    let default_cert_dir = r
        .data_dir
        .as_ref()
        .map_or_else(|| PathBuf::from("/data/certs"), |d| d.join("certs"));
    Some(TlsConfig {
        cert_dir: r.hub_tls_cert_dir.clone().unwrap_or(default_cert_dir),
        acme_email: r.hub_tls_acme_email.clone(),
        acme_staging: r.hub_tls_acme_staging.unwrap_or(false),
    })
}

struct HubInputs<'a> {
    enabled: Option<bool>,
    listen_addr: Option<String>,
    health_listen_addr: Option<String>,
    operator_api_key: Option<String>,
    operator_api_key_path: Option<PathBuf>,
    public_url: Option<String>,
    db_driver: Option<DbDriver>,
    db_dsn: Option<String>,
    leader_election: Option<bool>,
    leader_db_dsn: Option<String>,
    db_max_open_conns: Option<u32>,
    db_max_idle_conns: Option<u32>,
    invite_hash_key: Option<String>,
    invite_hash_key_path: Option<PathBuf>,
    hub_kek: Option<String>,
    hub_kek_path: Option<PathBuf>,
    link_listen_addr: Option<String>,
    link_psk: Option<std::sync::Arc<[u8; 32]>>,
    tls: Option<TlsConfig>,
    web_enabled: Option<bool>,
    ports_require_reservation: Option<bool>,
    user_port_quota: Option<i64>,
    trusted_proxies: Option<String>,
    rate_limit_per_sec: Option<u32>,
    rate_limit_burst: Option<u32>,
    oidc: OidcConfig,
    console_url: Option<String>,
    mail: Option<MailConfig>,
    webauthn_rp_id: Option<String>,
    data_dir: Option<&'a Path>,
}

#[expect(
    clippy::too_many_lines,
    reason = "linear destructure + per-field defaults; splitting hides the wiring"
)]
fn build_hub_config(inputs: HubInputs<'_>) -> anyhow::Result<HubConfig> {
    let HubInputs {
        enabled,
        listen_addr,
        health_listen_addr,
        operator_api_key,
        operator_api_key_path,
        public_url,
        db_driver,
        db_dsn,
        leader_election,
        leader_db_dsn,
        db_max_open_conns,
        db_max_idle_conns,
        invite_hash_key,
        invite_hash_key_path,
        hub_kek,
        hub_kek_path,
        link_listen_addr,
        link_psk,
        tls,
        web_enabled,
        ports_require_reservation,
        user_port_quota,
        trusted_proxies,
        rate_limit_per_sec,
        rate_limit_burst,
        oidc,
        console_url,
        mail,
        webauthn_rp_id,
        data_dir,
    } = inputs;

    let hub_enabled = enabled.unwrap_or(true);
    if hub_enabled && let Some(url) = public_url.as_deref() {
        validate_hub_public_url(url)?;
    }
    // The web account/passkey flow derives the WebAuthn RP ID and all
    // The WebAuthn RP ID and credential/invite links derive from public_url;
    // its listen-address fallback (0.0.0.0) yields unusable passkeys.
    if hub_enabled && web_enabled.unwrap_or(false) && public_url.is_none() {
        anyhow::bail!(
            "TOWONEL_HUB_WEB_ENABLED=true requires TOWONEL_HUB_PUBLIC_URL to be set: \
             the WebAuthn RP ID and credential/invite URLs are derived from it, and the \
             listen-address fallback (e.g. 0.0.0.0) yields unusable passkeys"
        );
    }
    if let Some(addr) = link_listen_addr.as_deref() {
        validate_socket_addr("TOWONEL_HUB_LINK_LISTEN_ADDR", addr)?;
    }
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
    let hub_kek_path = hub_kek_path.or_else(|| data_dir.map(|d| d.join("hub_kek.key")));

    if hub_enabled && driver == DbDriver::Postgres {
        refuse_autogen_under_postgres_for_ha(
            hub_kek.as_deref(),
            hub_kek_path.as_deref(),
            invite_hash_key.as_deref(),
            invite_hash_key_path.as_deref(),
        )?;
    }

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
    let hub_kek = if hub_enabled {
        Some(std::sync::Arc::new(crate::hub::load_or_generate_hub_kek(
            hub_kek.as_deref(),
            hub_kek_path.as_deref(),
        )?))
    } else {
        None
    };

    if hub_enabled && web_enabled.unwrap_or(false) && mail.is_none() {
        anyhow::bail!(
            "TOWONEL_HUB_WEB_ENABLED=true requires mail to be configured: set \
             TOWONEL_MAIL_MAILJET_API_KEY, TOWONEL_MAIL_MAILJET_API_SECRET, and \
             TOWONEL_MAIL_FROM_EMAIL — signup is verification-gated, so unverified \
             accounts would be locked out without a mailer"
        );
    }

    Ok(HubConfig {
        enabled: hub_enabled,
        database: DatabaseConfig {
            driver,
            dsn,
            max_open_conns: db_max_open_conns,
            max_idle_conns: db_max_idle_conns,
        },
        listen_addr: {
            let v = listen_addr.unwrap_or_else(|| "0.0.0.0:8443".to_string());
            validate_socket_addr("TOWONEL_HUB_LISTEN_ADDR", &v)?;
            v
        },
        health_listen_addr: {
            let v = health_listen_addr.unwrap_or_else(|| "0.0.0.0:9091".to_string());
            validate_socket_addr("TOWONEL_HUB_HEALTH_LISTEN_ADDR", &v)?;
            v
        },
        operator_api_key,
        operator_api_key_path,
        public_url,
        invite_hash_key,
        hub_kek,
        link_listen_addr,
        link_psk,
        tls,
        web_enabled: web_enabled.unwrap_or(false),
        ports_require_reservation: ports_require_reservation.unwrap_or(false),
        user_port_quota: user_port_quota.unwrap_or(0),
        trusted_proxies: trusted_proxies
            .as_deref()
            .map(parse_cidr_list)
            .transpose()?
            .unwrap_or_default(),
        rate_limit: build_rate_limit(rate_limit_per_sec, rate_limit_burst)?,
        leader_election: leader_election.unwrap_or(true),
        leader_db_dsn,
        oidc,
        console_url,
        mail,
        webauthn_rp_id,
    })
}

fn validate_console_url(raw: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(raw)
        .map_err(|e| anyhow::anyhow!("TOWONEL_HUB_CONSOLE_URL is not a valid URL: {e}"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        anyhow::bail!(
            "TOWONEL_HUB_CONSOLE_URL must use http:// or https:// (got {}://)",
            url.scheme()
        );
    }
    if url.host_str().is_none_or(str::is_empty) {
        anyhow::bail!("TOWONEL_HUB_CONSOLE_URL must include a host");
    }
    Ok(())
}

/// Partial config errors loudly rather than silently disabling mail.
fn build_mail_config(
    api_key: Option<String>,
    api_secret: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
    sandbox: Option<bool>,
) -> anyhow::Result<Option<MailConfig>> {
    let any = api_key.is_some() || api_secret.is_some() || from_email.is_some();
    if !any {
        return Ok(None);
    }
    let require = |name: &str, v: Option<String>| -> anyhow::Result<String> {
        v.map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("TOWONEL_MAIL_{name} is required when any TOWONEL_MAIL_* is set")
            })
    };
    let api_key = require("MAILJET_API_KEY", api_key)?;
    let api_secret = require("MAILJET_API_SECRET", api_secret)?;
    let from_email = require("FROM_EMAIL", from_email)?;
    if !from_email.contains('@') {
        anyhow::bail!("TOWONEL_MAIL_FROM_EMAIL is not a valid email");
    }
    let from_name = from_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Towonel".to_string());
    Ok(Some(MailConfig {
        api_key,
        api_secret: zeroize::Zeroizing::new(api_secret),
        from_email,
        from_name,
        sandbox: sandbox.unwrap_or(false),
    }))
}

/// Partial configuration is an error rather than a silent fallback so a
/// deploy typo can't leave the button visible but the callback broken.
fn build_oidc_provider(
    prefix: &str,
    default_issuer: &str,
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
) -> anyhow::Result<Option<OidcProviderConfig>> {
    let any = client_id.is_some() || client_secret.is_some() || redirect_uri.is_some();
    if !any {
        return Ok(None);
    }
    let require = |name: &str, v: Option<String>| -> anyhow::Result<String> {
        v.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
            anyhow::anyhow!("{prefix}_{name} is required when any other {prefix}_* var is set")
        })
    };
    let client_id = require("CLIENT_ID", client_id)?;
    let client_secret = require("CLIENT_SECRET", client_secret)?;
    let redirect_uri = require("REDIRECT_URI", redirect_uri)?;
    let issuer = issuer
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_issuer.to_string());
    if url::Url::parse(&issuer).is_err() {
        anyhow::bail!("{prefix}_ISSUER ({issuer}) is not a valid URL");
    }
    if url::Url::parse(&redirect_uri).is_err() {
        anyhow::bail!("{prefix}_REDIRECT_URI ({redirect_uri}) is not a valid URL");
    }
    Ok(Some(OidcProviderConfig {
        issuer,
        client_id,
        client_secret: zeroize::Zeroizing::new(client_secret),
        redirect_uri,
    }))
}

/// Under Postgres the hub is presumed to be running in HA mode against a
/// shared database. Auto-generating per-replica secrets would silently
/// diverge and only fail at first decrypt — refuse unless the operator
/// provided each secret explicitly (env or pre-existing file).
fn refuse_autogen_under_postgres_for_ha(
    kek_env: Option<&str>,
    kek_path: Option<&Path>,
    invite_env: Option<&str>,
    invite_path: Option<&Path>,
) -> anyhow::Result<()> {
    refuse_autogen("TOWONEL_HUB_KEK", "TOWONEL_HUB_KEK_PATH", kek_env, kek_path)?;
    refuse_autogen(
        "TOWONEL_INVITE_HASH_KEY",
        "TOWONEL_INVITE_HASH_KEY_PATH",
        invite_env,
        invite_path,
    )
}

fn refuse_autogen(
    env_label: &str,
    path_label: &str,
    env_value: Option<&str>,
    path: Option<&Path>,
) -> anyhow::Result<()> {
    let env_set = env_value.map(str::trim).is_some_and(|s| !s.is_empty());
    let file_present = path.is_some_and(Path::exists);
    if env_set || file_present {
        return Ok(());
    }
    anyhow::bail!(
        "{env_label} is not set and {path_label} has no existing key file; refusing to \
         auto-generate under TOWONEL_HUB_DB_DRIVER=postgres because each hub replica would \
         generate a different value and silently diverge — set {env_label} from your secret \
         manager so every replica reads the same value"
    )
}

fn validate_socket_addr(label: &str, raw: &str) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::str::FromStr as _;
    SocketAddr::from_str(raw.trim())
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("{label} is not a valid host:port: {e}"))
}

fn validate_host_port(label: &str, raw: &str) -> anyhow::Result<()> {
    let (host, port) = raw
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("{label} is not a valid host:port: {raw:?}"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        anyhow::bail!("{label} is not a valid host:port: empty host");
    }
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("{label} is not a valid host:port: {e}"))
}

fn validate_hub_public_url(raw: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(raw)
        .map_err(|e| anyhow::anyhow!("TOWONEL_HUB_PUBLIC_URL is not a valid URL: {e}"))?;
    if url.scheme() != "https" {
        anyhow::bail!(
            "TOWONEL_HUB_PUBLIC_URL must use https:// (got {}://); agents fetch invites and \
             credentials over this URL, plaintext is not safe even behind a reverse proxy",
            url.scheme()
        );
    }
    if url.host_str().is_none_or(str::is_empty) {
        anyhow::bail!("TOWONEL_HUB_PUBLIC_URL must include a host");
    }
    Ok(())
}

fn parse_psk_hex(raw: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = raw.trim();
    let bytes =
        hex::decode(trimmed).map_err(|e| anyhow::anyhow!("{label} is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_e| anyhow::anyhow!("{label} must be exactly 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

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

/// Parse `TOWONEL_EDGE_PUBLIC_IPS` — a CSV of raw IPs (no port).
/// Strips brackets from IPv6 literals and trims whitespace.
fn resolve_public_ips(raw: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for entry in raw {
        for part in entry.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ip = trimmed
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(trimmed);
            out.push(canonical_ip(ip));
        }
    }
    out
}

/// Canonical text form of an IP (compresses/lowercases IPv6) so string
/// comparisons can't miss on formatting; non-IP input passes through.
pub fn canonical_ip(s: &str) -> String {
    s.parse::<std::net::IpAddr>()
        .map_or_else(|_| s.to_string(), |ip| ip.to_string())
}

fn parse_json_opt<T: serde::de::DeserializeOwned>(
    key: &str,
    raw: Option<&str>,
) -> anyhow::Result<Option<T>> {
    raw.map(|s| serde_json::from_str::<T>(s).map_err(|e| anyhow::anyhow!("{key}: {e}")))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_db_url_masks_userinfo_and_query_passwords() {
        let out = redact_db_url("postgres://user:secret@db.example:5432/app?sslmode=require");
        assert!(
            out.contains("user:***@"),
            "userinfo password not masked: {out}"
        );
        assert!(
            out.contains("sslmode=require"),
            "non-secret param dropped: {out}"
        );

        let out =
            redact_db_url("postgresql://user@db.example/app?password=hunter2&sslpassword=k&x=1");
        assert!(!out.contains("hunter2"), "query password leaked: {out}");
        assert!(!out.contains("sslpassword=k"), "sslpassword leaked: {out}");
        assert!(out.contains("password=%2A%2A%2A") || out.contains("password=***"));
        assert!(out.contains("x=1"), "non-secret param dropped: {out}");

        // Non-postgres strings pass through untouched.
        assert_eq!(redact_db_url("/var/lib/hub.db"), "/var/lib/hub.db");
    }

    #[test]
    fn canonical_ip_normalizes_ipv6_forms() {
        assert_eq!(
            canonical_ip("2001:41D0:20A:900::14D0"),
            "2001:41d0:20a:900::14d0"
        );
        assert_eq!(
            canonical_ip("2001:41d0:020a:0900::14d0"),
            "2001:41d0:20a:900::14d0"
        );
        assert_eq!(canonical_ip("54.36.18.175"), "54.36.18.175");
        assert_eq!(canonical_ip("edge-eu.towonel.dev"), "edge-eu.towonel.dev");
    }

    #[test]
    fn resolve_public_ips_canonicalizes_entries() {
        let out = resolve_public_ips(vec!["54.36.18.175, [2001:41D0:20A:900::14D0]".to_string()]);
        assert_eq!(out, vec!["54.36.18.175", "2001:41d0:20a:900::14d0"]);
    }

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

    #[test]
    fn postgres_refuses_autogen_without_explicit_secret() {
        refuse_autogen("X", "X_PATH", None, None).unwrap_err();
        refuse_autogen("X", "X_PATH", Some("  "), None).unwrap_err();
        refuse_autogen("X", "X_PATH", Some("hex"), None).unwrap();
        let tmp = std::env::temp_dir().join("towonel-cfg-refuse-autogen-existing");
        std::fs::write(&tmp, b"hex").unwrap();
        refuse_autogen("X", "X_PATH", None, Some(&tmp)).unwrap();
        drop(std::fs::remove_file(&tmp));
        let absent = std::env::temp_dir().join("towonel-cfg-refuse-autogen-absent-xyz");
        drop(std::fs::remove_file(&absent));
        refuse_autogen("X", "X_PATH", None, Some(&absent)).unwrap_err();
    }

    #[test]
    fn socket_addr_validation_catches_typos() {
        validate_socket_addr("X", "0.0.0.0:443").unwrap();
        validate_socket_addr("X", "127.0.0.1:8443").unwrap();
        validate_socket_addr("X", "[::]:443").unwrap();
        validate_socket_addr("X", "0.0.0.0:44.3").unwrap_err();
        validate_socket_addr("X", "0.0.0.0").unwrap_err();
        validate_socket_addr("X", "not-an-addr").unwrap_err();
    }

    #[test]
    fn host_port_validation_accepts_dns_names() {
        validate_host_port("X", "0.0.0.0:443").unwrap();
        validate_host_port("X", "[::1]:443").unwrap();
        validate_host_port("X", "hub.example.com:51444").unwrap();
        validate_host_port("X", "hub.example.com").unwrap_err();
        validate_host_port("X", ":51444").unwrap_err();
        validate_host_port("X", "hub.example.com:notaport").unwrap_err();
        validate_host_port("X", "hub.example.com:70000").unwrap_err();
    }

    #[test]
    fn hub_public_url_must_be_https() {
        validate_hub_public_url("https://hub.example.eu").unwrap();
        validate_hub_public_url("https://hub.example.eu:8443/").unwrap();
        let err = validate_hub_public_url("http://hub.example.eu").unwrap_err();
        assert!(err.to_string().contains("https://"), "got: {err}");
        validate_hub_public_url("ftp://hub.example.eu").unwrap_err();
        validate_hub_public_url("not a url").unwrap_err();
        validate_hub_public_url("https://").unwrap_err();
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
            hub_kek: Some(invite_hex.into()),
            ..RawEnv::default()
        }
    }

    #[test]
    fn data_dir_cascades_into_path_defaults() {
        let dir = unique_data_dir("cascade");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            hub_tls_acme_email: Some("ops@example.com".into()),
            ..base_raw_env(&"11".repeat(32))
        })
        .unwrap();

        assert_eq!(
            cfg.identity.key_path.as_deref(),
            Some(dir.join("node.key").as_path())
        );
        assert_eq!(
            cfg.hub.database.dsn.as_deref(),
            Some(dir.join("hub.db").to_string_lossy().as_ref()),
        );
        assert_eq!(cfg.hub.operator_api_key_path, dir.join("operator.key"));
        let tls = cfg.hub.tls.expect("TLS expected when acme_email set");
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
            hub_tls_cert_dir: Some(PathBuf::from("/custom/certs")),
            hub_tls_acme_email: Some("ops@example.com".into()),
            ..base_raw_env(&"22".repeat(32))
        })
        .unwrap();

        assert_eq!(
            cfg.identity.key_path.as_deref(),
            Some(std::path::Path::new("/custom/node.key"))
        );
        assert_eq!(cfg.hub.database.dsn.as_deref(), Some("/custom/hub.db"));
        assert_eq!(
            cfg.hub.operator_api_key_path,
            PathBuf::from("/custom/operator.key")
        );
        let tls = cfg.hub.tls.unwrap();
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
    fn edge_http_listen_addr_defaults_to_disabled() {
        let cfg = NodeConfig::from_raw(RawEnv {
            identity_key_path: Some(PathBuf::from("/legacy/node.key")),
            ..base_raw_env(&"66".repeat(32))
        })
        .unwrap();
        assert_eq!(cfg.edge.http_listen_addr, None);
    }

    #[test]
    fn edge_http_listen_addr_accepts_valid_socket_addr() {
        let cfg = NodeConfig::from_raw(RawEnv {
            identity_key_path: Some(PathBuf::from("/legacy/node.key")),
            edge_http_listen_addr: Some("[::]:80".into()),
            ..base_raw_env(&"66".repeat(32))
        })
        .unwrap();
        assert_eq!(cfg.edge.http_listen_addr.as_deref(), Some("[::]:80"));
    }

    #[test]
    fn edge_http_listen_addr_rejects_invalid_value() {
        let err = NodeConfig::from_raw(RawEnv {
            identity_key_path: Some(PathBuf::from("/legacy/node.key")),
            edge_http_listen_addr: Some("not-an-addr".into()),
            ..base_raw_env(&"66".repeat(32))
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("TOWONEL_EDGE_HTTP_LISTEN_ADDR"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_identity_without_data_dir_errors_with_helpful_message() {
        let err = NodeConfig::from_raw(base_raw_env(&"44".repeat(32))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("TOWONEL_IDENTITY_KEY"), "got: {msg}");
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
        assert!(cfg.hub.tls.is_none(), "TLS stays off without TLS envs");
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

    #[test]
    fn inline_identity_key_satisfies_missing_path() {
        let cfg = NodeConfig::from_raw(RawEnv {
            identity_key: Some("66".repeat(32)),
            ..base_raw_env(&"77".repeat(32))
        })
        .unwrap();
        assert_eq!(
            cfg.identity.inline_hex.as_deref(),
            Some("6".repeat(64).as_str())
        );
        assert!(cfg.identity.key_path.is_none());
    }

    #[test]
    fn inline_operator_api_key_propagates_to_hub_config() {
        let dir = unique_data_dir("opkey");
        let cfg = NodeConfig::from_raw(RawEnv {
            data_dir: Some(dir.clone()),
            hub_operator_api_key: Some("super-secret-token".into()),
            ..base_raw_env(&"88".repeat(32))
        })
        .unwrap();
        assert_eq!(
            cfg.hub.operator_api_key.as_deref(),
            Some("super-secret-token")
        );
        drop(std::fs::remove_dir_all(&dir));
    }
}
