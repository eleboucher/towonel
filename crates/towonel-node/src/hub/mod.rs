pub mod acme;
pub mod api;
pub mod auth;
pub mod control;
pub mod db;
pub mod edge_link;
pub mod live_agents;
pub mod live_edges;
pub mod mail;
pub mod metrics;
pub mod signing;

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod observability_tests;
#[cfg(test)]
mod test_helpers;

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use tokio::sync::broadcast;
use towonel_common::identity::{write_key_file, write_key_file_exclusive};
use towonel_common::invite::InviteHashKey;
use towonel_common::kek::HubKek;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;
use tracing::info;
use webauthn_rs::WebauthnBuilder;

/// Length of a freshly generated operator API key in bytes (before base64).
/// 32 bytes = 256 bits, base64url-encoded without padding = 43 chars.
const OPERATOR_KEY_BYTES: usize = 32;

pub const INVITE_HASH_KEY_ENV: &str = "TOWONEL_INVITE_HASH_KEY";
pub const HUB_KEK_ENV: &str = "TOWONEL_HUB_KEK";

/// Resolve from env value, else read/generate at `path`, else error.
/// Refuses to start when env and an on-disk key disagree: silently shadowing
/// a stale file invalidates every outstanding invite.
pub fn load_or_generate_invite_hash_key(
    env_value: Option<&str>,
    path: Option<&Path>,
) -> anyhow::Result<InviteHashKey> {
    if let Some(hex) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(p) = path
            && p.exists()
        {
            ensure_env_matches_file(INVITE_HASH_KEY_ENV, "TOWONEL_INVITE_HASH_KEY_PATH", hex, p)?;
        }
        return InviteHashKey::from_hex(hex);
    }
    if let Some(path) = path {
        return load_or_generate_invite_hash_key_at(path);
    }
    anyhow::bail!(
        "{INVITE_HASH_KEY_ENV} is not set — generate one with \
         `openssl rand -hex 32` and export it before starting the hub, \
         or set TOWONEL_INVITE_HASH_KEY_PATH (or TOWONEL_DATA_DIR) so the \
         hub can persist a generated key to disk"
    )
}

fn ensure_env_matches_file(
    env_label: &str,
    path_label: &str,
    env_value: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let on_disk = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "{env_label} is set but {path_label} ({}) is unreadable: {e}",
            path.display()
        )
    })?;
    if on_disk.trim() != env_value.trim() {
        anyhow::bail!(
            "{env_label} is set but disagrees with the contents of {path_label} ({}); \
             remove one to disambiguate before starting the hub",
            path.display()
        );
    }
    Ok(())
}

fn load_or_generate_invite_hash_key_at(path: &Path) -> anyhow::Result<InviteHashKey> {
    // Exclusive-create + AlreadyExists fallback closes the TOCTOU window
    // where two hubs on shared storage would each generate a different key.
    let key = InviteHashKey::generate();
    let hex = key.to_hex();
    match write_key_file_exclusive(path, hex.as_bytes()) {
        Ok(()) => {
            tracing::warn!(
                path = %path.display(),
                "generated new invite-hash key — BACK THIS UP; losing it invalidates \
                 every outstanding invite"
            );
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_invite_hash_key_file(path),
        Err(e) => Err(anyhow::anyhow!(
            "failed to persist invite-hash key at {}: {e}",
            path.display()
        )),
    }
}

fn read_invite_hash_key_file(path: &Path) -> anyhow::Result<InviteHashKey> {
    let content = std::fs::read_to_string(path)?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        anyhow::bail!("invite-hash key file {} is empty", path.display());
    }
    InviteHashKey::from_hex(trimmed)
}

/// Same lifecycle as the invite-hash key: env value wins, else read/generate at `path`.
/// `TOWONEL_HUB_KEK` must be 32 hex-encoded bytes (`openssl rand -hex 32`).
pub fn load_or_generate_hub_kek(
    env_value: Option<&str>,
    path: Option<&Path>,
) -> anyhow::Result<HubKek> {
    if let Some(hex) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(p) = path
            && p.exists()
        {
            ensure_env_matches_file(HUB_KEK_ENV, "TOWONEL_HUB_KEK_PATH", hex, p)?;
        }
        return HubKek::from_hex(hex);
    }
    if let Some(path) = path {
        return load_or_generate_hub_kek_at(path);
    }
    anyhow::bail!(
        "{HUB_KEK_ENV} is not set — generate one with \
         `openssl rand -hex 32` and export it before starting the hub, \
         or set TOWONEL_HUB_KEK_PATH (or TOWONEL_DATA_DIR) so the hub \
         can persist a generated key to disk"
    )
}

fn load_or_generate_hub_kek_at(path: &Path) -> anyhow::Result<HubKek> {
    let kek = HubKek::generate();
    let hex = kek.to_hex();
    match write_key_file_exclusive(path, hex.as_bytes()) {
        Ok(()) => {
            tracing::warn!(
                path = %path.display(),
                "generated new hub KEK — BACK THIS UP; losing it bricks every \
                 row in hub_signing_keys"
            );
            Ok(kek)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_hub_kek_file(path),
        Err(e) => Err(anyhow::anyhow!(
            "failed to persist hub KEK at {}: {e}",
            path.display()
        )),
    }
}

fn read_hub_kek_file(path: &Path) -> anyhow::Result<HubKek> {
    let content = std::fs::read_to_string(path)?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        anyhow::bail!("hub KEK file {} is empty", path.display());
    }
    HubKek::from_hex(trimmed)
}

/// Resolve from env value, else read/generate at `path`. File I/O happens
/// on a blocking pool so the async runtime isn't stalled at startup.
pub async fn load_or_generate_operator_key(
    env_value: Option<&str>,
    path: &Path,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    if let Some(value) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
        if path.exists() {
            ensure_env_matches_file(
                "TOWONEL_HUB_OPERATOR_API_KEY",
                "TOWONEL_HUB_OPERATOR_API_KEY_PATH",
                value,
                path,
            )?;
        }
        return Ok(zeroize::Zeroizing::new(value.to_string()));
    }
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || load_or_generate_operator_key_blocking(&path))
        .await
        .map_err(|e| anyhow::anyhow!("operator-key task panicked: {e}"))?
}

fn load_or_generate_operator_key_blocking(
    path: &Path,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("operator API key file {} is empty", path.display());
        }
        Ok(zeroize::Zeroizing::new(trimmed))
    } else {
        let mut bytes = [0u8; OPERATOR_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
        let key = B64.encode(bytes);
        write_key_file(path, key.as_bytes())?;
        info!(
            path = %path.display(),
            "generated new operator API key (pass via `Authorization: Bearer <key>` for /v1/invites)"
        );
        Ok(zeroize::Zeroizing::new(key))
    }
}

/// Operational identity information that the hub exposes via `/v1/health`
/// and `/v1/edges`. Constructed once at startup in `main`.
pub struct HubIdentity {
    pub node_id: iroh::EndpointId,
    pub edge_node_id: Option<iroh::EndpointId>,
    pub edge_addresses: Vec<String>,
    /// Derived from `edge_addresses`' hostnames + the pinned iroh UDP port.
    pub edge_iroh_addresses: Vec<String>,
    /// Relay URL the hub advertises to agents at bootstrap so they don't have to configure it.
    pub relay_url: Option<String>,
    pub software_version: &'static str,
}

/// Everything the hub needs to start, grouped to keep the constructor lean.
pub struct HubParams {
    pub listen_addr: String,
    pub health_listen_addr: String,
    pub database: crate::config::DatabaseConfig,
    pub route_tx: broadcast::Sender<RouteTable>,
    pub static_policy: OwnershipPolicy,
    pub identity: HubIdentity,
    pub operator_api_key: zeroize::Zeroizing<String>,
    pub invite_hash_key: Arc<InviteHashKey>,
    pub kek: Arc<HubKek>,
    pub public_url: String,
    pub link_listen_addr: Option<String>,
    pub link_psk: Option<Arc<[u8; 32]>>,
    pub tls: Option<crate::config::TlsConfig>,
    pub web_enabled: bool,
    pub ports_require_reservation: bool,
    pub oidc: crate::config::OidcConfig,
    pub mailer: Option<mail::SharedMailer>,
    pub webauthn_rp_id: Option<String>,
}

/// The hub: accepts signed config entries from tenants via an HTTP management
/// API, persists them to `SQLite`, and serves config updates to edges.
pub struct Hub {
    p: HubParams,
    /// `Some` only when the hub is colocated with an edge; filled at boot.
    control_handler_cell: Option<crate::edge::hub_client::ControlHandlerCell>,
    live_agents_sink_cell: Option<crate::edge::hub_client::LiveAgentSinkCell>,
}

fn spawn_background_loops(state: &Arc<api::AppState>) {
    tokio::spawn(refresh_metrics_loop(Arc::clone(state)));
    tokio::spawn(route_rebuild_loop(Arc::clone(state)));
    tokio::spawn(session_prune_loop(Arc::clone(state)));
}

impl Hub {
    pub const fn new(params: HubParams) -> Self {
        Self {
            p: params,
            control_handler_cell: None,
            live_agents_sink_cell: None,
        }
    }

    #[must_use]
    pub fn with_control_handler_cell(
        mut self,
        cell: crate::edge::hub_client::ControlHandlerCell,
    ) -> Self {
        self.control_handler_cell = Some(cell);
        self
    }

    #[must_use]
    pub fn with_live_agents_sink_cell(
        mut self,
        cell: crate::edge::hub_client::LiveAgentSinkCell,
    ) -> Self {
        self.live_agents_sink_cell = Some(cell);
        self
    }

    /// Run the hub. Opens the DB and starts the HTTP management API.
    #[expect(
        clippy::too_many_lines,
        reason = "linear startup sequence: DB open + state build + listeners + edge_link spawn"
    )]
    pub async fn run(&self) -> anyhow::Result<()> {
        let db_url = self.p.database.connection_url()?;
        info!(
            listen = %self.p.listen_addr,
            db = %crate::config::redact_db_url(&db_url),
            max_open = self.p.database.max_open(),
            max_idle = self.p.database.max_idle(),
            web_enabled = self.p.web_enabled,
            "hub starting"
        );

        let db = db::Db::open(
            &db_url,
            self.p.database.max_open(),
            self.p.database.max_idle(),
        )
        .await?;

        db.verify_or_seed_canary(&self.p.kek, &self.p.invite_hash_key)
            .await?;

        let live_agents = Arc::new(live_agents::LiveAgents::new());
        let route_rebuild_notify = Arc::new(tokio::sync::Notify::new());

        let signer = Arc::new(signing::get_or_create_active_signing_key(&db, &self.p.kek).await?);
        info!(kid = signer.kid(), "active hub signing key loaded");

        // Before OIDC so build_oidc_runtimes can seed JWKS metrics.
        let metrics = metrics::HubMetrics::new();

        let oidc = api::build_oidc_runtimes(&self.p.oidc, &metrics).await?;
        if oidc.codeberg.is_some() {
            info!("OIDC provider 'codeberg' configured");
        }

        let parsed = url::Url::parse(&self.p.public_url)
            .map_err(|e| anyhow::anyhow!("invalid public_url for WebAuthn: {e}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("public_url has no host for WebAuthn rp_id"))?;
        let rp_id = self.p.webauthn_rp_id.as_deref().unwrap_or(host).to_string();
        let origin_str = format!("{}://{rp_id}", parsed.scheme());
        let rp_origin = url::Url::parse(&origin_str)
            .map_err(|e| anyhow::anyhow!("constructed WebAuthn origin invalid: {e}"))?;
        let webauthn = Arc::new(
            WebauthnBuilder::new(&rp_id, &rp_origin)
                .map_err(|e| anyhow::anyhow!("WebauthnBuilder::new failed: {e}"))?
                .rp_name("Towonel")
                .build()
                .map_err(|e| anyhow::anyhow!("Webauthn::build failed: {e}"))?,
        );

        let removed: Vec<towonel_common::identity::TenantId> = db.list_tenant_removals().await?;

        let mut policy = self.p.static_policy.clone();
        for tid in &removed {
            policy.remove(tid);
        }
        for tenant in db.list_active_tenants().await? {
            if removed.contains(&tenant.tenant_id) {
                continue;
            }
            policy.register_tenant(&tenant.tenant_id, tenant.pq_public_key, tenant.hostnames);
        }

        let state = Arc::new(api::AppState {
            db,
            route_tx: self.p.route_tx.clone(),
            policy: arc_swap::ArcSwap::from_pointee(policy),
            identity: HubIdentity {
                node_id: self.p.identity.node_id,
                edge_node_id: self.p.identity.edge_node_id,
                edge_addresses: self.p.identity.edge_addresses.clone(),
                edge_iroh_addresses: self.p.identity.edge_iroh_addresses.clone(),
                relay_url: self.p.identity.relay_url.clone(),
                software_version: self.p.identity.software_version,
            },
            operator_api_key: self.p.operator_api_key.clone(),
            use_secure_cookies: self.p.public_url.starts_with("https://"),
            public_url: self.p.public_url.clone(),
            invite_lock: tokio::sync::Mutex::new(()),
            metrics,
            invite_hash_key: Arc::clone(&self.p.invite_hash_key),
            signed_request_nonces: api::new_nonce_cache(),
            tcp_port_lock: tokio::sync::Mutex::new(()),
            udp_port_lock: tokio::sync::Mutex::new(()),
            signer,
            kek: Arc::clone(&self.p.kek),
            refresh_limiter: api::new_refresh_limiter(),
            login_limiter: api::new_login_limiter(),
            ip_login_limiter: api::new_login_limiter(),
            login_sentinel_hash: api::compute_login_sentinel_hash().await?,
            twofa_attempt_limiter: api::new_twofa_attempt_limiter(),
            live_edges: Arc::new(live_edges::LiveEdges::new()),
            live_agents: Arc::clone(&live_agents),
            route_rebuild_notify: Arc::clone(&route_rebuild_notify),
            web_enabled: self.p.web_enabled,
            mailer: self.p.mailer.clone(),
            port_reservations_tx: tokio::sync::broadcast::channel(64).0,
            ports_require_reservation: self.p.ports_require_reservation,
            port_index: arc_swap::ArcSwap::from_pointee(api::PortIndex::default()),
            oidc,
            webauthn,
            passkey_reg_states: api::new_passkey_reg_states(),
            passkey_auth_states: api::new_passkey_auth_states(),
            tls: self.p.tls.clone(),
        });

        // Seed the port index from the DB before serving any upsert; the
        // first call to `find_port_conflict` would otherwise see an empty
        // index and let a tenant re-claim someone else's port.
        if let Err(e) = api::rebuild_and_broadcast_routes(&state).await {
            tracing::warn!(error = %e, "initial route + port_index seed failed");
        }

        spawn_background_loops(&state);

        // Build once and share between the colocated in-process path and the
        // edge_link server so the nonce replay cache is global to the hub.
        let control_handler: Arc<dyn crate::edge::hub_client::ControlFrameHandler> =
            Arc::new(control::HubControlHandler::new(Arc::clone(&state)));
        if let Some(cell) = self.control_handler_cell.as_ref()
            && cell.set(Arc::clone(&control_handler)).is_err()
        {
            tracing::warn!("hub control handler cell was already set; ignoring");
        }

        let live_agents_sink: Arc<dyn crate::edge::hub_client::LiveAgentSink> =
            Arc::new(LocalLiveAgentSink {
                state: Arc::clone(&state),
            });
        if let Some(cell) = self.live_agents_sink_cell.as_ref()
            && cell.set(Arc::clone(&live_agents_sink)).is_err()
        {
            tracing::warn!("hub live agents sink cell was already set; ignoring");
        }

        let api_app = api::router(Arc::clone(&state))
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let health_app = api::health_router(Arc::clone(&state));

        let health_listener = tokio::net::TcpListener::bind(&self.p.health_listen_addr).await?;
        info!(listen = %self.p.health_listen_addr, "hub health/metrics listening");

        let api_listener = tokio::net::TcpListener::bind(&self.p.listen_addr).await?;
        let acme = if let Some(tls) = self.p.tls.as_ref() {
            let email = tls.acme_email.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "TOWONEL_HUB_TLS_ACME_EMAIL is required when any \
                     TOWONEL_HUB_TLS_* is set"
                )
            })?;
            let mgr = acme::AcmeManager::new(&tls.cert_dir, email, tls.acme_staging)?;
            if let Some(host) = url::Url::parse(&self.p.public_url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_lowercase))
            {
                mgr.trigger_obtain(&host);
            }
            Some(mgr)
        } else {
            None
        };
        info!(
            listen = %self.p.listen_addr,
            tls = acme.is_some(),
            "hub API listening"
        );

        let link_shutdown = tokio_util::sync::CancellationToken::new();
        let link_task = match (self.p.link_listen_addr.clone(), self.p.link_psk.clone()) {
            (Some(addr), Some(psk)) => {
                let server = edge_link::EdgeLinkServer::bind(
                    &addr,
                    psk,
                    *self.p.identity.node_id.as_bytes(),
                    Arc::clone(&state),
                    Arc::clone(&control_handler),
                )
                .await?;
                let shutdown = link_shutdown.clone();
                Some(tokio::spawn(async move { server.run(shutdown).await }))
            }
            (Some(_), None) | (None, Some(_)) => {
                tracing::warn!(
                    "edge_link listen_addr and psk must both be set; edge_link disabled"
                );
                None
            }
            (None, None) => None,
        };

        let serve_result = if let Some(mgr) = acme {
            let rustls_cfg =
                axum_server::tls_rustls::RustlsConfig::from_config(mgr.server_config());
            let api_std = api_listener.into_std()?;
            tokio::select! {
                res = axum_server::from_tcp_rustls(api_std, rustls_cfg).serve(api_app) => res.map_err(anyhow::Error::from),
                res = axum::serve(health_listener, health_app) => res.map_err(anyhow::Error::from),
            }
        } else {
            tokio::select! {
                res = axum::serve(api_listener, api_app) => res.map_err(anyhow::Error::from),
                res = axum::serve(health_listener, health_app) => res.map_err(anyhow::Error::from),
            }
        };

        link_shutdown.cancel();
        if let Some(task) = link_task {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "edge_link server exited with error"),
                Err(e) => tracing::debug!(error = %e, "edge_link task join error"),
            }
        }

        serve_result
    }
}

/// Drains `route_rebuild_notify` and runs one rebuild per wake. Bursts
/// of N notifications collapse to one rebuild (needed for many-agent
/// reconnect storms).
async fn route_rebuild_loop(state: Arc<api::AppState>) {
    let notify = Arc::clone(&state.route_rebuild_notify);
    if let Err(e) = api::rebuild_and_broadcast_routes(&state).await {
        tracing::warn!(error = %e, "initial route rebuild failed");
    }
    loop {
        notify.notified().await;
        if let Err(e) = api::rebuild_and_broadcast_routes(&state).await {
            tracing::warn!(error = %e, "route rebuild failed");
        }
    }
}

/// Hourly delete of expired session rows. Auth filters them out anyway;
/// this is storage hygiene.
async fn session_prune_loop(state: Arc<api::AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_hours(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // skip immediate first tick
    loop {
        tick.tick().await;
        let now = i64::try_from(towonel_common::time::now_ms()).unwrap_or(i64::MAX);
        match state.db.prune_expired_sessions(now).await {
            Ok(n) if n > 0 => tracing::debug!(pruned = n, "pruned expired sessions"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "session prune failed"),
        }
    }
}

/// Periodically refresh `tenants_total` from the in-memory policy.
///
/// A 15 s refresh is fine for dashboards; we don't need to instrument every
/// policy mutation just to keep a gauge accurate to the second.
async fn refresh_metrics_loop(state: Arc<api::AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let tenants = state.policy.load().iter_patterns().count();
        state
            .metrics
            .tenants_total
            .set(i64::try_from(tenants).unwrap_or(i64::MAX));
    }
}

/// Bridges the colocated in-process edge's session events into the hub's
/// [`live_agents::LiveAgents`] under `SourceKey::Local`.
struct LocalLiveAgentSink {
    state: Arc<api::AppState>,
}

impl crate::edge::hub_client::LiveAgentSink for LocalLiveAgentSink {
    fn record_added(
        &self,
        tenant_id: towonel_common::identity::TenantId,
        agent_id: towonel_common::identity::AgentId,
    ) -> bool {
        let changed =
            self.state
                .live_agents
                .record_added(live_agents::SourceKey::Local, tenant_id, agent_id);
        if changed {
            api::trigger_route_rebuild(&self.state);
        }
        changed
    }

    fn record_removed(
        &self,
        tenant_id: towonel_common::identity::TenantId,
        agent_id: towonel_common::identity::AgentId,
    ) -> bool {
        let changed = self.state.live_agents.record_removed(
            live_agents::SourceKey::Local,
            tenant_id,
            agent_id,
        );
        if changed {
            api::trigger_route_rebuild(&self.state);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).expect("rng");
        let mut p = std::env::temp_dir();
        p.push(format!(
            "towonel-invite-hash-{name}-{}-{}",
            std::process::id(),
            hex::encode(suffix),
        ));
        p
    }

    #[test]
    fn env_value_wins_over_path() {
        let hex = "11".repeat(32);
        let path = temp_path("env-wins");
        // File doesn't exist, but env value should be used and file left alone.
        let key = load_or_generate_invite_hash_key(Some(&hex), Some(&path)).unwrap();
        assert_eq!(key.to_hex(), hex);
        assert!(!path.exists(), "env value path must not be touched");
    }

    #[test]
    fn file_is_read_when_present() {
        let hex = "22".repeat(32);
        let path = temp_path("file-read");
        std::fs::write(&path, &hex).unwrap();
        let key = load_or_generate_invite_hash_key(None, Some(&path)).unwrap();
        assert_eq!(key.to_hex(), hex);
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn file_is_generated_when_missing() {
        let path = temp_path("file-gen");
        assert!(!path.exists());
        let key = load_or_generate_invite_hash_key(None, Some(&path)).unwrap();
        assert!(path.exists(), "key file must be persisted");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim(), key.to_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn neither_env_nor_path_errors() {
        let err = load_or_generate_invite_hash_key(None, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(INVITE_HASH_KEY_ENV), "got: {msg}");
        assert!(msg.contains("TOWONEL_INVITE_HASH_KEY_PATH"), "got: {msg}");
    }

    #[test]
    fn empty_env_value_falls_through_to_path() {
        let path = temp_path("empty-env");
        let key = load_or_generate_invite_hash_key(Some("   "), Some(&path)).unwrap();
        assert!(path.exists());
        drop(std::fs::remove_file(&path));
        // Sanity: we got a real key (not all-zeros).
        assert_ne!(key.to_hex(), "0".repeat(64));
    }

    #[test]
    fn empty_file_errors() {
        let path = temp_path("empty-file");
        std::fs::write(&path, "").unwrap();
        let err = load_or_generate_invite_hash_key(None, Some(&path)).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn env_matches_file_is_ok() {
        let hex = "33".repeat(32);
        let path = temp_path("env-match");
        std::fs::write(&path, &hex).unwrap();
        let key = load_or_generate_invite_hash_key(Some(&hex), Some(&path)).unwrap();
        assert_eq!(key.to_hex(), hex);
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn env_disagreeing_with_file_errors() {
        let env_hex = "44".repeat(32);
        let file_hex = "55".repeat(32);
        let path = temp_path("env-mismatch");
        std::fs::write(&path, &file_hex).unwrap();
        let err = load_or_generate_invite_hash_key(Some(&env_hex), Some(&path)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("disagrees"), "got: {msg}");
        assert!(msg.contains(INVITE_HASH_KEY_ENV), "got: {msg}");
        drop(std::fs::remove_file(&path));
    }

    #[tokio::test]
    async fn operator_key_env_value_wins_over_path() {
        let path = temp_path("op-env-wins");
        let key = load_or_generate_operator_key(Some("inline-token-value"), &path)
            .await
            .unwrap();
        assert_eq!(&**key, "inline-token-value");
        assert!(!path.exists(), "env value path must not be touched");
    }

    #[tokio::test]
    async fn operator_key_blank_env_falls_through_to_path() {
        let path = temp_path("op-blank-env");
        let key = load_or_generate_operator_key(Some("   "), &path)
            .await
            .unwrap();
        assert!(path.exists(), "blank env must trigger file generation");
        assert!(!key.is_empty());
        drop(std::fs::remove_file(&path));
    }
}
