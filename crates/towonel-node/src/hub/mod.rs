pub mod acme;
pub mod api;
pub mod auth;
pub mod control;
pub mod db;
pub mod edge_link;
pub mod live_edges;
pub mod liveness;
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

/// Length of a freshly generated operator API key in bytes (before base64).
/// 32 bytes = 256 bits, base64url-encoded without padding = 43 chars.
const OPERATOR_KEY_BYTES: usize = 32;

pub const INVITE_HASH_KEY_ENV: &str = "TOWONEL_INVITE_HASH_KEY";
pub const HUB_KEK_ENV: &str = "TOWONEL_HUB_KEK";

/// Resolve from env value, else read/generate at `path`, else error.
pub fn load_or_generate_invite_hash_key(
    env_value: Option<&str>,
    path: Option<&Path>,
) -> anyhow::Result<InviteHashKey> {
    if let Some(hex) = env_value.map(str::trim).filter(|s| !s.is_empty()) {
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

/// Load the operator API key from `path`, or generate a new random one and
/// save it with 0o600 permissions. File I/O happens on a blocking pool so
/// the async runtime isn't stalled at startup.
pub async fn load_or_generate_operator_key(
    path: &Path,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
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
}

/// The hub: accepts signed config entries from tenants via an HTTP management
/// API, persists them to `SQLite`, and serves config updates to edges.
pub struct Hub {
    p: HubParams,
    /// `Some` only when the hub is colocated with an edge; filled at boot.
    control_handler_cell: Option<crate::edge::hub_client::ControlHandlerCell>,
    liveness_cell: Option<crate::edge::hub_client::LivenessCell>,
}

fn spawn_background_loops(state: &Arc<api::AppState>) {
    tokio::spawn(refresh_metrics_loop(Arc::clone(state)));
    tokio::spawn(agent_liveness_prune_loop(Arc::clone(state)));
    tokio::spawn(session_prune_loop(Arc::clone(state)));
}

impl Hub {
    pub const fn new(params: HubParams) -> Self {
        Self {
            p: params,
            control_handler_cell: None,
            liveness_cell: None,
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
    pub fn with_liveness_cell(mut self, cell: crate::edge::hub_client::LivenessCell) -> Self {
        self.liveness_cell = Some(cell);
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

        let liveness: liveness::SharedLivenessStore =
            Arc::new(liveness::InMemoryLivenessStore::new());

        let signer = Arc::new(signing::get_or_create_active_signing_key(&db, &self.p.kek).await?);
        info!(kid = signer.kid(), "active hub signing key loaded");

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

        match db.get_all_entries().await {
            Ok(entries) => {
                let table = RouteTable::from_entries_with_liveness(
                    &entries,
                    &policy,
                    Some(&std::collections::HashSet::new()),
                );
                if self.p.route_tx.send(table).is_err() {
                    tracing::debug!("startup route broadcast: no subscribers yet");
                }
            }
            Err(e) => tracing::warn!(error = %e, "initial route broadcast skipped"),
        }

        let metrics = metrics::HubMetrics::new();
        let state = Arc::new(api::AppState {
            db,
            route_tx: self.p.route_tx.clone(),
            policy: arc_swap::ArcSwap::from_pointee(policy),
            identity: HubIdentity {
                node_id: self.p.identity.node_id,
                edge_node_id: self.p.identity.edge_node_id,
                edge_addresses: self.p.identity.edge_addresses.clone(),
                edge_iroh_addresses: self.p.identity.edge_iroh_addresses.clone(),
                software_version: self.p.identity.software_version,
            },
            operator_api_key: self.p.operator_api_key.clone(),
            public_url: self.p.public_url.clone(),
            invite_lock: tokio::sync::Mutex::new(()),
            metrics,
            invite_hash_key: Arc::clone(&self.p.invite_hash_key),
            signed_request_nonces: api::new_nonce_cache(),
            tcp_port_lock: tokio::sync::Mutex::new(()),
            udp_port_lock: tokio::sync::Mutex::new(()),
            signer,
            refresh_limiter: api::new_refresh_limiter(),
            login_limiter: api::new_login_limiter(),
            live_edges: Arc::new(live_edges::LiveEdges::new()),
            liveness,
            web_enabled: self.p.web_enabled,
            port_reservations_tx: tokio::sync::broadcast::channel(64).0,
            ports_require_reservation: self.p.ports_require_reservation,
        });

        spawn_background_loops(&state);

        if let Some(cell) = self.control_handler_cell.as_ref() {
            let handler: Arc<dyn crate::edge::hub_client::ControlFrameHandler> =
                Arc::new(control::HubControlHandler::new(Arc::clone(&state)));
            if cell.set(handler).is_err() {
                tracing::warn!("hub control handler cell was already set; ignoring");
            }
        }

        if let Some(cell) = self.liveness_cell.as_ref()
            && cell.set(Arc::clone(&state.liveness)).is_err()
        {
            tracing::warn!("hub liveness cell was already set; ignoring");
        }

        let api_app = api::router(Arc::clone(&state))
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let health_app = api::health_router(Arc::clone(&state));

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

        let health_listener = tokio::net::TcpListener::bind(&self.p.health_listen_addr).await?;
        info!(listen = %self.p.health_listen_addr, "hub health/metrics listening");

        let link_shutdown = tokio_util::sync::CancellationToken::new();
        let link_task = match (self.p.link_listen_addr.clone(), self.p.link_psk.clone()) {
            (Some(addr), Some(psk)) => {
                let server = edge_link::EdgeLinkServer::bind(
                    &addr,
                    psk,
                    *self.p.identity.node_id.as_bytes(),
                    Arc::clone(&state),
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

/// Catches sessions whose `SessionRemoved` never arrived (crashed pod, OOM-kill).
async fn agent_liveness_prune_loop(state: Arc<api::AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // skip immediate first tick
    loop {
        tick.tick().await;
        let cutoff = towonel_common::time::now_ms().saturating_sub(api::AGENT_PRUNE_TTL_MS);
        let pruned = match state.liveness.prune(cutoff).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "liveness prune failed");
                continue;
            }
        };
        if pruned > 0 {
            tracing::debug!(pruned, "pruned stale liveness rows");
            if let Err(e) = api::rebuild_and_broadcast_routes(&state).await {
                tracing::warn!(error = %e, "route rebuild after liveness prune failed");
            }
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
}
