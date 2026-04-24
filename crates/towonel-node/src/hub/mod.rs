pub mod api;
pub mod auth;
pub mod db;
pub mod metrics;

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
use towonel_common::identity::write_key_file;
use towonel_common::invite::InviteHashKey;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;
use tracing::info;

/// Length of a freshly generated operator API key in bytes (before base64).
/// 32 bytes = 256 bits, base64url-encoded without padding = 43 chars.
const OPERATOR_KEY_BYTES: usize = 32;

/// Env var carrying the 32-byte hex-encoded key used to keyed-hash invite
/// secrets. Required at hub startup: losing or rotating it invalidates every
/// outstanding invite. Generate with `openssl rand -hex 32`.
pub const INVITE_HASH_KEY_ENV: &str = "TOWONEL_INVITE_HASH_KEY";

/// Read the invite-hash key from `TOWONEL_INVITE_HASH_KEY` or fail with a
/// message that tells the operator how to generate one.
pub fn load_invite_hash_key() -> anyhow::Result<InviteHashKey> {
    let hex = std::env::var(INVITE_HASH_KEY_ENV).map_err(|_| {
        anyhow::anyhow!(
            "{INVITE_HASH_KEY_ENV} is not set — generate one with \
             `openssl rand -hex 32` and export it before starting the hub"
        )
    })?;
    InviteHashKey::from_hex(&hex)
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
        // OS RNG failures are unrecoverable on any supported platform.
        #[allow(clippy::expect_used)]
        getrandom::fill(&mut bytes).expect("OS RNG failed");
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
    pub public_url: String,
}

/// The hub: accepts signed config entries from tenants via an HTTP management
/// API, persists them to `SQLite`, and serves config updates to edges.
pub struct Hub {
    p: HubParams,
}

fn spawn_background_loops(state: &Arc<api::AppState>) {
    tokio::spawn(refresh_metrics_loop(Arc::clone(state)));
    tokio::spawn(agent_liveness_prune_loop(Arc::clone(state)));
}

impl Hub {
    pub const fn new(params: HubParams) -> Self {
        Self { p: params }
    }

    /// Run the hub. Opens the DB and starts the HTTP management API.
    pub async fn run(&self) -> anyhow::Result<()> {
        let db_url = self.p.database.connection_url()?;
        info!(
            listen = %self.p.listen_addr,
            db = %crate::config::redact_db_url(&db_url),
            max_open = self.p.database.max_open(),
            max_idle = self.p.database.max_idle(),
            "hub starting"
        );

        let db = db::Db::open(
            &db_url,
            self.p.database.max_open(),
            self.p.database.max_idle(),
        )
        .await?;

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

        // Initial broadcast: intersect with surviving liveness rows from the
        // previous process, so edges don't briefly see zombie agents after
        // a hub restart. The prune loop sweeps stale rows every 30 s;
        // anything still present at boot is either a currently-alive pod
        // (about to bump its heartbeat) or within the TTL window.
        let initial_cutoff = towonel_common::time::now_ms().saturating_sub(api::AGENT_LIVE_TTL_MS);
        let live = db.live_agents(initial_cutoff).await
            .inspect_err(|e| tracing::error!(error = %e, "failed to load live agents at startup; initial route table will be empty"))
            .unwrap_or_default();
        match db.get_all_entries().await {
            Ok(entries) => {
                let table = RouteTable::from_entries_with_liveness(&entries, &policy, Some(&live));
                // No edges have subscribed yet at startup; the broadcast
                // just primes the channel buffer.
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
                software_version: self.p.identity.software_version,
            },
            operator_api_key: self.p.operator_api_key.clone(),
            public_url: self.p.public_url.clone(),
            invite_lock: tokio::sync::Mutex::new(()),
            metrics,
            invite_hash_key: Arc::clone(&self.p.invite_hash_key),
            heartbeat_nonces: api::new_nonce_cache(),
            edge_sub_nonces: api::new_nonce_cache(),
        });

        spawn_background_loops(&state);

        let api_app = api::router(Arc::clone(&state))
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let health_app = api::health_router(Arc::clone(&state));

        let api_listener = tokio::net::TcpListener::bind(&self.p.listen_addr).await?;
        info!(listen = %self.p.listen_addr, "hub API listening");

        let health_listener = tokio::net::TcpListener::bind(&self.p.health_listen_addr).await?;
        info!(listen = %self.p.health_listen_addr, "hub health/metrics listening");

        tokio::select! {
            res = axum::serve(api_listener, api_app) => res?,
            res = axum::serve(health_listener, health_app) => res?,
        }
        Ok(())
    }
}

/// Periodically prune stale `agent_liveness` rows and trigger a route
/// rebuild if any row was dropped. Keeps the edge view fresh even when a pod
/// dies without sending SIGTERM (OOM-kill, node failure).
async fn agent_liveness_prune_loop(state: Arc<api::AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // skip immediate first tick
    loop {
        tick.tick().await;
        let cutoff = towonel_common::time::now_ms().saturating_sub(api::AGENT_PRUNE_TTL_MS);
        let pruned = match state.db.prune_agent_liveness(cutoff).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "agent_liveness prune failed");
                continue;
            }
        };
        if pruned > 0 {
            tracing::debug!(pruned, "pruned stale agent_liveness rows");
            if let Err(e) = api::rebuild_and_broadcast_routes(&state).await {
                tracing::warn!(error = %e, "route rebuild after liveness prune failed");
            }
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
