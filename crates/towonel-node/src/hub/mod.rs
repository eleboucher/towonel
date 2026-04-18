pub mod api;
pub mod auth;
pub mod db;
pub mod federation;
pub mod metrics;
pub mod peer_status;

#[cfg(test)]
mod admin_tests;
#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod federation_tests;
#[cfg(test)]
mod observability_tests;
#[cfg(test)]
mod test_helpers;

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use towonel_common::identity::write_key_file;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;
use tracing::info;

/// Length of a freshly generated operator API key in bytes (before base64).
/// 32 bytes = 256 bits, base64url-encoded without padding = 43 chars.
const OPERATOR_KEY_BYTES: usize = 32;

/// Load the operator API key from `path`, or generate a new random one and
/// save it with 0o600 permissions.
pub fn load_or_generate_operator_key(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("operator API key file {} is empty", path.display());
        }
        Ok(trimmed)
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
        Ok(key)
    }
}

/// Operational identity information that the hub exposes via `/v1/health`
/// and `/v1/edges`. Constructed once at startup in `main`.
pub struct HubIdentity {
    pub node_id: String,
    pub edge_node_id: Option<String>,
    pub edge_addresses: Vec<String>,
    pub software_version: &'static str,
}

/// Everything the hub needs to start, grouped to keep the constructor lean.
pub struct HubParams {
    pub listen_addr: String,
    pub database: crate::config::DatabaseConfig,
    pub route_tx: broadcast::Sender<RouteTable>,
    pub static_policy: OwnershipPolicy,
    pub identity: HubIdentity,
    pub operator_api_key: String,
    pub public_url: String,
    pub peers: Vec<crate::config::FederationPeer>,
    pub secret_key: iroh::SecretKey,
    pub dns_webhook_url: Option<String>,
    pub sync_invite_redeem: bool,
}

/// The hub: accepts signed config entries from tenants via an HTTP management
/// API, persists them to `SQLite`, and serves config updates to edges.
pub struct Hub {
    p: HubParams,
}

impl Hub {
    pub const fn new(params: HubParams) -> Self {
        Self { p: params }
    }

    /// Run the hub. Opens the `SQLite` database and starts the HTTP management API.
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
        for redeemed in db.list_redeemed_tenants().await? {
            if removed.contains(&redeemed.tenant_id) {
                continue;
            }
            policy.register_tenant(
                &redeemed.tenant_id,
                redeemed.pq_public_key,
                redeemed.hostnames,
            );
        }
        for federated in db.list_federated_tenants().await? {
            if removed.contains(&federated.tenant_id)
                || policy.is_known_tenant(&federated.tenant_id)
            {
                continue;
            }
            policy.register_tenant(
                &federated.tenant_id,
                federated.pq_public_key,
                federated.hostnames,
            );
        }

        match db.get_all_entries().await {
            Ok(entries) => {
                let table = RouteTable::from_entries(&entries, &policy);
                let _ = self.p.route_tx.send(table);
            }
            Err(e) => tracing::warn!(error = %e, "initial route broadcast skipped"),
        }

        let trusted_peers = init_trusted_peers(&self.p.peers).await?;
        let peer_urls: Vec<String> = self.p.peers.iter().map(|p| p.url.clone()).collect();
        let outbound = (!peer_urls.is_empty()).then(|| api::OutboundFederation {
            peer_urls: peer_urls.clone(),
            signing_key: iroh::SecretKey::from(self.p.secret_key.to_bytes()),
        });
        let metrics = metrics::HubMetrics::new();
        let peer_statuses = peer_status::new_peer_status_map(&peer_urls);
        let state = Arc::new(api::AppState {
            db,
            route_tx: self.p.route_tx.clone(),
            policy: Arc::new(RwLock::new(policy)),
            http_client: reqwest::Client::new(),
            identity: HubIdentity {
                node_id: self.p.identity.node_id.clone(),
                edge_node_id: self.p.identity.edge_node_id.clone(),
                edge_addresses: self.p.identity.edge_addresses.clone(),
                software_version: self.p.identity.software_version,
            },
            operator_api_key: self.p.operator_api_key.clone(),
            public_url: self.p.public_url.clone(),
            invite_lock: tokio::sync::Mutex::new(()),
            federation: api::FederationState {
                trusted_peers: trusted_peers.clone(),
                nonces: federation::new_nonce_cache(),
                outbound,
                sync_invite_redeem: self.p.sync_invite_redeem,
            },
            dns_webhook_url: self.p.dns_webhook_url.clone(),
            prev_hostnames: RwLock::new(std::collections::HashSet::new()),
            metrics,
            peer_statuses,
        });

        for peer in &self.p.peers {
            let peer_cfg = peer.clone();
            let sk = iroh::SecretKey::from(self.p.secret_key.to_bytes());
            let state_for_peer = state.clone();
            tokio::spawn(async move {
                if let Err(e) = federation::run_peer(peer_cfg, sk, state_for_peer).await {
                    tracing::error!(error = %e, "federation peer task exited");
                }
            });
        }

        tokio::spawn(refresh_metrics_loop(state.clone()));

        let app = api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();

        let listener = tokio::net::TcpListener::bind(&self.p.listen_addr).await?;
        info!(listen = %self.p.listen_addr, "hub API listening");

        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Decode and validate the pinned `node_id` on a [`crate::config::FederationPeer`].
/// Returns `None` when the operator didn't pin one (bootstrap will discover it
/// at cost of an MITM window, already warned at config load).
fn peer_pinned_node_id(peer: &crate::config::FederationPeer) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(hex_id) = peer.node_id.as_deref() else {
        return Ok(None);
    };
    let bytes: [u8; 32] = hex::FromHex::from_hex(hex_id)
        .map_err(|e| anyhow::anyhow!("peer {} node_id is not 32 hex bytes: {e}", peer.url))?;
    Ok(Some(bytes))
}

/// Seed the `trusted_peers` set with any operator-pinned peer `node_ids`, so
/// inbound federation pushes are accepted immediately without waiting for the
/// per-peer bootstrap task to probe `/v1/health`.
async fn init_trusted_peers(
    peers: &[crate::config::FederationPeer],
) -> anyhow::Result<federation::TrustedPeerSet> {
    let trusted = Arc::new(RwLock::new(std::collections::HashSet::new()));
    let mut set = trusted.write().await;
    for peer in peers {
        if let Some(pinned) = peer_pinned_node_id(peer)? {
            set.insert(pinned);
        }
    }
    drop(set);
    Ok(trusted)
}

/// Periodically refresh metrics gauges derived from DB/policy state.
/// Keeps `invites_pending` and `tenants_total` within ~15 s of the truth
/// without instrumenting every code path that might change them.
async fn refresh_metrics_loop(state: Arc<api::AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tick.tick().await;
        match state.db.list_invites().await {
            Ok(rows) => {
                let pending = rows
                    .iter()
                    .filter(|r| matches!(r.status, db::InviteStatus::Pending))
                    .count();
                state
                    .metrics
                    .invites_pending
                    .set(i64::try_from(pending).unwrap_or(i64::MAX));
            }
            Err(e) => tracing::debug!(error = %e, "metrics refresh: list_invites failed"),
        }
        let tenants = state.policy.read().await.iter_patterns().count();
        state
            .metrics
            .tenants_total
            .set(i64::try_from(tenants).unwrap_or(i64::MAX));
    }
}
