pub mod api;
pub mod auth;
pub mod db;
pub mod federation;

#[cfg(test)]
mod api_tests;

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tracing::info;
use turbo_common::identity::write_key_file;
use turbo_common::ownership::OwnershipPolicy;
use turbo_common::routing::RouteTable;

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
    pub db_path: std::path::PathBuf,
    pub route_tx: broadcast::Sender<RouteTable>,
    pub static_policy: OwnershipPolicy,
    pub identity: HubIdentity,
    pub operator_api_key: String,
    pub public_url: String,
    pub peer_urls: Vec<String>,
    pub secret_key: iroh::SecretKey,
    pub dns_webhook_url: Option<String>,
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
        info!(
            listen = %self.p.listen_addr,
            db = %self.p.db_path.display(),
            "hub starting"
        );

        let db = db::Db::open(&self.p.db_path).await?;

        let removed: Vec<turbo_common::identity::TenantId> = db.list_tenant_removals().await?;

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

        let trusted_peers = Arc::new(RwLock::new(std::collections::HashSet::new()));
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
                nonces: tokio::sync::Mutex::new(std::collections::HashSet::new()),
            },
            dns_webhook_url: self.p.dns_webhook_url.clone(),
            prev_hostnames: RwLock::new(std::collections::HashSet::new()),
        });

        for peer_url in &self.p.peer_urls {
            let url = peer_url.clone();
            let sk = iroh::SecretKey::from(self.p.secret_key.to_bytes());
            let state_for_peer = state.clone();
            let trusted = trusted_peers.clone();
            tokio::spawn(async move {
                if let Err(e) = federation::run_peer(url, sk, state_for_peer, trusted).await {
                    tracing::error!(error = %e, "federation peer task exited");
                }
            });
        }

        let app = api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();

        let listener = tokio::net::TcpListener::bind(&self.p.listen_addr).await?;
        info!(listen = %self.p.listen_addr, "hub API listening");

        axum::serve(listener, app).await?;
        Ok(())
    }
}
