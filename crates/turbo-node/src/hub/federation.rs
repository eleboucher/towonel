use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};
use turbo_common::config_entry::SignedConfigEntry;
use turbo_common::identity::{PqPublicKey, TenantId};
use turbo_common::routing::RouteTable;
use turbo_common::time::now_ms;

use super::api::AppState;
use super::api::{OutboundFederation, internal_error, invalid_request, json_ok, unauthorized};
use super::db::FederatedTenant;

const FEDERATION_AUTH_DOMAIN: &str = "turbo-tunnel/federation/v1";
/// Same ±60s window we use for edge subscriber auth.
const FEDERATION_MAX_CLOCK_SKEW_MS: u64 = 60_000;
/// Cap on concurrently remembered (`node_id`, timestamp) pairs. Entries expire
/// naturally via TTL — this cap only matters under extreme traffic.
const MAX_NONCE_ENTRIES: u64 = 10_000;

/// Set of iroh `node_ids` we've discovered for our configured peers. Inbound
/// federation pushes whose signing key isn't in here get rejected.
pub type TrustedPeerSet = Arc<RwLock<HashSet<[u8; 32]>>>;

/// Nonce replay-protection cache. Keyed by (`node_id`, `ts_ms`); values are
/// unit. TTL is 2× the clock-skew window so any in-window retry is caught.
pub type NonceCache = moka::future::Cache<([u8; 32], u64), ()>;

/// Construct an empty `NonceCache` with the cap and TTL used by federation auth.
#[must_use]
pub fn new_nonce_cache() -> NonceCache {
    moka::future::Cache::builder()
        .max_capacity(MAX_NONCE_ENTRIES)
        .time_to_live(Duration::from_millis(FEDERATION_MAX_CLOCK_SKEW_MS * 2))
        .build()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPush {
    pub tenant_id: String,     // 64-hex
    pub pq_public_key: String, // base64url 1952B
    pub hostnames: Vec<String>,
    pub registered_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalPush {
    pub tenant_id: String, // 64-hex
    pub removed_at_ms: u64,
}

async fn authenticate_peer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<[u8; 32], &'static str> {
    let (node_id_bytes, ts_ms) = super::auth::verify_signature_header(
        headers,
        FEDERATION_AUTH_DOMAIN,
        FEDERATION_MAX_CLOCK_SKEW_MS,
    )?;

    if !state
        .federation
        .trusted_peers
        .read()
        .await
        .contains(&node_id_bytes)
    {
        return Err("signing node_id is not a configured federation peer");
    }

    let key = (node_id_bytes, ts_ms);
    let inserted = state
        .federation
        .nonces
        .entry(key)
        .or_insert_with(async {})
        .await
        .is_fresh();
    if !inserted {
        return Err("replayed (node_id, timestamp) pair");
    }

    Ok(node_id_bytes)
}

fn ok() -> Response {
    json_ok(serde_json::json!({"status": "ok"}))
}

/// `POST /v1/federation/tenants` — peer announces a tenant they redeemed.
pub async fn push_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<TenantPush>,
) -> Response {
    let peer = match authenticate_peer(&state, &headers).await {
        Ok(p) => p,
        Err(msg) => return unauthorized(msg),
    };

    let tenant_id: TenantId = match req.tenant_id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("tenant_id: {e}")),
    };
    let pq_public_key: PqPublicKey = match req.pq_public_key.parse() {
        Ok(p) => p,
        Err(e) => return invalid_request(format!("pq_public_key: {e}")),
    };
    if TenantId::derive(&pq_public_key) != tenant_id {
        return invalid_request("tenant_id does not equal sha256(pq_public_key)");
    }
    if req.hostnames.is_empty() {
        return invalid_request("at least one hostname required");
    }

    let federated = FederatedTenant {
        tenant_id,
        pq_public_key,
        hostnames: req.hostnames.clone(),
        registered_at_ms: req.registered_at_ms,
    };

    if let Err(e) = state.db.insert_federated_tenant(&federated, &peer).await {
        warn!(error = %e, "federation: failed to insert tenant");
        return internal_error();
    }

    {
        let mut policy = state.policy.write().await;
        if !policy.is_known_tenant(&federated.tenant_id) {
            policy.register_tenant(
                &federated.tenant_id,
                federated.pq_public_key.clone(),
                federated.hostnames.clone(),
            );
        }
    }

    info!(
        peer = %hex::encode(peer),
        tenant = %federated.tenant_id,
        "federation: applied tenant"
    );
    ok()
}

/// `POST /v1/federation/tenant-removals` — peer announces a removal.
pub async fn push_removal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<RemovalPush>,
) -> Response {
    let peer = match authenticate_peer(&state, &headers).await {
        Ok(p) => p,
        Err(msg) => return unauthorized(msg),
    };

    let tenant_id: TenantId = match req.tenant_id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("tenant_id: {e}")),
    };

    if let Err(e) = state.db.remove_tenant(&tenant_id, req.removed_at_ms).await {
        warn!(error = %e, "federation: failed to record removal");
        return internal_error();
    }
    {
        let mut policy = state.policy.write().await;
        policy.remove(&tenant_id);
    }
    info!(peer = %hex::encode(peer), tenant = %tenant_id, "federation: removed tenant");
    rebuild_and_broadcast(&state).await;
    ok()
}

/// `POST /v1/federation/entries` — peer pushes a signed entry. We verify
/// the tenant signature (same as `/v1/entries`) before persisting.
pub async fn push_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match authenticate_peer(&state, &headers).await {
        Ok(p) => p,
        Err(msg) => return unauthorized(msg),
    };

    let entry: SignedConfigEntry = match ciborium::from_reader(body.as_ref()) {
        Ok(e) => e,
        Err(e) => return invalid_request(format!("invalid CBOR body: {e}")),
    };

    let policy = state.policy.read().await;
    let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
        return invalid_request("entry references an unknown tenant; push tenant first");
    };
    let payload = match entry.verify(pq_pubkey) {
        Ok(p) => p,
        Err(e) => return invalid_request(format!("signature: {e}")),
    };
    if payload.version != 1 {
        return invalid_request(format!("unsupported payload version {}", payload.version));
    }
    drop(policy);

    let sequence = payload.sequence;
    if let Err(e) = state.db.insert(&entry, sequence).await {
        if super::db::is_unique_violation(&e) {
            return ok();
        }
        warn!(error = %e, "federation: failed to insert entry");
        return internal_error();
    }
    info!(
        peer = %hex::encode(peer),
        tenant = %entry.tenant_id,
        sequence,
        "federation: applied entry"
    );
    rebuild_and_broadcast(&state).await;
    ok()
}

async fn rebuild_and_broadcast(state: &Arc<super::api::AppState>) {
    let policy_snapshot = state.policy.read().await.clone();
    match state.db.get_all_entries().await {
        Ok(entries) => {
            let table = RouteTable::from_entries(&entries, &policy_snapshot);
            super::api::broadcast_routes(state, table).await;
        }
        Err(e) => warn!(error = %e, "federation: route rebuild failed"),
    }
}

/// Run forever pushing this hub's state to one peer. Discovers the peer's
/// iroh `node_id` via GET /v1/health, then loops over local DB state and
/// pushes unseen items. Idempotent — peers de-dupe.
pub async fn run_peer(
    peer_url: String,
    secret_key: iroh::SecretKey,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let peer_node_id = bootstrap_peer(&client, &peer_url, &state.federation.trusted_peers).await;
    info!(
        peer = %peer_url,
        node_id = %hex::encode(peer_node_id),
        "federation: peer bootstrapped"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        if let Err(e) = push_round(&client, &peer_url, &peer_node_id, &secret_key, &state).await {
            warn!(peer = %peer_url, error = %e, "federation: push round failed");
        }
    }
}

/// Resolve the peer's iroh `node_id` by polling its `/v1/health` until a
/// response is received. Backs off between attempts.
async fn bootstrap_peer(
    client: &reqwest::Client,
    peer_url: &str,
    trusted_peers: &TrustedPeerSet,
) -> [u8; 32] {
    let url = format!("{}/v1/health", peer_url.trim_end_matches('/'));
    let mut backoff = Duration::from_secs(1);
    loop {
        match fetch_node_id(client, &url).await {
            Ok(node_id) => {
                trusted_peers.write().await.insert(node_id);
                return node_id;
            }
            Err(e) => {
                warn!(peer = %peer_url, error = %e, "federation: bootstrap failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

async fn fetch_node_id(client: &reqwest::Client, health_url: &str) -> anyhow::Result<[u8; 32]> {
    #[derive(Deserialize)]
    struct HealthResponse {
        node_id: String,
    }
    let resp: HealthResponse = client
        .get(health_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    hex::FromHex::from_hex(&resp.node_id)
        .map_err(|e| anyhow::anyhow!("peer node_id is not 32 hex bytes: {e}"))
}

// Held read-guard covers the entire entries loop to avoid repeated lock/clone.
// `pub` (not `pub(crate)`) so federation_tests can drive it without the
// redundant_pub_crate lint firing on this privately-rooted module.
#[allow(clippy::significant_drop_tightening)]
pub async fn push_round(
    client: &reqwest::Client,
    peer_url: &str,
    peer_node_id: &[u8; 32],
    secret_key: &iroh::SecretKey,
    state: &AppState,
) -> anyhow::Result<()> {
    let super::db::FederationPushState {
        tenants: sent_tenants,
        removals: sent_removals,
        entry_seq: sent_seq,
    } = state.db.load_federation_push_state(peer_node_id).await?;

    for tenant in state.db.list_redeemed_tenants().await? {
        if sent_tenants.contains(&tenant.tenant_id) {
            continue;
        }
        let body = TenantPush {
            tenant_id: tenant.tenant_id.to_string(),
            pq_public_key: tenant.pq_public_key.to_string(),
            hostnames: tenant.hostnames,
            registered_at_ms: 0, // not tracked locally; peer doesn't care
        };
        post_signed(
            client,
            peer_url,
            "/v1/federation/tenants",
            secret_key,
            &body,
        )
        .await?;
        state
            .db
            .mark_federation_tenant_pushed(peer_node_id, &tenant.tenant_id)
            .await?;
    }

    for tid in state.db.list_tenant_removals().await? {
        if sent_removals.contains(&tid) {
            continue;
        }
        let body = RemovalPush {
            tenant_id: tid.to_string(),
            removed_at_ms: 0,
        };
        post_signed(
            client,
            peer_url,
            "/v1/federation/tenant-removals",
            secret_key,
            &body,
        )
        .await?;
        state
            .db
            .mark_federation_removal_pushed(peer_node_id, &tid)
            .await?;
    }

    let policy = state.policy.read().await;
    for (entry, sequence) in state.db.list_entries_with_sequence().await? {
        let last_sent = sent_seq.get(&entry.tenant_id).copied().unwrap_or(0);
        if sequence <= last_sent {
            continue;
        }
        // Skip entries whose tenant we no longer know locally — the peer
        // would reject them with "unknown tenant" anyway.
        if policy.pq_public_key(&entry.tenant_id).is_none() {
            continue;
        }
        let mut body = Vec::new();
        ciborium::into_writer(&entry, &mut body)?;
        post_signed_cbor(client, peer_url, "/v1/federation/entries", secret_key, body).await?;
        state
            .db
            .mark_federation_entry_pushed(peer_node_id, &entry.tenant_id, sequence)
            .await?;
    }
    Ok(())
}

fn signed_auth_header(secret_key: &iroh::SecretKey) -> String {
    let node_id = secret_key.public();
    let ts = now_ms();
    let message = format!("{FEDERATION_AUTH_DOMAIN}/{node_id}/{ts}");
    let sig = secret_key.sign(message.as_bytes());
    format!("Signature {node_id}.{ts}.{}", B64.encode(sig.to_bytes()))
}

fn peer_url_path(peer_url: &str, path: &str) -> String {
    format!("{}{path}", peer_url.trim_end_matches('/'))
}

/// Send `request` with the federation signature header and bail on non-2xx.
async fn send_signed(
    request: reqwest::RequestBuilder,
    secret_key: &iroh::SecretKey,
    url: &str,
) -> anyhow::Result<()> {
    let resp = request
        .header(
            reqwest::header::AUTHORIZATION,
            signed_auth_header(secret_key),
        )
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} returned {status}: {body}");
    }
    Ok(())
}

// T is not required to be Sync because we only pass &T to json().
#[allow(clippy::future_not_send)]
async fn post_signed<T: Serialize>(
    client: &reqwest::Client,
    peer_url: &str,
    path: &str,
    secret_key: &iroh::SecretKey,
    body: &T,
) -> anyhow::Result<()> {
    let url = peer_url_path(peer_url, path);
    send_signed(client.post(&url).json(body), secret_key, &url).await
}

const SYNC_PUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Fan out a `TenantPush` to every peer in `outbound`. Best-effort: a peer
/// that is unreachable or returns an error is logged and skipped, but the
/// caller still succeeds. The async `run_peer` loop retries failures on its
/// normal 15 s cadence, so this only closes the happy-path consistency gap.
pub async fn push_tenant_sync(
    client: &reqwest::Client,
    outbound: &OutboundFederation,
    body: &TenantPush,
) {
    for peer_url in &outbound.peer_urls {
        let push = post_signed(
            client,
            peer_url,
            "/v1/federation/tenants",
            &outbound.signing_key,
            body,
        );
        match tokio::time::timeout(SYNC_PUSH_TIMEOUT, push).await {
            Ok(Ok(())) => {
                info!(peer = %peer_url, tenant = %body.tenant_id, "federation: sync-pushed tenant");
            }
            Ok(Err(e)) => {
                warn!(peer = %peer_url, error = %e, "federation: sync tenant push failed");
            }
            Err(_) => {
                warn!(peer = %peer_url, "federation: sync tenant push timed out");
            }
        }
    }
}

async fn post_signed_cbor(
    client: &reqwest::Client,
    peer_url: &str,
    path: &str,
    secret_key: &iroh::SecretKey,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let url = peer_url_path(peer_url, path);
    let request = client
        .post(&url)
        .header(
            reqwest::header::CONTENT_TYPE,
            turbo_common::CBOR_CONTENT_TYPE,
        )
        .body(body);
    send_signed(request, secret_key, &url).await
}
