use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
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
use super::db::FederatedTenant;

const FEDERATION_AUTH_DOMAIN: &str = "turbo-tunnel/federation/v1";
/// Same ±60s window we use for edge subscriber auth.
const FEDERATION_MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Set of iroh node_ids we've discovered for our configured peers. Inbound
/// federation pushes whose signing key isn't in here get rejected.
pub type TrustedPeerSet = Arc<RwLock<HashSet<[u8; 32]>>>;

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
    let auth = headers
        .get(header::AUTHORIZATION)
        .ok_or("missing Authorization header")?
        .to_str()
        .map_err(|_| "malformed Authorization header")?;
    let body = auth
        .strip_prefix("Signature ")
        .ok_or("Authorization must be `Signature <node_id>.<ts>.<sig>`")?;

    let mut parts = body.splitn(3, '.');
    let node_id_hex = parts.next().ok_or("missing node_id segment")?;
    let ts_str = parts.next().ok_or("missing timestamp segment")?;
    let sig_b64 = parts.next().ok_or("missing signature segment")?;

    let node_id_bytes: [u8; 32] = hex::decode(node_id_hex)
        .map_err(|_| "node_id is not hex")?
        .try_into()
        .map_err(|_| "node_id must be 32 bytes")?;

    let ts_ms: u64 = ts_str.parse().map_err(|_| "timestamp is not a u64")?;
    if now_ms().abs_diff(ts_ms) > FEDERATION_MAX_CLOCK_SKEW_MS {
        return Err("timestamp outside freshness window");
    }

    let sig_arr: [u8; 64] = B64
        .decode(sig_b64)
        .map_err(|_| "signature is not base64url")?
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;

    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&node_id_bytes)
        .map_err(|_| "node_id is not a valid Ed25519 public key")?;
    let message = format!("{FEDERATION_AUTH_DOMAIN}/{node_id_hex}/{ts_ms}");
    pubkey
        .verify_strict(
            message.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_arr),
        )
        .map_err(|_| "signature does not verify")?;

    if !state.trusted_peers.read().await.contains(&node_id_bytes) {
        return Err("signing node_id is not a configured federation peer");
    }

    {
        const MAX_NONCE_ENTRIES: usize = 10_000;
        let now = now_ms();
        let evict_before = now.saturating_sub(FEDERATION_MAX_CLOCK_SKEW_MS * 2);
        let mut nonces = state.federation_nonces.lock().await;
        nonces.retain(|&(_, ts)| ts > evict_before);
        if nonces.len() >= MAX_NONCE_ENTRIES {
            return Err("nonce cache full — too many requests in window");
        }
        if !nonces.insert((node_id_bytes, ts_ms)) {
            return Err("replayed (node_id, timestamp) pair");
        }
    }

    Ok(node_id_bytes)
}

fn unauthorized(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        axum::Json(serde_json::json!({"error": {"code": "unauthorized", "message": msg}})),
    )
        .into_response()
}

fn invalid(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        axum::Json(serde_json::json!({
            "error": {"code": "invalid_request", "message": msg.into()}
        })),
    )
        .into_response()
}

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        axum::Json(serde_json::json!({"error": {"code": "internal", "message": "internal error"}})),
    )
        .into_response()
}

fn ok() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        axum::Json(serde_json::json!({"status": "ok"})),
    )
        .into_response()
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
        Err(e) => return invalid(format!("tenant_id: {e}")),
    };
    let pq_public_key: PqPublicKey = match req.pq_public_key.parse() {
        Ok(p) => p,
        Err(e) => return invalid(format!("pq_public_key: {e}")),
    };
    if TenantId::derive(&pq_public_key) != tenant_id {
        return invalid("tenant_id does not equal sha256(pq_public_key)");
    }
    if req.hostnames.is_empty() {
        return invalid("at least one hostname required");
    }

    let federated = FederatedTenant {
        tenant_id,
        pq_public_key,
        hostnames: req.hostnames.clone(),
        registered_at_ms: req.registered_at_ms,
    };

    if let Err(e) = state.db.insert_federated_tenant(&federated, &peer).await {
        warn!(error = %e, "federation: failed to insert tenant");
        return internal();
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
        Err(e) => return invalid(format!("tenant_id: {e}")),
    };

    if let Err(e) = state.db.remove_tenant(&tenant_id, req.removed_at_ms).await {
        warn!(error = %e, "federation: failed to record removal");
        return internal();
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
        Err(e) => return invalid(format!("invalid CBOR body: {e}")),
    };

    let policy = state.policy.read().await;
    let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
        return invalid("entry references an unknown tenant; push tenant first");
    };
    let payload = match entry.verify(pq_pubkey) {
        Ok(p) => p,
        Err(e) => return invalid(format!("signature: {e}")),
    };
    if payload.version != 1 {
        return invalid(format!("unsupported payload version {}", payload.version));
    }
    drop(policy);

    let sequence = payload.sequence;
    if let Err(e) = state.db.insert(&entry, sequence).await {
        if e.to_string().contains("UNIQUE constraint") {
            return ok();
        }
        warn!(error = %e, "federation: failed to insert entry");
        return internal();
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
/// iroh node_id via GET /v1/health, then loops over local DB state and
/// pushes unseen items. Idempotent — peers de-dupe.
pub async fn run_peer(
    peer_url: String,
    secret_key: iroh::SecretKey,
    state: Arc<AppState>,
    trusted_peers: TrustedPeerSet,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let peer_node_id = bootstrap_peer(&client, &peer_url, &trusted_peers).await;
    info!(
        peer = %peer_url,
        node_id = %hex::encode(peer_node_id),
        "federation: peer bootstrapped"
    );

    let mut sent_tenants: HashSet<TenantId> = HashSet::new();
    let mut sent_removals: HashSet<TenantId> = HashSet::new();
    let mut sent_seq: HashMap<TenantId, u64> = HashMap::new();

    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        if let Err(e) = push_round(
            &client,
            &peer_url,
            &secret_key,
            &state,
            &mut sent_tenants,
            &mut sent_removals,
            &mut sent_seq,
        )
        .await
        {
            warn!(peer = %peer_url, error = %e, "federation: push round failed");
        }
    }
}

/// Resolve the peer's iroh node_id by polling its `/v1/health` until a
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
    let bytes = hex::decode(&resp.node_id)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer node_id is not 32 bytes"))
}

async fn push_round(
    client: &reqwest::Client,
    peer_url: &str,
    secret_key: &iroh::SecretKey,
    state: &AppState,
    sent_tenants: &mut HashSet<TenantId>,
    sent_removals: &mut HashSet<TenantId>,
    sent_seq: &mut HashMap<TenantId, u64>,
) -> anyhow::Result<()> {
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
        sent_tenants.insert(tenant.tenant_id);
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
        sent_removals.insert(tid);
    }

    let entries = state.db.get_all_entries().await?;
    let policy = state.policy.read().await;
    for entry in entries {
        let last_sent = sent_seq.get(&entry.tenant_id).copied().unwrap_or(0);
        let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
            continue;
        };
        let Ok(payload) = entry.verify(pq_pubkey) else {
            continue;
        };
        if payload.sequence <= last_sent {
            continue;
        }
        let mut body = Vec::new();
        ciborium::into_writer(&entry, &mut body)?;
        post_signed_cbor(client, peer_url, "/v1/federation/entries", secret_key, body).await?;
        sent_seq.insert(entry.tenant_id, payload.sequence);
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

async fn post_signed<T: Serialize>(
    client: &reqwest::Client,
    peer_url: &str,
    path: &str,
    secret_key: &iroh::SecretKey,
    body: &T,
) -> anyhow::Result<()> {
    let url = format!("{}{path}", peer_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            signed_auth_header(secret_key),
        )
        .json(body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} returned {status}: {body}");
    }
    Ok(())
}

async fn post_signed_cbor(
    client: &reqwest::Client,
    peer_url: &str,
    path: &str,
    secret_key: &iroh::SecretKey,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let url = format!("{}{path}", peer_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            signed_auth_header(secret_key),
        )
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} returned {status}: {body}");
    }
    Ok(())
}
