use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::config_entry::SignedConfigEntry;
use towonel_common::identity::{PqPublicKey, TenantId};
use tracing::{info, warn};

use super::super::db::{FederatedTenant, is_unique_violation};
use super::{AppState, internal_error, invalid_request, json_ok, rebuild_and_broadcast_routes};

/// Sentinel `source_peer_node_id` for resync-originated rows.
const RESYNC_SOURCE_PEER: [u8; 32] = [0xff; 32];

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SnapshotResponse {
    pub tenants: Vec<TenantSnapshot>,
    pub removals: Vec<RemovalSnapshot>,
    pub entries_cbor_b64: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct TenantSnapshot {
    pub tenant_id: String,
    pub pq_public_key: String,
    pub hostnames: Vec<String>,
    pub registered_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct RemovalSnapshot {
    pub tenant_id: String,
    pub removed_at_ms: u64,
}

pub(super) async fn snapshot(State(state): State<Arc<AppState>>) -> Response {
    let res: anyhow::Result<SnapshotResponse> = async {
        let federated = state.db.list_federated_tenants().await?;
        let redeemed = state.db.list_active_tenants().await?;
        let removals = state.db.list_tenant_removals().await?;
        let entries = state.db.get_all_entries().await?;

        let tenants = federated
            .into_iter()
            .map(|t| TenantSnapshot {
                tenant_id: t.tenant_id.to_string(),
                pq_public_key: t.pq_public_key.to_string(),
                hostnames: t.hostnames,
                registered_at_ms: t.registered_at_ms,
            })
            .chain(redeemed.into_iter().map(|r| TenantSnapshot {
                tenant_id: r.tenant_id.to_string(),
                pq_public_key: r.pq_public_key.to_string(),
                hostnames: r.hostnames,
                registered_at_ms: 0,
            }))
            .collect();

        let removals = removals
            .into_iter()
            .map(|tid| RemovalSnapshot {
                tenant_id: tid.to_string(),
                removed_at_ms: 0,
            })
            .collect();

        let mut entries_cbor_b64 = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut buf = Vec::new();
            ciborium::into_writer(&entry, &mut buf).context("cbor encode entry")?;
            entries_cbor_b64.push(B64.encode(&buf));
        }

        Ok(SnapshotResponse {
            tenants,
            removals,
            entries_cbor_b64,
        })
    }
    .await;

    match res {
        Ok(body) => json_ok(body),
        Err(e) => {
            warn!(error = %e, "admin snapshot failed");
            internal_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ResyncRequest {
    pub peer_url: String,
    pub peer_operator_key: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ResyncResponse {
    status: &'static str,
    tenants_ingested: usize,
    removals_ingested: usize,
    entries_ingested: usize,
    entries_skipped: usize,
}

enum ResyncError {
    BadRequest(String),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for ResyncError {
    fn from(e: E) -> Self {
        Self::Internal(e.into())
    }
}

fn bad<S: Into<String>>(s: S) -> ResyncError {
    ResyncError::BadRequest(s.into())
}

pub(super) async fn resync(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ResyncRequest>,
) -> Response {
    match do_resync(&state, &req).await {
        Ok(body) => {
            info!(peer = %req.peer_url, ?body, "resync complete");
            json_ok(body)
        }
        Err(ResyncError::BadRequest(m)) => invalid_request(m),
        Err(ResyncError::Internal(e)) => {
            warn!(error = %e, "resync failed");
            internal_error()
        }
    }
}

/// Reject SSRF-prone URLs: require https scheme and refuse IP-literal hosts
/// that point at loopback, link-local, private, or unspecified ranges. Does
/// not guard against DNS names resolving to private IPs — operators should
/// point resync at public peers only. `allow_loopback` is enabled only by
/// integration-test scaffolding.
fn validate_resync_url(raw: &str, allow_loopback: bool) -> Result<(), ResyncError> {
    let parsed = url::Url::parse(raw).map_err(|e| bad(format!("peer_url is not a URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "https" && !(allow_loopback && scheme == "http") {
        return Err(bad("peer_url must use https://"));
    }
    let Some(host) = parsed.host() else {
        return Err(bad("peer_url is missing a host"));
    };
    match host {
        url::Host::Ipv4(ip) => {
            if allow_loopback && ip.is_loopback() {
                return Ok(());
            }
            if ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
            {
                return Err(bad("peer_url host is in a non-routable IPv4 range"));
            }
        }
        url::Host::Ipv6(ip) => {
            if allow_loopback && ip.is_loopback() {
                return Ok(());
            }
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return Err(bad("peer_url host is in a non-routable IPv6 range"));
            }
            let seg = ip.segments()[0];
            if (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80 {
                return Err(bad("peer_url host is in a non-routable IPv6 range"));
            }
        }
        url::Host::Domain(name) => {
            let lower = name.to_ascii_lowercase();
            if !allow_loopback && (lower == "localhost" || lower.ends_with(".localhost")) {
                return Err(bad("peer_url host resolves to loopback"));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn do_resync(
    state: &Arc<AppState>,
    req: &ResyncRequest,
) -> Result<ResyncResponse, ResyncError> {
    validate_resync_url(&req.peer_url, state.allow_loopback_peers)?;

    let url = format!(
        "{}/v1/admin/federation/snapshot",
        req.peer_url.trim_end_matches('/')
    );
    let resp = state
        .http_client
        .get(&url)
        .bearer_auth(&req.peer_operator_key)
        .send()
        .await
        .map_err(|e| bad(format!("peer unreachable: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(bad(format!("peer returned {status}: {body}")));
    }
    let snapshot: SnapshotResponse = resp
        .json()
        .await
        .map_err(|e| bad(format!("invalid peer snapshot: {e}")))?;

    let mut parsed_tenants = Vec::with_capacity(snapshot.tenants.len());
    for t in &snapshot.tenants {
        let tenant_id: TenantId = t
            .tenant_id
            .parse()
            .map_err(|e| bad(format!("snapshot tenant_id: {e}")))?;
        let pq_public_key: PqPublicKey = t
            .pq_public_key
            .parse()
            .map_err(|e| bad(format!("snapshot pq_public_key: {e}")))?;
        if TenantId::derive(&pq_public_key) != tenant_id {
            return Err(bad("snapshot tenant_id does not match pq_public_key"));
        }
        let federated = FederatedTenant {
            tenant_id,
            pq_public_key,
            hostnames: t.hostnames.clone(),
            registered_at_ms: t.registered_at_ms,
        };
        state
            .db
            .insert_federated_tenant(&federated, &RESYNC_SOURCE_PEER)
            .await?;
        parsed_tenants.push(federated);
    }

    {
        let mut policy = state.policy.write().await;
        for t in &parsed_tenants {
            if !policy.is_known_tenant(&t.tenant_id) {
                policy.register_tenant(&t.tenant_id, t.pq_public_key.clone(), t.hostnames.clone());
            }
        }
    }

    for r in &snapshot.removals {
        let tid: TenantId = r
            .tenant_id
            .parse()
            .map_err(|e| bad(format!("snapshot removal tenant_id: {e}")))?;
        state.db.remove_tenant(&tid, r.removed_at_ms).await?;
        state.policy.write().await.remove(&tid);
    }

    let pq_lookup: HashMap<TenantId, &PqPublicKey> = parsed_tenants
        .iter()
        .map(|t| (t.tenant_id, &t.pq_public_key))
        .collect();

    let mut entries_ingested = 0usize;
    let mut entries_skipped = 0usize;
    for b64 in &snapshot.entries_cbor_b64 {
        let bytes = B64
            .decode(b64)
            .map_err(|e| bad(format!("snapshot entry: base64 decode: {e}")))?;
        let entry: SignedConfigEntry = ciborium::from_reader(bytes.as_slice())
            .map_err(|e| bad(format!("snapshot entry: cbor decode: {e}")))?;
        let Some(pq_pubkey) = pq_lookup.get(&entry.tenant_id) else {
            entries_skipped += 1;
            continue;
        };
        let payload = entry
            .verify(pq_pubkey)
            .map_err(|e| bad(format!("snapshot entry signature: {e}")))?;
        match state.db.insert(&entry, payload.sequence).await {
            Ok(()) => entries_ingested += 1,
            Err(e) if is_unique_violation(&e) => entries_skipped += 1,
            Err(e) => return Err(ResyncError::Internal(e)),
        }
    }

    if let Err(e) = rebuild_and_broadcast_routes(state).await {
        warn!(error = %e, "resync: route rebuild failed");
    }

    Ok(ResyncResponse {
        status: "ok",
        tenants_ingested: parsed_tenants.len(),
        removals_ingested: snapshot.removals.len(),
        entries_ingested,
        entries_skipped,
    })
}
