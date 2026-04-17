use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use serde::Serialize;
use tracing::warn;
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::TenantId;
use turbo_common::routing::RouteTable;

use turbo_common::time::now_ms;

use super::{
    AppState, PROTOCOL_VERSION, broadcast_routes, cbor_response, hostname_not_owned,
    internal_error, invalid_request, invalid_signature, json_ok, sequence_conflict,
    tenant_not_allowed, unsupported_version,
};

#[derive(Serialize)]
struct PostEntryResponse {
    status: &'static str,
    sequence: u64,
}

/// `POST /v1/entries`
///
/// Validation pipeline per protocol section 4.3:
/// 1. parse CBOR body
/// 2. tenant allowlist check (cheap -- fail before crypto)
/// 3. Ed25519 signature verification
/// 4. inner/outer `tenant_id` match
/// 5. payload version check
/// 6. hostname ownership check (for hostname ops only)
/// 7. sequence uniqueness (DB UNIQUE constraint)
pub(super) async fn post_entry(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let entry: SignedConfigEntry = match ciborium::from_reader(body.as_ref()) {
        Ok(e) => e,
        Err(e) => return invalid_request(format!("invalid CBOR body: {e}")),
    };

    let policy = state.policy.read().await;

    let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
        return tenant_not_allowed("tenant is not on the operator's allowlist");
    };

    let payload: ConfigPayload = match entry.verify(pq_pubkey) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "rejected entry: signature or tenant_id mismatch");
            return invalid_signature(format!("signature verification failed: {e}"));
        }
    };

    if payload.version != PROTOCOL_VERSION {
        return unsupported_version(format!(
            "payload version {} is not supported by this hub (expected {PROTOCOL_VERSION})",
            payload.version
        ));
    }

    if let ConfigOp::UpsertHostname { hostname } | ConfigOp::DeleteHostname { hostname } =
        &payload.op
    {
        if let Err(e) = turbo_common::hostname::validate_hostname(hostname) {
            return invalid_request(format!("invalid hostname `{hostname}`: {e}"));
        }
        if !policy.is_hostname_allowed(&payload.tenant_id, hostname) {
            return hostname_not_owned(format!(
                "tenant is not authorized for hostname: {hostname}"
            ));
        }
    }

    let sequence = payload.sequence;

    if let Err(e) = state.db.insert(&entry, sequence).await {
        if super::db::is_unique_violation(&e) {
            return sequence_conflict("sequence number already used by this tenant");
        }
        warn!(error = %e, "failed to insert entry");
        return internal_error();
    }

    let policy_snapshot = policy.clone();
    drop(policy);
    match state.db.get_all_entries().await {
        Ok(all_entries) => {
            let table = RouteTable::from_entries(&all_entries, &policy_snapshot);
            broadcast_routes(&state, table).await;
        }
        Err(e) => warn!(error = %e, "failed to rebuild routes after insert"),
    }

    cbor_response(&PostEntryResponse {
        status: "ok",
        sequence,
    })
}

pub(super) async fn get_tenant_entries(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    let entries = match state.db.get_entries(&tenant_id).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "failed to query entries");
            return internal_error();
        }
    };

    cbor_response(&entries)
}

pub(super) async fn health(State(state): State<Arc<AppState>>) -> Response {
    #[derive(Serialize)]
    struct HealthResponse<'a> {
        status: &'a str,
        node_id: &'a str,
        version: &'a str,
        protocol_version: u16,
    }
    json_ok(HealthResponse {
        status: "ok",
        node_id: &state.identity.node_id,
        version: state.identity.software_version,
        protocol_version: PROTOCOL_VERSION,
    })
}

pub(super) async fn list_edges(State(state): State<Arc<AppState>>) -> Response {
    #[derive(Serialize)]
    struct EdgeEntry<'a> {
        node_id: &'a str,
        healthy: bool,
        addresses: &'a [String],
    }
    #[derive(Serialize)]
    struct ListEdgesResponse<'a> {
        edges: Vec<EdgeEntry<'a>>,
    }

    let edges = state
        .identity
        .edge_node_id
        .as_deref()
        .map_or_else(Vec::new, |node_id| {
            vec![EdgeEntry {
                node_id,
                healthy: true,
                addresses: &state.identity.edge_addresses,
            }]
        });

    json_ok(ListEdgesResponse { edges })
}

/// `DELETE /v1/tenants/{tenant_id}` -- operator removes a tenant.
///
/// Signed entries from this tenant stay in the DB (the signatures are still
/// cryptographically valid), but the materialized route table stops
/// surfacing them because the tenant is dropped from the in-memory
/// `OwnershipPolicy`. The removal is recorded in `tenant_removals` so hub
/// restart still skips the tenant when rebuilding the policy.
pub(super) async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    if let Err(e) = state.db.remove_tenant(&tenant_id, now_ms()).await {
        warn!(error = %e, "failed to persist tenant removal");
        return internal_error();
    }

    let policy_snapshot = {
        let mut policy = state.policy.write().await;
        policy.remove(&tenant_id);
        policy.clone()
    };

    match state.db.get_all_entries().await {
        Ok(entries) => {
            let table = RouteTable::from_entries(&entries, &policy_snapshot);
            broadcast_routes(&state, table).await;
        }
        Err(e) => warn!(error = %e, "failed to rebuild routes after tenant removal"),
    }

    json_ok(serde_json::json!({
        "status": "removed",
        "tenant_id": tenant_id.to_string(),
    }))
}
