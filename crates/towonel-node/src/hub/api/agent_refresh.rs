use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tracing::warn;

use towonel_common::edge_cred::Kid;
use towonel_common::identity::{AgentId, TenantId};
use towonel_common::routing::RouteTable;

use super::bootstrap::mint_edge_cred;
use super::{
    AGENT_REFRESH_MAX_PER_MIN, AppState, MAX_CLOCK_SKEW_MS, error_response, internal_error,
    invalid_request, json_ok, unauthorized,
};
use crate::hub::auth::verify_signature_header;

const REFRESH_AUTH_DOMAIN: &str = "towonel/agent-refresh/v1";

#[derive(Debug, Deserialize)]
struct RefreshBody {
    tenant_id: TenantId,
    agent_id: AgentId,
}

#[derive(Debug, Serialize)]
struct RefreshResponse {
    status: &'static str,
    kid: Kid,
    edge_cred_b64: String,
    edge_cred_sig_b64: String,
}

pub(super) async fn post_refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (node_id_bytes, ts_ms) = match verify_signature_header(
        &headers,
        REFRESH_AUTH_DOMAIN,
        MAX_CLOCK_SKEW_MS,
        body.as_ref(),
    ) {
        Ok(v) => v,
        Err(msg) => return unauthorized(msg),
    };

    let fresh = state
        .signed_request_nonces
        .entry((node_id_bytes, ts_ms))
        .or_insert_with(async {})
        .await
        .is_fresh();
    if !fresh {
        return unauthorized("replayed refresh signature");
    }

    let req: RefreshBody = match ciborium::from_reader(body.as_ref()) {
        Ok(b) => b,
        Err(e) => return invalid_request(format!("invalid CBOR body: {e}")),
    };

    if req.agent_id.as_bytes() != &node_id_bytes {
        return unauthorized("signature node_id does not match body agent_id");
    }

    // Rate-limit BEFORE any DB / RouteTable work so a sig-holder for a known
    // agent_id can't drive `db.get_entries` + RouteTable rebuild on every hit.
    if !check_rate_limit(&state.refresh_limiter, node_id_bytes).await {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("more than {AGENT_REFRESH_MAX_PER_MIN} refreshes per minute for this agent"),
        );
    }

    if !state.policy.load().is_known_tenant(&req.tenant_id) {
        return unauthorized("tenant is not registered with this hub");
    }

    match agent_is_signed(&state, &req.tenant_id, &req.agent_id).await {
        Ok(true) => {}
        Ok(false) => return unauthorized("agent is not in signed_agents for this tenant"),
        Err(e) => {
            warn!(error = %e, "failed to check signed_agents");
            return internal_error();
        }
    }

    let (kid, edge_cred_b64, edge_cred_sig_b64) =
        match mint_edge_cred(&state, &req.agent_id.to_string(), &req.tenant_id) {
            Ok(t) => t,
            Err(resp) => return *resp,
        };

    json_ok(RefreshResponse {
        status: "ok",
        kid,
        edge_cred_b64,
        edge_cred_sig_b64,
    })
}

async fn agent_is_signed(
    state: &AppState,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> anyhow::Result<bool> {
    let entries = state.db.get_entries(tenant_id).await?;
    let policy = state.policy.load_full();
    let table = RouteTable::from_entries_with_liveness(&entries, &policy, None);
    Ok(table.signed_agents().contains(agent_id))
}

async fn check_rate_limit(limiter: &super::RefreshLimiter, agent_id: [u8; 32]) -> bool {
    let counter: Arc<AtomicU32> = limiter
        .get_with(agent_id, async { Arc::new(AtomicU32::new(0)) })
        .await;
    counter.fetch_add(1, Ordering::Relaxed) < AGENT_REFRESH_MAX_PER_MIN
}
