//! `POST /v1/agent/heartbeat` -- pods call this every ~20s so the hub can
//! reap stale agents from the route table. The signature header proves the
//! caller holds the ephemeral iroh key authorized earlier via `UpsertAgent`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::identity::{AgentId, TenantId};
use tracing::warn;

use towonel_common::time::now_ms;

use super::{AppState, internal_error, invalid_request, json_ok, unauthorized};
use crate::hub::auth::verify_signature_header;

/// Domain string prepended to the signed message. Keyed per-endpoint so a
/// signature captured elsewhere can't be replayed here.
const HEARTBEAT_AUTH_DOMAIN: &str = "towonel/agent-heartbeat/v1";

/// Generous clock-skew tolerance -- pods may be far from NTP.
const HEARTBEAT_MAX_CLOCK_SKEW_MS: u64 = 60_000;

#[derive(Debug, Deserialize)]
struct HeartbeatBody {
    tenant_id: TenantId,
    agent_id: AgentId,
}

#[derive(Debug, Serialize)]
struct HeartbeatResponse {
    status: &'static str,
    next_interval_secs: u64,
}

pub(super) async fn post_heartbeat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Body-bound signature: verifier hashes the exact bytes we then decode.
    // This prevents an attacker with a captured header from substituting a
    // different tenant_id within the clock-skew window.
    let node_id_bytes = match verify_signature_header(
        &headers,
        HEARTBEAT_AUTH_DOMAIN,
        HEARTBEAT_MAX_CLOCK_SKEW_MS,
        body.as_ref(),
    ) {
        Ok((id, _)) => id,
        Err(msg) => return unauthorized(msg),
    };

    let req: HeartbeatBody = match ciborium::from_reader(body.as_ref()) {
        Ok(b) => b,
        Err(e) => return invalid_request(format!("invalid CBOR body: {e}")),
    };

    if req.agent_id.as_bytes() != &node_id_bytes {
        return unauthorized("signature node_id does not match body agent_id");
    }

    let policy = state.policy.read().await;
    if !policy.is_known_tenant(&req.tenant_id) {
        return unauthorized("tenant is not registered with this hub");
    }
    drop(policy);

    if let Err(e) = state
        .db
        .bump_agent_liveness(&req.tenant_id, &req.agent_id, now_ms())
        .await
    {
        warn!(error = %e, "failed to bump agent_liveness");
        return internal_error();
    }

    json_ok(HeartbeatResponse {
        status: "ok",
        next_interval_secs: 20,
    })
}
