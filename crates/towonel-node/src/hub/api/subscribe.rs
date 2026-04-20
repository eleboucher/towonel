use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use towonel_common::metrics::GaugeGuard;
use towonel_common::routing::RouteTable;

use super::{AGENT_LIVE_TTL_MS, AppState, internal_error, json_ok, unauthorized};

/// Timestamp window for signature freshness. Replay within this window is
/// acceptable (the endpoint just opens another identical SSE stream).
const EDGE_SUB_MAX_CLOCK_SKEW_MS: u64 = 60_000;

const EDGE_SUB_AUTH_DOMAIN: &str = "towonel/edge-sub/v1";

/// Parse the `Authorization: Signature <node_id>.<ts>.<sig>` header, check
/// the timestamp window, verify the signature against `node_id`, and
/// confirm the node is registered via a pending (not revoked)
/// `edge_invites` row.
async fn authenticate_edge_subscriber(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<[u8; 32], &'static str> {
    let (node_id_bytes, _ts_ms) = crate::hub::auth::verify_signature_header(
        headers,
        EDGE_SUB_AUTH_DOMAIN,
        EDGE_SUB_MAX_CLOCK_SKEW_MS,
        &[], // GET has no body
    )?;

    if !state
        .db
        .edge_is_registered(&node_id_bytes)
        .await
        .map_err(|_| "failed to check edge registration")?
    {
        return Err("edge is not registered with this hub");
    }
    Ok(node_id_bytes)
}

/// Serialize a `RouteTable` as canonical CBOR, base64url-encode it, and
/// wrap it in an SSE `routes` event.
fn route_event(table: &RouteTable) -> axum::response::sse::Event {
    let mut buf = Vec::new();
    // RouteTable only contains serializable primitives; CBOR encode into a Vec is infallible.
    #[allow(clippy::expect_used)]
    ciborium::into_writer(table, &mut buf).expect("RouteTable CBOR encode is infallible");
    axum::response::sse::Event::default()
        .event("routes")
        .data(B64.encode(&buf))
}

pub(super) async fn routes_subscribe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    use axum::response::sse::{KeepAlive, Sse};
    use std::convert::Infallible;

    let node_id = match authenticate_edge_subscriber(&state, &headers).await {
        Ok(id) => id,
        Err(msg) => return unauthorized(msg),
    };
    tracing::info!(edge = %hex::encode(node_id), "edge subscriber connected");

    let initial_table = {
        let policy_snapshot = state.policy.load_full();
        let entries = match state.db.get_all_entries().await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch entries for initial snapshot");
                return internal_error();
            }
        };
        let cutoff = towonel_common::time::now_ms().saturating_sub(AGENT_LIVE_TTL_MS);
        let live = match state.db.live_agents(cutoff).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch liveness for initial snapshot");
                return internal_error();
            }
        };
        RouteTable::from_entries_with_liveness(&entries, &policy_snapshot, Some(&live))
    };

    let mut rx = state.route_tx.subscribe();

    let guard = GaugeGuard::inc(&state.metrics.sse_subscribers_connected);

    let stream = async_stream::stream! {
        let _guard = guard;
        yield Ok::<_, Infallible>(route_event(&initial_table));
        loop {
            match rx.recv().await {
                Ok(table) => yield Ok(route_event(&table)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// `GET /v1/dns/records` -- returns all active hostnames paired with this
/// hub's edge addresses. An external-dns sidecar or cron job can poll this
/// to create A / AAAA records pointing each hostname at the edge IPs.
#[derive(Serialize)]
struct DnsRecord<'a> {
    hostname: &'a str,
    targets: &'a [String],
}

pub(super) async fn get_dns_records(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let hostnames = state.prev_hostnames.load();
    let records: Vec<DnsRecord<'_>> = hostnames
        .iter()
        .map(|h| DnsRecord {
            hostname: h.as_str(),
            targets: &state.identity.edge_addresses,
        })
        .collect();

    json_ok(serde_json::json!({ "records": records }))
}
