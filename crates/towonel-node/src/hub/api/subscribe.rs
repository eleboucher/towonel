use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use towonel_common::metrics::GaugeGuard;
use towonel_common::routing::RouteTable;

use super::{AGENT_LIVE_TTL_MS, AppState, internal_error, unauthorized};

const EDGE_SUB_MAX_CLOCK_SKEW_MS: u64 = 60_000;

const EDGE_SUB_AUTH_DOMAIN: &str = "towonel/edge-sub/v1";

/// Parse the `Authorization: Signature <node_id>.<ts>.<sig>` header, check
async fn authenticate_edge_subscriber(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<[u8; 32], &'static str> {
    let (node_id_bytes, ts_ms) = crate::hub::auth::verify_signature_header(
        headers,
        EDGE_SUB_AUTH_DOMAIN,
        EDGE_SUB_MAX_CLOCK_SKEW_MS,
        &[], // GET has no body
    )?;

    let key = (node_id_bytes, ts_ms);
    let fresh = state
        .edge_sub_nonces
        .entry(key)
        .or_insert_with(async {})
        .await
        .is_fresh();
    if !fresh {
        return Err("replayed (node_id, timestamp) pair");
    }

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

pub(super) async fn build_initial_snapshot(state: &AppState) -> anyhow::Result<RouteTable> {
    let policy_snapshot = state.policy.load_full();
    let cutoff = towonel_common::time::now_ms().saturating_sub(AGENT_LIVE_TTL_MS);
    let (entries, live) =
        tokio::try_join!(state.db.get_all_entries(), state.db.live_agents(cutoff))?;
    Ok(RouteTable::from_entries_with_liveness(
        &entries,
        &policy_snapshot,
        Some(&live),
    ))
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

    let initial_table = match build_initial_snapshot(&state).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build initial route snapshot");
            return internal_error();
        }
    };

    let mut rx = state.route_tx.subscribe();
    let state_for_recover = Arc::clone(&state);
    let guard = GaugeGuard::inc(&state.metrics.sse_subscribers_connected);

    let stream = async_stream::stream! {
        let _guard = guard;
        yield Ok::<_, Infallible>(route_event(&initial_table));
        loop {
            match rx.recv().await {
                Ok(table) => yield Ok(route_event(&table)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // Client fell behind the 64-slot broadcast buffer. Resend
                    // a fresh snapshot so it resyncs instead of silently
                    // missing route updates until the next one lands.
                    tracing::warn!(
                        edge = %hex::encode(node_id),
                        skipped = n,
                        "edge SSE subscriber lagged; resending current snapshot",
                    );
                    match build_initial_snapshot(&state_for_recover).await {
                        Ok(t) => yield Ok(route_event(&t)),
                        Err(e) => {
                            tracing::warn!(error = %e, "lag-recovery snapshot failed; closing");
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
