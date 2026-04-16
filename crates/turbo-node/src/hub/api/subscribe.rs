use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use turbo_common::routing::RouteTable;

use turbo_common::time::now_ms;

use super::{AppState, internal_error, json_ok, unauthorized};

/// Timestamp window for signature freshness. Replay within this window is
/// acceptable (the endpoint just opens another identical SSE stream).
const EDGE_SUB_MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Parse the `Authorization: Signature <node_id>.<ts>.<sig>` header, check
/// the timestamp window, verify the Ed25519 signature against `node_id`, and
/// confirm the node is registered in the `edges` table.
async fn authenticate_edge_subscriber(
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
    let now = now_ms();
    let skew = now.abs_diff(ts_ms);
    if skew > EDGE_SUB_MAX_CLOCK_SKEW_MS {
        return Err("timestamp outside freshness window");
    }

    let sig_bytes = B64
        .decode(sig_b64)
        .map_err(|_| "signature is not base64url")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;

    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&node_id_bytes)
        .map_err(|_| "node_id is not a valid Ed25519 public key")?;
    let message = format!("turbo-tunnel/edge-sub/v1/{node_id_hex}/{ts_ms}");
    pubkey
        .verify_strict(
            message.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_arr),
        )
        .map_err(|_| "signature does not verify")?;

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
        let policy_snapshot = state.policy.read().await.clone();
        match state.db.get_all_entries().await {
            Ok(entries) => RouteTable::from_entries(&entries, &policy_snapshot),
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch entries for initial snapshot");
                return internal_error();
            }
        }
    };

    let mut rx = state.route_tx.subscribe();

    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(route_event(&initial_table));
        loop {
            match rx.recv().await {
                Ok(table) => yield Ok(route_event(&table)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
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
pub(super) async fn get_dns_records(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let hostnames = state.prev_hostnames.read().await;

    #[derive(Serialize)]
    struct DnsRecord<'a> {
        hostname: &'a str,
        targets: &'a [String],
    }

    let records: Vec<DnsRecord<'_>> = hostnames
        .iter()
        .map(|h| DnsRecord {
            hostname: h.as_str(),
            targets: &state.edge_addresses,
        })
        .collect();

    json_ok(serde_json::json!({ "records": records }))
}
