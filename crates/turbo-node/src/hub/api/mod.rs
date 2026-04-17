mod edge_invites;
mod entries;
mod invites;
mod subscribe;

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, broadcast};
use tower_http::trace::TraceLayer;
use turbo_common::invite::INVITE_ID_LEN;
use turbo_common::ownership::OwnershipPolicy;
use turbo_common::routing::RouteTable;

use super::db;
use db::Db;

pub(super) use turbo_common::CBOR_CONTENT_TYPE;
pub(super) use turbo_common::JSON_CONTENT_TYPE;

/// Protocol version supported by this hub.
pub const PROTOCOL_VERSION: u16 = 1;

/// Shared application state for all axum handlers.
pub struct AppState {
    pub db: Db,
    pub route_tx: broadcast::Sender<RouteTable>,
    /// Mutable ownership policy. Invite redemption inserts new tenants at
    /// runtime; the route table rebuilds pull from this same policy via a
    /// read lock.
    pub policy: Arc<RwLock<OwnershipPolicy>>,
    /// Shared HTTP client for outbound requests (DNS webhook, etc.).
    pub http_client: reqwest::Client,
    /// Identity information (`node_id`, edge info, version).
    pub identity: super::HubIdentity,
    /// Bearer token protecting operator-only endpoints.
    pub operator_api_key: String,
    /// Public URL of the hub (e.g. "<https://node.turbo.example.eu:8443>").
    pub public_url: String,
    /// Serializes the check+insert window in `POST /v1/invites`.
    pub invite_lock: Mutex<()>,
    /// Federation state: trusted peers and nonce cache.
    pub federation: FederationState,
    /// Optional webhook URL for DNS automation.
    pub dns_webhook_url: Option<String>,
    /// Hostnames present in the last broadcasted route table.
    pub prev_hostnames: RwLock<std::collections::HashSet<String>>,
}

/// Federation-related runtime state.
pub struct FederationState {
    /// iroh `node_ids` of configured federation peers.
    pub trusted_peers: super::federation::TrustedPeerSet,
    /// Nonce cache for federation auth: prevents within-window replay.
    /// Bounded size + TTL eviction via moka.
    pub nonces: super::federation::NonceCache,
}

/// Broadcast `table` to edges and fire the DNS webhook if hostnames changed.
pub async fn broadcast_routes(state: &Arc<AppState>, table: RouteTable) {
    let new_hostnames = table.hostnames();
    let _ = state.route_tx.send(table);

    if let Some(url) = &state.dns_webhook_url {
        let mut prev = state.prev_hostnames.write().await;
        let added: Vec<&String> = new_hostnames.difference(&prev).collect();
        let removed: Vec<&String> = prev.difference(&new_hostnames).collect();

        if !added.is_empty() || !removed.is_empty() {
            let url = url.clone();
            let client = state.http_client.clone();
            let body = serde_json::json!({
                "added": added,
                "removed": removed,
            });
            tokio::spawn(async move {
                match client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::info!(url = %url, "DNS webhook notified");
                    }
                    Ok(resp) => {
                        tracing::warn!(url = %url, status = %resp.status(), "DNS webhook returned error");
                    }
                    Err(e) => {
                        tracing::warn!(url = %url, error = %e, "DNS webhook request failed");
                    }
                }
            });
        }

        *prev = new_hostnames;
    }
}

/// Build the axum router with a per-IP rate limiter on the public surface.
pub fn router(state: Arc<AppState>) -> Router {
    build_router(state, /* rate_limit */ true)
}

/// Build the router without the rate limiter. Used by integration tests
/// which hammer the same 127.0.0.1 loopback with many requests per second.
#[cfg(test)]
pub fn router_unlimited(state: Arc<AppState>) -> Router {
    build_router(state, false)
}

fn build_router(state: Arc<AppState>, rate_limit: bool) -> Router {
    let operator_routes = Router::new()
        .route(
            "/v1/invites",
            post(invites::post_invite).get(invites::list_invites),
        )
        .route("/v1/invites/{id}", delete(invites::delete_invite))
        .route("/v1/tenants/{id}", delete(entries::delete_tenant))
        .route(
            "/v1/edge-invites",
            post(edge_invites::post_edge_invite).get(edge_invites::list_edge_invites_route),
        )
        .route(
            "/v1/edge-invites/{id}",
            delete(edge_invites::delete_edge_invite),
        )
        .route("/v1/dns/records", get(subscribe::get_dns_records))
        .layer(middleware::from_fn_with_state(state.clone(), operator_auth));

    let public_write = Router::new()
        .route("/v1/entries", post(entries::post_entry))
        .route("/v1/tenants/{id}/entries", get(entries::get_tenant_entries))
        .route("/v1/invites/redeem", post(invites::redeem_invite))
        .route(
            "/v1/edge-invites/redeem",
            post(edge_invites::redeem_edge_invite),
        )
        .route("/v1/routes/subscribe", get(subscribe::routes_subscribe));

    let public_write = if rate_limit {
        let governor_conf = std::sync::Arc::new(
            // The builder configuration above is statically valid; finish() returns None
            // only for invalid configs (e.g. zero rate), which can't happen here.
            #[allow(clippy::expect_used)]
            tower_governor::governor::GovernorConfigBuilder::default()
                .per_second(2)
                .burst_size(20)
                .finish()
                .expect("tower_governor config is valid"),
        );
        let limiter = governor_conf.limiter().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                limiter.retain_recent();
            }
        });
        public_write.layer(tower_governor::GovernorLayer::new(governor_conf))
    } else {
        public_write
    };

    let unlimited_public = Router::new()
        .route("/v1/health", get(entries::health))
        .route("/v1/edges", get(entries::list_edges));

    let federation_routes = Router::new()
        .route(
            "/v1/federation/tenants",
            post(super::federation::push_tenant),
        )
        .route(
            "/v1/federation/tenant-removals",
            post(super::federation::push_removal),
        )
        .route(
            "/v1/federation/entries",
            post(super::federation::push_entry),
        );

    Router::new()
        .merge(public_write)
        .merge(unlimited_public)
        .merge(federation_routes)
        .merge(operator_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub(super) fn error_response(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    #[derive(Serialize)]
    struct Body {
        error: Err,
    }
    #[derive(Serialize)]
    struct Err {
        code: &'static str,
        message: String,
    }
    json_with_status(
        status,
        Body {
            error: Err {
                code,
                message: message.into(),
            },
        },
    )
}

/// Convenience aliases used throughout the handlers.
pub(super) fn invalid_request(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request", msg)
}
pub(super) fn invalid_signature(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_signature", msg)
}
pub(super) fn tenant_not_allowed(msg: impl Into<String>) -> Response {
    error_response(StatusCode::FORBIDDEN, "tenant_not_allowed", msg)
}
pub(super) fn hostname_not_owned(msg: impl Into<String>) -> Response {
    error_response(StatusCode::FORBIDDEN, "hostname_not_owned", msg)
}
pub(super) fn sequence_conflict(msg: impl Into<String>) -> Response {
    error_response(StatusCode::CONFLICT, "sequence_conflict", msg)
}
pub(super) fn unsupported_version(msg: impl Into<String>) -> Response {
    error_response(StatusCode::UNPROCESSABLE_ENTITY, "unsupported_version", msg)
}
pub(super) fn unauthorized(msg: impl Into<String>) -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized", msg)
}
pub(super) fn not_found(msg: impl Into<String>) -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", msg)
}
pub(super) fn conflict(code: &'static str, msg: impl Into<String>) -> Response {
    error_response(StatusCode::CONFLICT, code, msg)
}
pub(super) fn gone(msg: impl Into<String>) -> Response {
    error_response(StatusCode::GONE, "invite_expired", msg)
}
pub(super) fn internal_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

pub(super) fn json_ok(value: impl Serialize) -> Response {
    json_with_status(StatusCode::OK, value)
}

pub(super) fn json_with_status(status: StatusCode, value: impl Serialize) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        axum::Json(value),
    )
        .into_response()
}

/// Serialize a value as CBOR with the correct Content-Type.
pub(super) fn cbor_response<T: Serialize>(value: &T) -> Response {
    let mut buf = Vec::new();
    if let Err(e) = ciborium::into_writer(value, &mut buf) {
        tracing::warn!(error = %e, "failed to encode CBOR response");
        return internal_error();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
        buf,
    )
        .into_response()
}

pub(super) fn parse_invite_id(s: &str) -> Option<[u8; INVITE_ID_LEN]> {
    let bytes = B64.decode(s).ok()?;
    bytes.as_slice().try_into().ok()
}

async fn operator_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        return unauthorized("missing Authorization header");
    };
    let Ok(auth) = auth.to_str() else {
        return unauthorized("malformed Authorization header");
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return unauthorized("Authorization must be `Bearer <operator_api_key>`");
    };

    if !constant_time_eq(token.as_bytes(), state.operator_api_key.as_bytes()) {
        return unauthorized("invalid operator API key");
    }
    next.run(req).await
}

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
