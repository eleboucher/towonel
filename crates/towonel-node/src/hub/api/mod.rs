mod admin;
mod agent_heartbeat;
mod bootstrap;
mod edge_invites;
mod entries;
mod federation_status;
mod invites;
mod metrics_handler;
mod subscribe;

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast};
use tokio_util::task::TaskTracker;
use tower_http::ServiceBuilderExt;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::MakeRequestUuid;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use towonel_common::invite::{INVITE_ID_LEN, InviteHashKey};
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;
use tracing::Level;

use super::db;
use super::metrics::HubMetrics;
use super::peer_status::PeerStatusMap;
use db::Db;

pub(super) use towonel_common::CBOR_CONTENT_TYPE;
pub(super) use towonel_common::JSON_CONTENT_TYPE;

/// Protocol version supported by this hub.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum age of an agent heartbeat for the agent to still appear in route
/// tables. Pods heartbeat every 20s; 90s tolerates two missed beats.
pub const AGENT_LIVE_TTL_MS: u64 = 90_000;

/// Upper bound on any request body accepted by the hub API.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Rows older than this are physically deleted by the prune loop. Five
/// minutes is long enough to debug a dead pod without keeping rows forever.
pub const AGENT_PRUNE_TTL_MS: u64 = 300_000;

/// Shared application state for all axum handlers.
pub struct AppState {
    pub db: Db,
    pub route_tx: broadcast::Sender<RouteTable>,
    /// Mutable ownership policy. Invite redemption inserts new tenants at
    /// runtime; the route table rebuilds pull from this same policy.
    /// Copy-on-write via `ArcSwap`: readers do a pointer-bump `.load()`;
    /// writers clone, mutate, and `.store()` a new `Arc`. Serialization
    /// across concurrent writers is provided by `invite_lock` for the
    /// check-then-register windows that need it.
    pub policy: ArcSwap<OwnershipPolicy>,
    /// Shared HTTP client for outbound requests (DNS webhook, etc.).
    pub http_client: reqwest::Client,
    /// Identity information (`node_id`, edge info, version).
    pub identity: super::HubIdentity,
    /// Bearer token protecting operator-only endpoints.
    pub operator_api_key: zeroize::Zeroizing<String>,
    /// Public URL of the hub (e.g. "<https://node.towonel.example.eu:8443>").
    pub public_url: String,
    /// Serializes the check+insert window in `POST /v1/invites`.
    pub invite_lock: Mutex<()>,
    /// Federation state: trusted peers and nonce cache.
    pub federation: FederationState,
    /// Optional webhook URL for DNS automation.
    pub dns_webhook_url: Option<String>,
    /// Hostnames present in the last broadcasted route table. Single-writer
    /// (the route-rebuild path) / many-reader (`/v1/dns/records`); `ArcSwap`
    /// keeps reads lock-free.
    pub prev_hostnames: ArcSwap<std::collections::HashSet<String>>,
    /// Prometheus metrics surface exposed on `/metrics`.
    pub metrics: HubMetrics,
    /// Per-peer federation push status, surfaced via `/v1/federation/status`.
    pub peer_statuses: PeerStatusMap,
    /// Tracker for fire-and-forget background tasks (DNS webhook, etc.).
    pub tasks: TaskTracker,
    /// Operator secret used to keyed-hash invite secrets before persistence.
    pub invite_hash_key: Arc<InviteHashKey>,
    /// Replay cache for heartbeat (`node_id`, `ts_ms`) pairs. Stops an
    /// attacker with a captured heartbeat from keeping a revoked agent
    /// looking live within the ±60s clock-skew window.
    pub heartbeat_nonces: super::federation::NonceCache,
    /// Accept `http://` and loopback hosts in `/v1/admin/resync`. Only set
    /// by the integration-test scaffolding; production leaves this `false`.
    pub allow_loopback_peers: bool,
}

/// Federation-related runtime state.
pub struct FederationState {
    /// iroh `node_ids` of configured federation peers.
    pub trusted_peers: super::federation::TrustedPeerSet,
    /// Nonce cache for federation auth: prevents within-window replay.
    /// Bounded size + TTL eviction via moka.
    pub nonces: super::federation::NonceCache,
    /// Outbound peer surface for synchronous pushes. `None` when the hub
    /// has no configured peers (federation disabled).
    pub outbound: Option<OutboundFederation>,
    /// Push the new tenant to all peers inside `redeem_invite` before
    /// responding. Trades redemption latency for consistency on the op
    /// operators care about most.
    pub sync_invite_redeem: bool,
}

/// Outbound federation identity: the signing key + URLs of peer hubs.
pub struct OutboundFederation {
    pub peer_urls: Vec<String>,
    pub signing_key: iroh::SecretKey,
}

impl AppState {
    /// Copy-on-write mutator for the ownership policy. Clones the current
    /// snapshot, applies `mutate`, and stores the new `Arc`. Concurrent
    /// writers race like last-writer-wins; callers that need serialization
    /// (check-then-register) hold `invite_lock` for the whole window.
    pub fn policy_update(&self, mutate: impl FnOnce(&mut OwnershipPolicy)) {
        let current = self.policy.load_full();
        let mut next = (*current).clone();
        mutate(&mut next);
        self.policy.store(Arc::new(next));
    }
}

/// Build a route table from the hub's current state (policy + entries +
/// agent liveness) and broadcast it to edges.
///
/// The liveness-aware rebuild is the single funnel every route update flows
/// through; it guarantees stale agents vanish from the edge view as soon as
/// their heartbeat lapses.
pub async fn rebuild_and_broadcast_routes(state: &Arc<AppState>) -> anyhow::Result<()> {
    let policy_snapshot = state.policy.load_full();
    let cutoff = towonel_common::time::now_ms().saturating_sub(AGENT_LIVE_TTL_MS);
    let (entries, live) =
        tokio::try_join!(state.db.get_all_entries(), state.db.live_agents(cutoff))?;
    let table = RouteTable::from_entries_with_liveness(&entries, &policy_snapshot, Some(&live));
    broadcast_routes(state, table);
    Ok(())
}

/// Broadcast `table` to edges and fire the DNS webhook if hostnames changed.
pub fn broadcast_routes(state: &Arc<AppState>, table: RouteTable) {
    let new_hostnames = table.hostnames();
    if state.route_tx.send(table).is_err() {
        tracing::debug!("route broadcast: no active subscribers");
    }

    if let Some(url) = &state.dns_webhook_url {
        let prev = state.prev_hostnames.load();
        let added: Vec<&String> = new_hostnames.difference(&prev).collect();
        let removed: Vec<&String> = prev.difference(&new_hostnames).collect();

        if !added.is_empty() || !removed.is_empty() {
            let url = url.clone();
            let client = state.http_client.clone();
            let body = serde_json::json!({
                "added": added,
                "removed": removed,
            });
            state.tasks.spawn(async move {
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

        state.prev_hostnames.store(Arc::new(new_hostnames));
    }
}

/// Build the axum router with a per-IP rate limiter on the public surface.
pub fn router(state: Arc<AppState>) -> Router {
    build_router(state, /* rate_limit */ true)
}

/// Router for the private health/metrics listener. Bound to a separate port
/// so `/metrics` isn't exposed on the public API and scrape traffic doesn't
/// show up in `towonel_hub_requests_total`.
pub fn health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler::metrics))
        .with_state(state)
}

/// Build the router without the rate limiter. Used by integration tests
/// which hammer the same 127.0.0.1 loopback with many requests per second.
#[cfg(test)]
pub fn router_unlimited(state: Arc<AppState>) -> Router {
    build_router(state, false)
}

fn build_router(state: Arc<AppState>, rate_limit: bool) -> Router {
    let operator_routes = operator_routes(&state);
    let public_write = maybe_rate_limit(public_write_routes(), rate_limit);
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

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(|req: &axum::http::Request<_>| {
            let request_id = req
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map_or_else(|| "-".to_string(), ToString::to_string);
            tracing::info_span!(
                "http",
                method = %req.method(),
                uri = %req.uri(),
                request_id = %request_id,
            )
        })
        .on_response(DefaultOnResponse::new().level(Level::INFO));
    let correlated = tower::ServiceBuilder::new()
        .set_x_request_id(MakeRequestUuid)
        .layer(trace_layer)
        .propagate_x_request_id()
        .into_inner();

    Router::new()
        .merge(public_write)
        .merge(unlimited_public)
        .merge(federation_routes)
        .merge(operator_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            record_request_metric,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(correlated)
        .with_state(state)
}

fn operator_routes(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
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
        .route("/v1/admin/federation/snapshot", get(admin::snapshot))
        .route("/v1/admin/resync", post(admin::resync))
        .route("/v1/federation/status", get(federation_status::get_status))
        .layer(middleware::from_fn_with_state(state.clone(), operator_auth))
}

fn public_write_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/entries", post(entries::post_entry))
        .route("/v1/tenants/{id}/entries", get(entries::get_tenant_entries))
        .route("/v1/bootstrap", post(bootstrap::post_bootstrap))
        .route("/v1/agent/heartbeat", post(agent_heartbeat::post_heartbeat))
        .route("/v1/routes/subscribe", get(subscribe::routes_subscribe))
}

fn maybe_rate_limit(router: Router<Arc<AppState>>, rate_limit: bool) -> Router<Arc<AppState>> {
    if !rate_limit {
        return router;
    }
    let governor_conf = std::sync::Arc::new(
        #[allow(clippy::expect_used)]
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(20)
            .finish()
            .expect("tower_governor config is valid"),
    );
    let limiter = governor_conf.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });
    router.layer(tower_governor::GovernorLayer::new(governor_conf))
}

/// Bump `towonel_hub_requests{endpoint,status}` per response. Uses the
/// matched axum route pattern as `endpoint` to keep cardinality bounded —
/// dynamic path segments like `/v1/invites/{id}` collapse to one label.
/// Unmatched requests get `endpoint="unmatched"`.
async fn record_request_metric(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let matched = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .cloned();
    let resp = next.run(req).await;
    let endpoint = matched
        .as_ref()
        .map_or("unmatched", axum::extract::MatchedPath::as_str);
    state
        .metrics
        .record_request(endpoint, resp.status().as_u16());
    resp
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

pub(super) async fn load_trusted_edges(state: &AppState) -> anyhow::Result<Vec<iroh::EndpointId>> {
    state
        .db
        .list_trusted_edge_ids()
        .await?
        .iter()
        .map(|bytes| {
            iroh::EndpointId::from_bytes(bytes)
                .map_err(|e| anyhow::anyhow!("corrupt edge_node_id in edge_invites: {e}"))
        })
        .collect()
}
