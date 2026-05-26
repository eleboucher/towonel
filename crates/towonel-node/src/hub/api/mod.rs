mod acme_account;
mod agent_refresh;
mod app_settings;
mod auth;
mod bootstrap;
mod entries;
mod invites;
mod metrics_handler;
mod oidc;
mod passkey;
mod password_reset;
mod ports;
mod signup_invites;
mod twofa;
mod users;
mod verify;

pub use oidc::{OidcRuntimes, build_runtimes as build_oidc_runtimes};

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast};
use tower_http::ServiceBuilderExt;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::MakeRequestUuid;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use towonel_common::invite::{INVITE_ID_LEN, InviteHashKey};
use towonel_common::kek::HubKek;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;
use tracing::Level;

use super::auth::middleware::OperatorPrincipal;
use super::db;
use super::edge_link::PortReservationDelta;
use super::metrics::HubMetrics;
use super::signing::HubSigner;
use db::Db;

pub(super) use towonel_common::CBOR_CONTENT_TYPE;
pub(super) use towonel_common::JSON_CONTENT_TYPE;

/// Protocol version supported by this hub.
pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound on any request body accepted by the hub API.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Freshness window for signed heartbeat/edge-subscribe requests. A request
/// outside ±`MAX_CLOCK_SKEW_MS` is rejected outright.
const MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Bound on the replay-nonce cache. Entries are also evicted by TTL; the cap
/// only matters under extreme traffic.
pub const MAX_NONCE_ENTRIES: u64 = 10_000;

/// Replay-protection cache for `(node_id, ts_ms)` pairs. TTL is 2× the
/// freshness window so any in-window retry is caught.
pub type NonceCache = moka::future::Cache<([u8; 32], u64), ()>;

/// Construct an empty nonce cache with the project-wide cap and TTL.
#[must_use]
pub fn new_nonce_cache() -> NonceCache {
    moka::future::Cache::builder()
        .max_capacity(MAX_NONCE_ENTRIES)
        .time_to_live(Duration::from_millis(MAX_CLOCK_SKEW_MS * 2))
        .build()
}

/// Counter per `agent_id`; key auto-expires after 60s. `u32` (not `u8`) so
/// the counter cannot wrap inside the TTL window and let another burst
/// through.
pub type RefreshLimiter = moka::future::Cache<[u8; 32], Arc<std::sync::atomic::AtomicU32>>;

pub const AGENT_REFRESH_MAX_PER_MIN: u32 = 10;

#[must_use]
pub fn new_refresh_limiter() -> RefreshLimiter {
    moka::future::Cache::builder()
        .max_capacity(MAX_NONCE_ENTRIES)
        .time_to_live(Duration::from_mins(1))
        .build()
}

/// Counter per lowercased login email; cache TTL is the lockout window.
pub type LoginLimiter = moka::future::Cache<String, Arc<std::sync::atomic::AtomicU32>>;

pub const LOGIN_MAX_FAILURES: u32 = 10;
pub const LOGIN_LOCKOUT_WINDOW_SECS: u64 = 15 * 60;

/// Per-challenge counter. At [`TWOFA_MAX_ATTEMPTS_PER_CHALLENGE`] failures
/// the verify handler consumes the challenge so a stolen password can't
/// brute-force the 6-digit space inside the challenge TTL.
pub type TwoFaAttemptLimiter = moka::future::Cache<String, Arc<std::sync::atomic::AtomicU32>>;

pub const TWOFA_MAX_ATTEMPTS_PER_CHALLENGE: u32 = 5;

#[must_use]
pub fn new_twofa_attempt_limiter() -> TwoFaAttemptLimiter {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(LOGIN_LOCKOUT_WINDOW_SECS))
        .build()
}

pub type PasskeyRegStates = moka::future::Cache<String, webauthn_rs::prelude::PasskeyRegistration>;
pub type PasskeyAuthStates =
    moka::future::Cache<String, (String, webauthn_rs::prelude::PasskeyAuthentication)>;

const PASSKEY_CHALLENGE_TTL_SECS: u64 = 5 * 60;

#[must_use]
pub fn new_passkey_reg_states() -> PasskeyRegStates {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(PASSKEY_CHALLENGE_TTL_SECS))
        .build()
}

#[must_use]
pub fn new_passkey_auth_states() -> PasskeyAuthStates {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(PASSKEY_CHALLENGE_TTL_SECS))
        .build()
}

/// Compute the PHC hash that login uses as a fall-back verify target when
/// the supplied email does not exist (or is disabled). Spending the same
/// argon2 CPU on those paths closes the user-enumeration timing oracle.
pub async fn compute_login_sentinel_hash() -> anyhow::Result<String> {
    super::auth::password::hash("\0towonel-login-sentinel\0").await
}

#[must_use]
pub fn new_login_limiter() -> LoginLimiter {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(LOGIN_LOCKOUT_WINDOW_SECS))
        .build()
}

/// Shared application state for all axum handlers.
pub struct AppState {
    pub db: Db,
    pub route_tx: broadcast::Sender<RouteTable>,
    /// Mutable ownership policy. Invite redemption inserts new tenants at
    /// runtime; the route table rebuilds pull from this same policy.
    /// Copy-on-write via `ArcSwap`: readers do a pointer-bump `.load()`;
    /// writers clone, mutate, and `.store()` a new `Arc`. Serialization
    /// across concurrent writers is provided by `invite_lock` — every
    /// `policy_update` call site must hold it, otherwise a concurrent
    /// create + delete will drop the newer tenant from the snapshot.
    pub policy: ArcSwap<OwnershipPolicy>,
    /// Identity information (`node_id`, edge info, version).
    pub identity: super::HubIdentity,
    /// Bearer token protecting operator-only endpoints.
    pub operator_api_key: zeroize::Zeroizing<String>,
    /// Public URL of the hub (e.g. "<https://node.towonel.example.eu:8443>").
    pub public_url: String,
    /// `Secure` flag on auth cookies. Computed once from `public_url`
    /// so per-response checks can't drift.
    pub use_secure_cookies: bool,
    /// Serializes every mutator of [`AppState::policy`] (invite create +
    /// invite revoke + tenant delete) so the copy-on-write snapshots can't
    /// race-stomp each other. Despite the historical name this is the
    /// global policy lock — keep adding new callers here, not bypassing it.
    pub invite_lock: Mutex<()>,
    /// Prometheus metrics surface exposed on `/metrics`.
    pub metrics: HubMetrics,
    /// Operator secret used to keyed-hash invite secrets before persistence.
    pub invite_hash_key: Arc<InviteHashKey>,
    /// Replay cache for signed agent → hub requests (`/agent/refresh`),
    /// keyed by `(node_id, ts_ms)`. The auth domain in the signed message
    /// is endpoint-specific so cross-replay across endpoints is impossible;
    /// this cache only catches in-endpoint replays within the ±60s freshness
    /// window.
    pub signed_request_nonces: NonceCache,
    /// Serializes the check+insert window for `UpsertTcpService`.
    pub tcp_port_lock: Mutex<()>,
    /// Same role as `tcp_port_lock` but for `UpsertUdpService`. UDP ports
    /// live in their own namespace at the OS so a separate lock keeps the
    /// fast path independent of TCP claims.
    pub udp_port_lock: Mutex<()>,
    pub signer: Arc<HubSigner>,
    /// At-rest KEK: seals signing keys and TOTP secrets.
    pub kek: Arc<HubKek>,
    pub refresh_limiter: RefreshLimiter,
    /// Per-email counter for failed logins. Audit/observability only — the
    /// IP-keyed counter below is what actually blocks. A per-email lockout
    /// would let any third party pin a known account by sending wrong
    /// passwords from anywhere.
    pub login_limiter: LoginLimiter,
    /// Per-client-IP counter for failed logins. Trips lockout when an IP
    /// crosses [`LOGIN_MAX_FAILURES`] in the window; legitimate users from
    /// other IPs are unaffected.
    pub ip_login_limiter: LoginLimiter,
    /// PHC hash of a fixed sentinel, computed once at startup. Used to make
    /// the user-not-found and user-disabled paths spend the same argon2 CPU
    /// as a real verify, closing a user-enumeration timing oracle.
    pub login_sentinel_hash: String,
    pub twofa_attempt_limiter: TwoFaAttemptLimiter,
    pub live_edges: Arc<super::live_edges::LiveEdges>,
    pub live_agents: Arc<super::live_agents::LiveAgents>,
    /// Fed via [`trigger_route_rebuild`]; drained by the coalescer task.
    pub route_rebuild_notify: Arc<tokio::sync::Notify>,
    pub web_enabled: bool,
    pub mailer: Option<super::mail::SharedMailer>,
    pub port_reservations_tx: broadcast::Sender<PortReservationDelta>,
    pub ports_require_reservation: bool,
    /// Port → (tenant, service) index, computed without the liveness filter
    /// so an offline agent's reservation still blocks another tenant from
    /// claiming the port. Read by `find_port_conflict` under the
    /// per-protocol locks; refreshed by `rebuild_and_broadcast_routes`.
    pub port_index: ArcSwap<PortIndex>,
    /// Configured OIDC providers (one runtime per provider). Empty means
    /// no OIDC providers are advertised on `/v1/auth/providers`.
    pub oidc: OidcRuntimes,
    pub webauthn: Arc<webauthn_rs::Webauthn>,
    pub passkey_reg_states: PasskeyRegStates,
    pub passkey_auth_states: PasskeyAuthStates,
    pub tls: Option<crate::config::TlsConfig>,
}

#[derive(Default)]
pub struct PortIndex {
    pub tcp:
        std::collections::BTreeMap<u16, (towonel_common::identity::TenantId, std::string::String)>,
    pub udp:
        std::collections::BTreeMap<u16, (towonel_common::identity::TenantId, std::string::String)>,
}

/// Walk all signed entries and materialize the per-protocol
/// `listen_port → (tenant, service)` map. Independent of agent liveness so a
/// reconnecting agent's port reservation persists across blips.
fn build_port_index(
    entries: &[towonel_common::config_entry::SignedConfigEntry],
    policy: &towonel_common::ownership::OwnershipPolicy,
) -> PortIndex {
    use towonel_common::config_entry::ConfigOp;
    use towonel_common::identity::TenantId;
    let mut per_tenant_tcp: std::collections::HashMap<
        TenantId,
        std::collections::HashMap<String, u16>,
    > = std::collections::HashMap::new();
    let mut per_tenant_udp: std::collections::HashMap<
        TenantId,
        std::collections::HashMap<String, u16>,
    > = std::collections::HashMap::new();
    for entry in entries {
        if policy.pq_public_key(&entry.tenant_id).is_none() {
            continue;
        }
        let Ok(payload) = entry.payload_unverified() else {
            continue;
        };
        match payload.op {
            ConfigOp::UpsertTcpService {
                service,
                listen_port,
            } => {
                per_tenant_tcp
                    .entry(payload.tenant_id)
                    .or_default()
                    .insert(service, listen_port);
            }
            ConfigOp::DeleteTcpService { service } => {
                per_tenant_tcp
                    .entry(payload.tenant_id)
                    .or_default()
                    .remove(&service);
            }
            ConfigOp::UpsertUdpService {
                service,
                listen_port,
            } => {
                per_tenant_udp
                    .entry(payload.tenant_id)
                    .or_default()
                    .insert(service, listen_port);
            }
            ConfigOp::DeleteUdpService { service } => {
                per_tenant_udp
                    .entry(payload.tenant_id)
                    .or_default()
                    .remove(&service);
            }
            _ => {}
        }
    }
    let mut idx = PortIndex::default();
    for (tenant, services) in per_tenant_tcp {
        for (service, port) in services {
            idx.tcp.entry(port).or_insert((tenant, service));
        }
    }
    for (tenant, services) in per_tenant_udp {
        for (service, port) in services {
            idx.udp.entry(port).or_insert((tenant, service));
        }
    }
    idx
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

/// Wake the rebuild coalescer. Bursts collapse into a single rebuild.
pub fn trigger_route_rebuild(state: &AppState) {
    state.route_rebuild_notify.notify_one();
}

/// Synchronous because the next `find_port_conflict` after an insert must
/// see the new claim; the coalesced route rebuild can't satisfy that.
pub async fn refresh_port_index(state: &Arc<AppState>) -> anyhow::Result<()> {
    let policy_snapshot = state.policy.load_full();
    let entries = state.db.get_all_entries().await?;
    let idx = build_port_index(&entries, &policy_snapshot);
    state.port_index.store(Arc::new(idx));
    Ok(())
}

/// Build the table from policy + entries + live agents and broadcast.
/// Driven by the coalescer in `hub::Hub::run`; everything else funnels
/// through [`trigger_route_rebuild`].
pub async fn rebuild_and_broadcast_routes(state: &Arc<AppState>) -> anyhow::Result<()> {
    let policy_snapshot = state.policy.load_full();
    let entries = state.db.get_all_entries().await?;
    let live = state.live_agents.snapshot();
    // Port index ignores liveness and tenant-has-agents so a crashed pod
    // doesn't free its port for another tenant to race-claim.
    let idx = build_port_index(&entries, &policy_snapshot);
    state.port_index.store(Arc::new(idx));

    let table = RouteTable::from_entries_with_liveness(&entries, &policy_snapshot, Some(&live));
    if state.route_tx.send(table).is_err() {
        tracing::debug!("route broadcast: no active subscribers");
    }
    Ok(())
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
    let invites_routes = invites_routes();
    let rate_limited_public = maybe_rate_limit(rate_limited_routes(state.web_enabled), rate_limit);
    let signed_public = signed_public_routes();
    let web_admin = web_admin_routes(state.web_enabled);
    // `/v1/health` is intentionally public — load balancers and uptime
    // monitors probe it without credentials. Everything operator-shaped
    // (including `/v1/edges`, which leaks the iroh endpoint topology of the
    // deployment) lives under the operator-auth router below.
    let unlimited_public = Router::new()
        .route("/v1/health", get(entries::health))
        .route("/v1/readyz", get(entries::readyz))
        .route("/v1/acme/account", get(acme_account::get_acme_account));

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
        .on_response(DefaultOnResponse::new().level(Level::DEBUG));
    let correlated = tower::ServiceBuilder::new()
        .set_x_request_id(MakeRequestUuid)
        .layer(trace_layer)
        .propagate_x_request_id()
        .into_inner();

    let tenant_member = tenant_member_routes();
    Router::new()
        .merge(rate_limited_public)
        .merge(signed_public)
        .merge(unlimited_public)
        .merge(operator_routes)
        .merge(invites_routes)
        .merge(web_admin)
        .merge(tenant_member)
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
        .route("/v1/tenants/{id}", delete(entries::delete_tenant))
        .route("/v1/ports", get(ports::list_all_ports))
        .route("/v1/edges", get(entries::list_edges))
        .route(
            "/v1/settings/user-port-quota",
            get(app_settings::get_user_port_quota).put(app_settings::put_user_port_quota),
        )
        .layer(middleware::from_extractor_with_state::<
            OperatorPrincipal,
            Arc<AppState>,
        >(state.clone()))
}

fn tenant_member_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v1/tenants/{id}/ports",
            post(ports::post_port).get(ports::list_ports),
        )
        .route(
            "/v1/tenants/{id}/ports/{proto}/{port}",
            delete(ports::delete_port),
        )
        .route("/v1/ports/available", get(ports::get_available_ports))
}

fn invites_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v1/invites",
            post(invites::post_invite).get(invites::list_invites),
        )
        .route("/v1/invites/{id}", delete(invites::delete_invite))
}

fn rate_limited_routes(web_enabled: bool) -> Router<Arc<AppState>> {
    let mut r = Router::new().route("/v1/bootstrap", post(bootstrap::post_bootstrap));
    if web_enabled {
        r = r
            .route("/v1/auth/signup", post(auth::post_signup))
            .route("/v1/auth/login", post(auth::post_login))
            .route("/v1/auth/logout", post(auth::post_logout))
            .route("/v1/auth/me", get(auth::get_me))
            .route(
                "/v1/auth/verify",
                post(verify::post_verify).get(verify::get_verify),
            )
            .route("/v1/auth/verify/resend", post(verify::post_resend))
            .route(
                "/v1/auth/password/reset",
                post(password_reset::post_request),
            )
            .route(
                "/v1/auth/password/reset/confirm",
                post(password_reset::post_confirm),
            )
            .route("/v1/auth/2fa/setup", post(twofa::post_setup))
            .route("/v1/auth/2fa/confirm", post(twofa::post_confirm))
            .route("/v1/auth/2fa/disable", post(twofa::post_disable))
            .route(
                "/v1/auth/2fa/backup/regenerate",
                post(twofa::post_regenerate),
            )
            .route("/v1/auth/2fa/verify", post(auth::post_twofa_verify))
            .route("/v1/auth/2fa/status", get(twofa::get_status))
            .route("/v1/auth/passkeys", get(passkey::list_passkeys))
            .route(
                "/v1/auth/passkeys/register/begin",
                post(passkey::post_register_begin),
            )
            .route(
                "/v1/auth/passkeys/register/finish",
                post(passkey::post_register_finish),
            )
            .route(
                "/v1/auth/passkeys/authenticate/begin",
                post(passkey::post_authenticate_begin),
            )
            .route(
                "/v1/auth/passkeys/authenticate/finish",
                post(passkey::post_authenticate_finish),
            )
            .route("/v1/auth/passkeys/{id}", delete(passkey::delete_passkey))
            .route("/v1/auth/providers", get(oidc::list_providers))
            .route("/v1/auth/oidc/{provider}/start", get(oidc::start))
            // POST so SameSite=Lax cookies don't ride cross-site
            // top-level navigation (CSRF). Same for /unlink below.
            .route("/v1/auth/oidc/{provider}/link", post(oidc::link))
            .route("/v1/auth/oidc/{provider}/unlink", post(oidc::unlink))
            .route("/v1/auth/oidc/identities", get(oidc::list_identities))
            .route("/v1/auth/oidc/{provider}/callback", get(oidc::callback));
    }
    r
}

fn web_admin_routes(web_enabled: bool) -> Router<Arc<AppState>> {
    if !web_enabled {
        return Router::new();
    }
    Router::new()
        .route(
            "/v1/signup-invites",
            post(signup_invites::post_signup_invite).get(signup_invites::list_signup_invites),
        )
        .route("/v1/users", get(users::list_users))
        .route("/v1/users/{id}/disable", post(users::post_user_disable))
}

fn signed_public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/entries", post(entries::post_entry))
        .route("/v1/tenants/{id}/entries", get(entries::get_tenant_entries))
        .route("/v1/agent/refresh", post(agent_refresh::post_refresh))
}

fn maybe_rate_limit(router: Router<Arc<AppState>>, rate_limit: bool) -> Router<Arc<AppState>> {
    if !rate_limit {
        return router;
    }
    let governor_conf = std::sync::Arc::new(
        #[expect(
            clippy::expect_used,
            reason = "config builder values are constants; failure is a programmer error caught at startup"
        )]
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
pub(super) fn unsupported_op(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, "unsupported_op", msg)
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

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
