use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{Router, get};
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder};
use serde::Serialize;
use towonel_common::metrics::{register_counter, register_counter_vec, register_gauge};

/// Edge observability surface. Cheap to clone: the `prometheus` metric
/// types are internally `Arc`-shared and the `Registry` is held as an `Arc`.
#[derive(Clone)]
pub struct EdgeMetrics {
    pub active_connections: IntGauge,
    pub total_connections: IntCounter,
    pub total_bytes_in: IntCounter,
    pub total_bytes_out: IntCounter,
    pub active_sessions: IntGauge,
    pub sessions_total: IntCounter,
    pub sessions_rejected_total: IntCounterVec,
    pub route_no_session_total: IntCounter,
    /// Connections / sessions dropped because the edge concurrency caps were
    /// saturated. Counts both TCP-accept overload (the global
    /// `TOWONEL_EDGE_MAX_INFLIGHT_CONNECTIONS` semaphore) and UDP new-session
    /// overload (per-listener `TOWONEL_EDGE_MAX_UDP_SESSIONS_PER_LISTENER`).
    pub connections_rejected_overload: IntCounter,
    registry: Arc<Registry>,
}

impl EdgeMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        towonel_common::process_metrics::register(&r);
        Self {
            active_connections: register_gauge(
                &r,
                "towonel_edge_active_connections",
                "Active tunneled connections",
            ),
            total_connections: register_counter(
                &r,
                "towonel_edge_connections_total",
                "Total connections handled",
            ),
            total_bytes_in: register_counter(
                &r,
                "towonel_edge_bytes_in_total",
                "Total bytes received from clients",
            ),
            total_bytes_out: register_counter(
                &r,
                "towonel_edge_bytes_out_total",
                "Total bytes sent to clients",
            ),
            active_sessions: register_gauge(
                &r,
                "towonel_edge_active_sessions",
                "Agent iroh sessions currently registered with this edge",
            ),
            sessions_total: register_counter(
                &r,
                "towonel_edge_sessions_total",
                "Agent iroh sessions registered (each reconnect counts once)",
            ),
            sessions_rejected_total: register_counter_vec(
                &r,
                "towonel_edge_sessions_rejected_total",
                "Inbound iroh connections rejected, by reason",
                &["reason"],
            ),
            route_no_session_total: register_counter(
                &r,
                "towonel_edge_route_no_session_total",
                "Requests where no session was registered for the agent at lookup time \
                 (excludes the case where a session existed but its open_bi failed)",
            ),
            connections_rejected_overload: register_counter(
                &r,
                "towonel_edge_connections_rejected_overload_total",
                "TCP connections dropped because the edge inflight-connection cap was \
                 reached. Sustained values mean an accept-time DoS or an under-sized \
                 EDGE_MAX_INFLIGHT_CONNECTIONS.",
            ),
            registry: Arc::new(r),
        }
    }
}

pub mod session_reject_reason {
    pub const UNKNOWN_AGENT: &str = "unknown_agent";
    pub const HANDSHAKE_ERROR: &str = "handshake_error";
    pub const PER_TENANT_LIMIT: &str = "per_tenant_limit";
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    active_connections: i64,
    total_connections: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
}

async fn health(State(metrics): State<EdgeMetrics>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        active_connections: metrics.active_connections.get(),
        total_connections: metrics.total_connections.get(),
        total_bytes_in: metrics.total_bytes_in.get(),
        total_bytes_out: metrics.total_bytes_out.get(),
    })
}

async fn metrics_handler(State(metrics): State<EdgeMetrics>) -> impl IntoResponse {
    let mut buf = Vec::new();
    if let Err(e) = TextEncoder::new().encode(&metrics.registry.gather(), &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encoding failed: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buf,
    )
        .into_response()
}

pub fn router(metrics: EdgeMetrics) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}

async fn readyz(State(metrics): State<EdgeMetrics>) -> impl IntoResponse {
    // Edge is "ready" once at least one agent session has registered.
    // Before that, an LB would route traffic that has nowhere to go.
    if metrics.active_sessions.get() > 0 {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no agent sessions").into_response()
    }
}
