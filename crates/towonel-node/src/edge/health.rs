use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{Router, get};
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use serde::Serialize;
use towonel_common::metrics::{register_counter, register_gauge};

/// Edge observability surface. Cheap to clone: the `prometheus` metric
/// types are internally `Arc`-shared and the `Registry` is held as an `Arc`.
#[derive(Clone)]
pub struct EdgeMetrics {
    pub active_connections: IntGauge,
    pub total_connections: IntCounter,
    pub total_bytes_in: IntCounter,
    pub total_bytes_out: IntCounter,
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
            registry: Arc::new(r),
        }
    }
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
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}
