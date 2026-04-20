use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{Router, get};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::Serialize;
use towonel_common::metrics::{register_counter, register_gauge};

/// Edge observability surface. Cheap to clone: inner metrics hold `Arc`s.
#[derive(Clone)]
pub struct EdgeMetrics {
    pub active_connections: Gauge,
    pub total_connections: Counter,
    pub total_bytes_in: Counter,
    pub total_bytes_out: Counter,
    registry: Arc<Registry>,
}

impl EdgeMetrics {
    pub fn new() -> Self {
        let mut r = Registry::default();
        Self {
            active_connections: register_gauge(
                &mut r,
                "towonel_edge_active_connections",
                "Active tunneled connections",
            ),
            total_connections: register_counter(
                &mut r,
                "towonel_edge_total_connections",
                "Total connections handled",
            ),
            total_bytes_in: register_counter(
                &mut r,
                "towonel_edge_bytes_in",
                "Total bytes received from clients",
            ),
            total_bytes_out: register_counter(
                &mut r,
                "towonel_edge_bytes_out",
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
    let mut body = String::new();
    if let Err(e) = encode(&mut body, &metrics.registry) {
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
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub fn router(metrics: EdgeMetrics) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}
