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

/// Edge observability surface. Counters are wrapped in cheap `Arc`s by
/// prometheus-client, so cloning `EdgeMetrics` around tasks is free.
#[derive(Clone)]
pub struct EdgeMetrics {
    pub active_connections: Gauge,
    pub total_connections: Counter,
    pub total_bytes_in: Counter,
    pub total_bytes_out: Counter,
    /// The Registry owns the names/help strings and borrows the counters
    /// above. We only touch it from the `/metrics` handler.
    registry: Arc<Registry>,
}

impl EdgeMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let active_connections = Gauge::default();
        let total_connections = Counter::default();
        let total_bytes_in = Counter::default();
        let total_bytes_out = Counter::default();

        registry.register(
            "towonel_edge_active_connections",
            "Active tunneled connections",
            active_connections.clone(),
        );
        registry.register(
            "towonel_edge_total_connections",
            "Total connections handled",
            total_connections.clone(),
        );
        registry.register(
            "towonel_edge_bytes_in",
            "Total bytes received from clients",
            total_bytes_in.clone(),
        );
        registry.register(
            "towonel_edge_bytes_out",
            "Total bytes sent to clients",
            total_bytes_out.clone(),
        );

        Self {
            active_connections,
            total_connections,
            total_bytes_in,
            total_bytes_out,
            registry: Arc::new(registry),
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
