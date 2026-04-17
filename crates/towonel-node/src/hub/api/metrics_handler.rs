use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use prometheus_client::encoding::text::encode;

use super::AppState;

pub(super) async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let mut body = String::new();
    if let Err(e) = encode(&mut body, state.metrics.registry()) {
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
