use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use prometheus::{Encoder, TextEncoder};

use super::AppState;

pub(super) async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let mut buf = Vec::new();
    if let Err(e) = TextEncoder::new().encode(&state.metrics.registry().gather(), &mut buf) {
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
