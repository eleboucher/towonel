use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::Serialize;

use super::super::peer_status::PeerStatus;
use super::{AppState, json_ok};

#[derive(Serialize)]
struct FederationStatusResponse {
    peers: HashMap<String, PeerStatus>,
}

pub(super) async fn get_status(State(state): State<Arc<AppState>>) -> Response {
    let peers = state.peer_statuses.read().await.clone();
    json_ok(FederationStatusResponse { peers })
}
