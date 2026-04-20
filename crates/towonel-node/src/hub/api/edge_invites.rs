use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use towonel_common::invite::{EdgeInviteToken, hash_invite_secret};
use tracing::warn;

use towonel_common::time::now_ms;

use super::db::{EdgeInviteRow, InviteStatus};
use super::{AppState, internal_error, invalid_request, json_ok, not_found, parse_invite_id};

#[derive(Debug, Deserialize)]
pub(super) struct CreateEdgeInviteRequest {
    /// Optional human-readable label. A random name is generated when absent.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateEdgeInviteResponse {
    status: &'static str,
    token: String,
    invite_id: String,
    name: String,
    edge_node_id: String,
}

pub(super) async fn post_edge_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CreateEdgeInviteRequest>,
) -> Response {
    let name = match req.name {
        Some(n) if !n.trim().is_empty() => n,
        _ => towonel_common::random_name::random_name(),
    };

    let token = EdgeInviteToken::generate(state.public_url.clone());
    let edge_signing_key = SigningKey::from_bytes(&token.node_seed);
    let edge_node_id = edge_signing_key.verifying_key().to_bytes();

    let pending = super::db::PendingEdgeInvite {
        invite_id: token.invite_id,
        name: &name,
        secret_hash: hash_invite_secret(&state.invite_hash_key, &token.invite_secret),
        edge_node_id,
        created_at_ms: now_ms(),
    };

    if let Err(e) = state.db.insert_edge_invite(&pending).await {
        warn!(error = %e, "failed to insert edge invite");
        return internal_error();
    }

    json_ok(CreateEdgeInviteResponse {
        status: "ok",
        token: token.encode(),
        invite_id: token.invite_id_b64(),
        name,
        edge_node_id: hex::encode(edge_node_id),
    })
}

#[derive(Debug, Serialize)]
pub(super) struct EdgeInviteSummary {
    invite_id: String,
    name: String,
    status: InviteStatus,
    edge_node_id: String,
    created_at_ms: u64,
}

impl From<EdgeInviteRow> for EdgeInviteSummary {
    fn from(row: EdgeInviteRow) -> Self {
        Self {
            invite_id: B64.encode(row.invite_id),
            name: row.name,
            status: row.status,
            edge_node_id: hex::encode(row.edge_node_id),
            created_at_ms: row.created_at_ms,
        }
    }
}

pub(super) async fn list_edge_invites_route(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_edge_invites().await {
        Ok(rows) => json_ok(serde_json::json!({
            "invites": rows.into_iter().map(EdgeInviteSummary::from).collect::<Vec<_>>()
        })),
        Err(e) => {
            warn!(error = %e, "failed to list edge invites");
            internal_error()
        }
    }
}

pub(super) async fn delete_edge_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    match state.db.revoke_edge_invite(&invite_id).await {
        Ok(true) => axum::Json(serde_json::json!({"status": "revoked"})).into_response(),
        Ok(false) => not_found("edge invite is not pending or does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to revoke edge invite");
            internal_error()
        }
    }
}
