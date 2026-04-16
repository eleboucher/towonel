use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tracing::warn;
use turbo_common::invite::{EdgeInviteToken, hash_invite_secret};

use turbo_common::time::now_ms;

use super::db::EdgeInviteRow;
use super::{
    AppState, conflict, constant_time_eq, gone, internal_error, invalid_request, json_ok,
    not_found, parse_invite_id, unauthorized,
};

#[derive(Debug, Deserialize)]
pub(super) struct CreateEdgeInviteRequest {
    /// Optional human-readable label. A random name is generated when absent.
    name: Option<String>,
    expires_in_secs: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateEdgeInviteResponse {
    status: &'static str,
    token: String,
    invite_id: String,
    name: String,
    expires_at_ms: u64,
}

pub(super) async fn post_edge_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CreateEdgeInviteRequest>,
) -> Response {
    let name = match req.name {
        Some(n) if !n.trim().is_empty() => n,
        _ => turbo_common::random_name::random_name(),
    };
    const MAX_TTL_SECS: u64 = 30 * 24 * 3600;
    if req.expires_in_secs == 0 || req.expires_in_secs > MAX_TTL_SECS {
        return invalid_request(format!("expires_in_secs must be in 1..={MAX_TTL_SECS}"));
    }

    let token = EdgeInviteToken::generate(state.public_url.clone());
    let created_at_ms = now_ms();
    let expires_at_ms = created_at_ms + req.expires_in_secs * 1000;

    let pending = super::db::PendingEdgeInvite {
        invite_id: token.invite_id,
        name: &name,
        secret_hash: hash_invite_secret(&token.invite_secret),
        expires_at_ms,
        created_at_ms,
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
        expires_at_ms,
    })
}

#[derive(Debug, Serialize)]
pub(super) struct EdgeInviteSummary {
    invite_id: String,
    name: String,
    status: String,
    expires_at_ms: u64,
    edge_node_id: Option<String>,
    redeemed_at_ms: Option<u64>,
    created_at_ms: u64,
}

impl From<EdgeInviteRow> for EdgeInviteSummary {
    fn from(row: EdgeInviteRow) -> Self {
        Self {
            invite_id: B64.encode(row.invite_id),
            name: row.name,
            status: row.status,
            expires_at_ms: row.expires_at_ms,
            edge_node_id: row.edge_node_id.map(hex::encode),
            redeemed_at_ms: row.redeemed_at_ms,
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

#[derive(Debug, Deserialize)]
pub(super) struct RedeemEdgeInviteRequest {
    invite_id: String,
    invite_secret: String,
    /// Hex-encoded iroh EndpointId (32-byte Ed25519 pubkey) that this edge
    /// will use to authenticate subsequent requests.
    edge_node_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RedeemEdgeInviteResponse {
    status: &'static str,
    hub_node_id: String,
    name: String,
}

pub(super) async fn redeem_edge_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RedeemEdgeInviteRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&req.invite_id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    let Ok(invite_secret) = B64.decode(&req.invite_secret) else {
        return invalid_request("invite_secret is not valid base64url");
    };
    let edge_node_id: [u8; 32] = match hex::decode(&req.edge_node_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    {
        Some(arr) => arr,
        None => return invalid_request("edge_node_id must be 64 hex chars (32 bytes)"),
    };

    let invite = match state.db.get_edge_invite(&invite_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return not_found("edge invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to fetch edge invite");
            return internal_error();
        }
    };

    match invite.status.as_str() {
        "pending" => {}
        "redeemed" => return conflict("invite_already_redeemed", "edge invite already redeemed"),
        "revoked" => return conflict("invite_revoked", "edge invite has been revoked"),
        _ => return internal_error(),
    }

    if now_ms() > invite.expires_at_ms {
        return gone("edge invite has expired");
    }

    if !constant_time_eq(&hash_invite_secret(&invite_secret), &invite.secret_hash) {
        return unauthorized("invite_secret does not match");
    }

    match state
        .db
        .redeem_edge_invite(&invite_id, &edge_node_id, &invite.name, now_ms())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return conflict(
                "invite_already_redeemed",
                "edge invite was redeemed concurrently",
            );
        }
        Err(e) => {
            warn!(error = %e, "failed to redeem edge invite");
            return internal_error();
        }
    }

    json_ok(RedeemEdgeInviteResponse {
        status: "ok",
        hub_node_id: state.node_id.clone(),
        name: invite.name,
    })
}
