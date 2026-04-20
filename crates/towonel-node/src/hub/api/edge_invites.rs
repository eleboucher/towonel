use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::invite::{EdgeInviteToken, hash_invite_secret};
use tracing::warn;
use zeroize::Zeroizing;

use towonel_common::time::now_ms;

use super::db::{EdgeInviteRow, InviteStatus};
use super::{
    AppState, conflict, constant_time_eq, internal_error, invalid_request, json_ok, not_found,
    parse_invite_id, unauthorized,
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

const EDGE_MAX_TTL_SECS: u64 = 30 * 24 * 3600;

pub(super) async fn post_edge_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CreateEdgeInviteRequest>,
) -> Response {
    let name = match req.name {
        Some(n) if !n.trim().is_empty() => n,
        _ => towonel_common::random_name::random_name(),
    };
    if req.expires_in_secs == 0 || req.expires_in_secs > EDGE_MAX_TTL_SECS {
        return invalid_request(format!(
            "expires_in_secs must be in 1..={EDGE_MAX_TTL_SECS}"
        ));
    }

    let token = EdgeInviteToken::generate(state.public_url.clone());
    let created_at_ms = now_ms();
    let expires_at_ms = created_at_ms + req.expires_in_secs * 1000;

    let pending = super::db::PendingEdgeInvite {
        invite_id: token.invite_id,
        name: &name,
        secret_hash: hash_invite_secret(&state.invite_hash_key, &token.invite_secret),
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
    status: InviteStatus,
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
    /// Hex-encoded iroh `EndpointId` (32 bytes) that this edge will use to
    /// authenticate subsequent requests.
    edge_node_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RedeemEdgeInviteResponse {
    status: &'static str,
    hub_node_id: iroh::EndpointId,
    name: String,
}

pub(super) async fn redeem_edge_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RedeemEdgeInviteRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&req.invite_id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    let Ok(invite_secret) = B64.decode(&req.invite_secret).map(Zeroizing::new) else {
        return invalid_request("invite_secret is not valid base64url");
    };
    let edge_node_id: [u8; 32] = match hex::FromHex::from_hex(&req.edge_node_id) {
        Ok(arr) => arr,
        Err(_) => return invalid_request("edge_node_id must be 64 hex chars (32 bytes)"),
    };

    let invite = match state.db.get_edge_invite(&invite_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            // Unified unauthorized: unknown / revoked / expired / wrong secret
            // all return 401 so callers can't probe invite state without the
            // secret. Server-side logs preserve the real reason.
            warn!(invite_id = %req.invite_id, "edge invite redemption: not found");
            return unauthorized("edge invite redemption failed");
        }
        Err(e) => {
            warn!(error = %e, "failed to fetch edge invite");
            return internal_error();
        }
    };

    let secret_ok = constant_time_eq(
        &hash_invite_secret(&state.invite_hash_key, &invite_secret),
        &invite.secret_hash,
    );
    let status_ok = matches!(invite.status, InviteStatus::Pending);
    let not_expired = now_ms() <= invite.expires_at_ms;
    if !(secret_ok && status_ok && not_expired) {
        warn!(
            invite_id = %req.invite_id,
            secret_ok,
            status = ?invite.status,
            expired = !not_expired,
            "edge invite redemption rejected"
        );
        return unauthorized("edge invite redemption failed");
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
        hub_node_id: state.identity.node_id,
        name: invite.name,
    })
}
