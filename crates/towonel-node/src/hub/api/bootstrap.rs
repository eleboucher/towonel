use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::invite::hash_invite_secret;
use tracing::warn;
use zeroize::Zeroizing;

use towonel_common::time::now_ms;

use super::db::InviteStatus;
use super::{
    AppState, constant_time_eq, gone, internal_error, invalid_request, json_ok, not_found,
    parse_invite_id, unauthorized,
};

#[derive(Debug, Deserialize)]
pub(super) struct BootstrapRequest {
    invite_id: String,
    invite_secret: String,
}

#[derive(Debug, Serialize)]
pub(super) struct BootstrapResponse {
    status: &'static str,
    tenant_id: String,
    hostnames: Vec<String>,
    hub_node_id: String,
    edge_node_id: Option<String>,
    edge_addresses: Vec<String>,
}

pub(super) async fn post_bootstrap(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<BootstrapRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&req.invite_id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    let Ok(invite_secret) = B64.decode(&req.invite_secret).map(Zeroizing::new) else {
        return invalid_request("invite_secret is not valid base64url");
    };

    let invite = match state.db.get_invite(&invite_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to fetch invite");
            return internal_error();
        }
    };

    // Return the SAME error for both wrong-secret and revoked-with-right-secret
    // so an attacker who obtains an invite_secret can't distinguish a revoked
    // invite from a mistyped secret. Legitimate clients see the generic message;
    // hub operators can inspect the server log (below) for the real cause.
    let secret_ok = constant_time_eq(
        &hash_invite_secret(&state.invite_hash_key, &invite_secret),
        &invite.secret_hash,
    );
    let revoked = matches!(invite.status, InviteStatus::Revoked);
    if !secret_ok || revoked {
        if secret_ok && revoked {
            tracing::info!(
                invite_id = %req.invite_id,
                "bootstrap rejected: invite is revoked (secret was valid)"
            );
        }
        return unauthorized("invite_secret is invalid or the invite has been revoked");
    }

    if invite.expires_at_ms.is_some_and(|e| now_ms() > e) {
        return gone("invite has expired");
    }

    json_ok(BootstrapResponse {
        status: "ok",
        tenant_id: invite.tenant_id.to_string(),
        hostnames: invite.hostnames,
        hub_node_id: state.identity.node_id.clone(),
        edge_node_id: state.identity.edge_node_id.clone(),
        edge_addresses: state.identity.edge_addresses.clone(),
    })
}
