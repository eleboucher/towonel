use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tracing::warn;
use turbo_common::identity::{PqPublicKey, TenantId};
use turbo_common::invite::{InviteToken, hash_invite_secret};

use turbo_common::time::now_ms;

use super::db::{InviteRow, PendingInvite};
use super::{
    AppState, conflict, constant_time_eq, gone, internal_error, invalid_request, json_ok,
    not_found, parse_invite_id, unauthorized,
};

#[derive(Debug, Deserialize)]
pub(super) struct CreateInviteRequest {
    name: String,
    hostnames: Vec<String>,
    /// Relative TTL from now. 48h default enforced by the operator tool;
    /// the hub trusts whatever it's told but caps at 30 days.
    expires_in_secs: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateInviteResponse {
    status: &'static str,
    token: String,
    invite_id: String,
    expires_at_ms: u64,
}

pub(super) async fn post_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CreateInviteRequest>,
) -> Response {
    if req.name.trim().is_empty() {
        return invalid_request("name must not be empty");
    }
    if req.hostnames.is_empty() {
        return invalid_request("at least one hostname is required");
    }
    for h in &req.hostnames {
        if let Err(e) = turbo_common::hostname::validate_hostname(h) {
            return invalid_request(format!("invalid hostname `{h}`: {e}"));
        }
    }

    const MAX_TTL_SECS: u64 = 30 * 24 * 3600;
    if req.expires_in_secs == 0 || req.expires_in_secs > MAX_TTL_SECS {
        return invalid_request(format!("expires_in_secs must be in 1..={MAX_TTL_SECS}"));
    }

    let _guard = state.invite_lock.lock().await;

    let candidates_lower: Vec<String> = req.hostnames.iter().map(|h| h.to_lowercase()).collect();
    let policy = state.policy.read().await;
    for (h_lower, h_orig) in candidates_lower.iter().zip(req.hostnames.iter()) {
        for (tenant, patterns) in policy.iter_patterns() {
            if patterns.contains(h_lower) {
                return conflict(
                    "hostname_conflict",
                    format!("hostname `{h_orig}` is already owned by tenant {tenant}"),
                );
            }
        }
    }
    drop(policy);

    match state.db.any_pending_invite_claims(&candidates_lower).await {
        Ok(Some(h)) => {
            return conflict(
                "hostname_conflict",
                format!("hostname `{h}` is already reserved by a pending invite"),
            );
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "failed to check pending invites");
            return internal_error();
        }
    }

    let token = InviteToken::generate(state.public_url.clone());

    let created_at_ms = now_ms();
    let expires_at_ms = created_at_ms + req.expires_in_secs * 1000;

    let pending = PendingInvite {
        invite_id: token.invite_id,
        name: &req.name,
        hostnames: &req.hostnames,
        secret_hash: hash_invite_secret(&token.invite_secret),
        expires_at_ms,
        created_at_ms,
    };

    if let Err(e) = state.db.insert_invite(&pending).await {
        warn!(error = %e, "failed to insert invite");
        return internal_error();
    }

    json_ok(CreateInviteResponse {
        status: "ok",
        token: token.encode(),
        invite_id: token.invite_id_b64(),
        expires_at_ms,
    })
}

#[derive(Debug, Serialize)]
pub(super) struct InviteSummary {
    invite_id: String,
    name: String,
    hostnames: Vec<String>,
    status: String,
    expires_at_ms: u64,
    tenant_id: Option<String>,
    redeemed_at_ms: Option<u64>,
    created_at_ms: u64,
}

impl From<InviteRow> for InviteSummary {
    fn from(row: InviteRow) -> Self {
        Self {
            invite_id: B64.encode(row.invite_id),
            name: row.name,
            hostnames: row.hostnames,
            status: row.status,
            expires_at_ms: row.expires_at_ms,
            tenant_id: row.tenant_id.map(|t| t.to_string()),
            redeemed_at_ms: row.redeemed_at_ms,
            created_at_ms: row.created_at_ms,
        }
    }
}

pub(super) async fn list_invites(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_invites().await {
        Ok(rows) => json_ok(serde_json::json!({
            "invites": rows.into_iter().map(InviteSummary::from).collect::<Vec<_>>()
        })),
        Err(e) => {
            warn!(error = %e, "failed to list invites");
            internal_error()
        }
    }
}

pub(super) async fn delete_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    match state.db.revoke_invite(&invite_id).await {
        Ok(true) => {
            #[derive(Serialize)]
            struct Ok {
                status: &'static str,
            }
            axum::Json(Ok { status: "revoked" }).into_response()
        }
        Ok(false) => not_found("invite is not pending or does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to revoke invite");
            internal_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RedeemRequest {
    invite_id: String,
    invite_secret: String,
    /// Base64url-encoded ML-DSA-65 public key (1952 bytes).
    /// The hub derives `tenant_id = sha256(tenant_pq_public_key)`.
    tenant_pq_public_key: String,
    agent_node_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RedeemResponse {
    status: &'static str,
    tenant_id: String,
    hostnames: Vec<String>,
    hub_node_id: String,
    edge_node_id: Option<String>,
    edge_addresses: Vec<String>,
}

pub(super) async fn redeem_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RedeemRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&req.invite_id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    let Ok(invite_secret) = B64.decode(&req.invite_secret) else {
        return invalid_request("invite_secret is not valid base64url");
    };
    let pq_public_key: PqPublicKey = match req.tenant_pq_public_key.parse() {
        Ok(pk) => pk,
        Err(e) => return invalid_request(format!("invalid tenant_pq_public_key: {e}")),
    };
    let tenant_id = TenantId::derive(&pq_public_key);

    let _agent_id: turbo_common::identity::NodeId = match req.agent_node_id.parse() {
        Ok(a) => a,
        Err(e) => return invalid_request(format!("invalid agent_node_id: {e}")),
    };

    let invite = match state.db.get_invite(&invite_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to fetch invite");
            return internal_error();
        }
    };

    match invite.status.as_str() {
        "pending" => {}
        "redeemed" => {
            if !constant_time_eq(&hash_invite_secret(&invite_secret), &invite.secret_hash) {
                return unauthorized("invite_secret does not match");
            }

            if let Some(old_tid) = invite.tenant_id {
                state.db.remove_tenant(&old_tid, now_ms()).await.ok();
                state.policy.write().await.remove(&old_tid);
            }

            if let Err(e) = state
                .db
                .re_redeem_invite(&invite_id, &tenant_id, &pq_public_key, now_ms())
                .await
            {
                warn!(error = %e, "failed to re-redeem invite");
                return internal_error();
            }

            let mut policy = state.policy.write().await;
            policy.register_tenant(
                &tenant_id,
                pq_public_key.clone(),
                invite.hostnames.iter().cloned(),
            );

            return json_ok(RedeemResponse {
                status: "ok",
                tenant_id: tenant_id.to_string(),
                hostnames: invite.hostnames,
                hub_node_id: state.node_id.clone(),
                edge_node_id: state.edge_node_id.clone(),
                edge_addresses: state.edge_addresses.clone(),
            });
        }
        "revoked" => return conflict("invite_revoked", "invite has been revoked"),
        _ => return internal_error(),
    }

    if now_ms() > invite.expires_at_ms {
        return gone("invite has expired");
    }

    if !constant_time_eq(&hash_invite_secret(&invite_secret), &invite.secret_hash) {
        return unauthorized("invite_secret does not match");
    }

    {
        let policy = state.policy.read().await;
        for h in &invite.hostnames {
            for (owner, patterns) in policy.iter_patterns() {
                if patterns.contains(&h.to_lowercase()) && *owner != tenant_id {
                    return conflict(
                        "hostname_conflict",
                        format!("hostname `{h}` is already owned by another tenant"),
                    );
                }
            }
        }
    }

    match state
        .db
        .redeem_invite(&invite_id, &tenant_id, &pq_public_key, now_ms())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return conflict(
                "invite_already_redeemed",
                "invite was redeemed concurrently",
            );
        }
        Err(e) => {
            warn!(error = %e, "failed to redeem invite");
            return internal_error();
        }
    }

    {
        let mut policy = state.policy.write().await;
        policy.register_tenant(
            &tenant_id,
            pq_public_key.clone(),
            invite.hostnames.iter().cloned(),
        );
    }

    json_ok(RedeemResponse {
        status: "ok",
        tenant_id: tenant_id.to_string(),
        hostnames: invite.hostnames,
        hub_node_id: state.node_id.clone(),
        edge_node_id: state.edge_node_id.clone(),
        edge_addresses: state.edge_addresses.clone(),
    })
}
