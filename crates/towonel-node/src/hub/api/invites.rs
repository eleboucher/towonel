use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::identity::{TenantId, TenantKeypair};
use towonel_common::invite::{InviteToken, hash_invite_secret};
use tracing::warn;

use towonel_common::time::now_ms;

use super::db::{InviteRow, InviteStatus, PendingInvite};
use super::{
    AppState, conflict, internal_error, invalid_request, json_ok, not_found, parse_invite_id,
};
use crate::hub::federation::{TenantPush, push_tenant_sync};

#[derive(Debug, Deserialize)]
pub(super) struct CreateInviteRequest {
    /// Optional human-readable label. A random name is generated when absent.
    name: Option<String>,
    hostnames: Vec<String>,
    /// `None` (or 0) means the token never expires. The hub caps finite
    /// values at 30 days; the operator tool sets sensible defaults.
    #[serde(default)]
    expires_in_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateInviteResponse {
    status: &'static str,
    token: String,
    invite_id: String,
    tenant_id: String,
    name: String,
    /// `None` when the token never expires.
    expires_at_ms: Option<u64>,
}

const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

pub(super) async fn post_invite(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<CreateInviteRequest>,
) -> Response {
    let name = match req.name {
        Some(n) if !n.trim().is_empty() => n,
        _ => towonel_common::random_name::random_name(),
    };
    if req.hostnames.is_empty() {
        return invalid_request("at least one hostname is required");
    }
    for h in &req.hostnames {
        if let Err(e) = towonel_common::hostname::validate_hostname(h) {
            return invalid_request(format!("invalid hostname `{h}`: {e}"));
        }
    }
    let expires_at_ms = match req.expires_in_secs {
        None | Some(0) => None,
        Some(secs) if secs <= MAX_TTL_SECS => Some(now_ms() + secs * 1000),
        Some(secs) => {
            return invalid_request(format!(
                "expires_in_secs must be None (forever) or in 1..={MAX_TTL_SECS}, got {secs}"
            ));
        }
    };

    let _guard = state.invite_lock.lock().await;

    let candidates_lower: Vec<String> = req.hostnames.iter().map(|h| h.to_lowercase()).collect();
    {
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
    }

    match state.db.any_active_invite_claims(&candidates_lower).await {
        Ok(Some(h)) => {
            return conflict(
                "hostname_conflict",
                format!("hostname `{h}` is already reserved by an active invite"),
            );
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "failed to check active invites");
            return internal_error();
        }
    }

    // v2 token generation bundles a fresh tenant seed so pods can derive the
    // tenant signing key locally. The hub never persists the seed.
    let token = InviteToken::generate(state.public_url.clone());
    let tenant_kp = TenantKeypair::from_seed(token.tenant_seed);
    let tenant_id = tenant_kp.id();
    let pq_public_key = tenant_kp.public_key().clone();

    let created_at_ms = now_ms();

    let pending = PendingInvite {
        invite_id: token.invite_id,
        name: &name,
        hostnames: &req.hostnames,
        secret_hash: hash_invite_secret(&token.invite_secret),
        tenant_id,
        pq_public_key: &pq_public_key,
        expires_at_ms,
        created_at_ms,
    };

    if let Err(e) = state.db.insert_invite(&pending).await {
        warn!(error = %e, "failed to insert invite");
        return internal_error();
    }

    {
        let mut policy = state.policy.write().await;
        policy.register_tenant(
            &tenant_id,
            pq_public_key.clone(),
            req.hostnames.iter().cloned(),
        );
    }

    maybe_sync_push(&state, &tenant_id, &pq_public_key, &req.hostnames).await;

    json_ok(CreateInviteResponse {
        status: "ok",
        token: token.encode(),
        invite_id: token.invite_id_b64(),
        tenant_id: tenant_id.to_string(),
        name,
        expires_at_ms,
    })
}

#[derive(Debug, Serialize)]
pub(super) struct InviteSummary {
    invite_id: String,
    name: String,
    hostnames: Vec<String>,
    status: InviteStatus,
    expires_at_ms: Option<u64>,
    tenant_id: String,
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
            tenant_id: row.tenant_id.to_string(),
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

    let row = match state.db.get_invite(&invite_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to look up invite for revoke");
            return internal_error();
        }
    };

    match state.db.revoke_invite(&invite_id).await {
        Ok(true) => {
            let tid = row.tenant_id;
            if let Err(e) = state.db.remove_tenant(&tid, now_ms()).await {
                warn!(error = %e, tenant = %tid, "failed to persist tenant removal on invite revoke");
                return internal_error();
            }
            state.policy.write().await.remove(&tid);
            json_ok(serde_json::json!({"status": "revoked"}))
        }
        Ok(false) => not_found("invite is already revoked or does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to revoke invite");
            internal_error()
        }
    }
}

async fn maybe_sync_push(
    state: &AppState,
    tenant_id: &TenantId,
    pq_public_key: &towonel_common::identity::PqPublicKey,
    hostnames: &[String],
) {
    if !state.federation.sync_invite_redeem {
        return;
    }
    if state.federation.outbound.is_none() {
        return;
    }
    let body = TenantPush {
        tenant_id: tenant_id.to_string(),
        pq_public_key: pq_public_key.to_string(),
        hostnames: hostnames.to_vec(),
        registered_at_ms: now_ms(),
    };
    push_tenant_sync(state, &body).await;
}
