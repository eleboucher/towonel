use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::identity::TenantKeypair;
use towonel_common::invite::{InviteToken, hash_invite_secret};
use tracing::warn;

use towonel_common::time::now_ms;

use crate::hub::auth::middleware::Principal;
use crate::hub::db::tenant_ownership::NewTenantOwnership;

use super::db::{InviteRow, InviteStatus, PendingInvite};
use super::{
    AppState, conflict, internal_error, invalid_request, json_ok, not_found, parse_invite_id,
};

#[derive(Debug, Deserialize)]
pub(super) struct CreateInviteRequest {
    /// Optional human-readable label. A random name is generated when absent.
    name: Option<String>,
    hostnames: Vec<String>,
    /// `None` (or 0) means the token never expires. The hub caps finite
    /// values at 30 days; the operator tool sets sensible defaults.
    #[serde(default)]
    expires_in_secs: Option<u64>,
    /// Operator-key only: attach the new invite to an existing hub user.
    #[serde(default)]
    owner_email: Option<String>,
    /// Region the agent belongs to. Absent/empty resolves to `EU`.
    #[serde(default)]
    region: Option<String>,
    /// Extra regions whose edges the agent also dials for failover.
    #[serde(default)]
    failover_regions: Vec<String>,
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

#[expect(
    clippy::too_many_lines,
    reason = "linear happy path with explicit rollback branches; splitting hides the ordering"
)]
pub(super) async fn post_invite(
    State(state): State<Arc<AppState>>,
    principal: Principal,
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

    let owner_user_id: Option<String> = match (&principal, req.owner_email.as_deref()) {
        (Principal::User(u), _) => Some(u.id.clone()),
        (Principal::OperatorKey, Some(email)) => {
            let email = email.trim();
            if email.is_empty() {
                return invalid_request("owner_email must be non-empty when supplied");
            }
            match state.db.find_user_by_email(email).await {
                Ok(Some(u)) => Some(u.id),
                Ok(None) => {
                    return not_found(format!("no user with email {email}"));
                }
                Err(e) => {
                    warn!(error = %e, "find_user_by_email failed");
                    return internal_error();
                }
            }
        }
        (Principal::OperatorKey, None) => None,
    };

    let _guard = state.invite_lock.lock().await;

    let candidates_lower: Vec<String> = req.hostnames.iter().map(|h| h.to_lowercase()).collect();
    {
        let policy = state.policy.load();
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

    // Uppercased so region matching is case-insensitive.
    let region = req
        .region
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_uppercase);
    let failover_regions: Vec<String> = req
        .failover_regions
        .iter()
        .map(|r| r.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    let pending = PendingInvite {
        invite_id: token.invite_id,
        name: &name,
        hostnames: &req.hostnames,
        secret_hash: hash_invite_secret(&state.invite_hash_key, &token.invite_secret),
        tenant_id,
        pq_public_key: &pq_public_key,
        expires_at_ms,
        created_at_ms,
        region,
        failover_regions: &failover_regions,
    };

    if let Err(e) = state.db.insert_invite(&pending).await {
        warn!(error = %e, "failed to insert invite");
        return internal_error();
    }

    if let Some(user_id) = &owner_user_id
        && let Err(e) = state
            .db
            .insert_tenant_ownership(NewTenantOwnership {
                user_id,
                tenant_id: tenant_id.as_bytes(),
                invite_id: &token.invite_id,
                display_name: &name,
                now_ms: i64::try_from(created_at_ms).unwrap_or(i64::MAX),
            })
            .await
    {
        warn!(error = %e, "insert_tenant_ownership failed");
        if let Err(rev_err) = state.db.revoke_invite(&token.invite_id).await {
            warn!(error = %rev_err, "revoke_invite during ownership rollback");
        }
        return internal_error();
    }

    state.policy_update(|policy| {
        policy.register_tenant(
            &tenant_id,
            pq_public_key.clone(),
            req.hostnames.iter().cloned(),
        );
    });

    json_ok(CreateInviteResponse {
        status: "ok",
        token: token.encode().to_string(),
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

#[derive(Debug, Deserialize)]
pub(super) struct ListInvitesQuery {
    /// `all` is honored only for operator principals; everyone else gets the
    /// ownership-scoped list regardless of what they pass.
    #[serde(default)]
    scope: Option<String>,
}

pub(super) async fn list_invites(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Query(query): Query<ListInvitesQuery>,
) -> Response {
    let rows = match state.db.list_invites().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to list invites");
            return internal_error();
        }
    };

    let want_all = matches!(query.scope.as_deref(), Some("all")) && principal.is_operator();

    let filtered: Vec<InviteRow> = match (&principal, want_all) {
        (_, true) | (Principal::OperatorKey, _) => rows,
        (Principal::User(u), false) => {
            let owned = match state.db.list_invite_ids_for_user(&u.id).await {
                Ok(ids) => ids,
                Err(e) => {
                    warn!(error = %e, "list_invite_ids_for_user failed");
                    return internal_error();
                }
            };
            let owned_set: std::collections::HashSet<Vec<u8>> = owned.into_iter().collect();
            rows.into_iter()
                .filter(|r| owned_set.contains(r.invite_id.as_slice()))
                .collect()
        }
    };

    json_ok(serde_json::json!({
        "invites": filtered.into_iter().map(InviteSummary::from).collect::<Vec<_>>()
    }))
}

#[derive(Debug, Deserialize)]
pub(super) struct AddHostnamesRequest {
    hostnames: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct AddHostnamesResponse {
    status: &'static str,
    hostnames: Vec<String>,
}

pub(super) async fn post_invite_hostnames(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<AddHostnamesRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&id) else {
        return invalid_request("invite_id is not valid base64url");
    };

    if req.hostnames.is_empty() {
        return invalid_request("at least one hostname is required");
    }

    for h in &req.hostnames {
        if let Err(e) = towonel_common::hostname::validate_hostname(h) {
            return invalid_request(format!("invalid hostname `{h}`: {e}"));
        }
    }

    let row = match state.db.get_invite(&invite_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to look up invite");
            return internal_error();
        }
    };

    if let Principal::User(u) = &principal
        && u.role != "operator"
    {
        let owned = match state
            .db
            .find_tenant_ownership_by_invite(&u.id, &invite_id)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, "find_tenant_ownership_by_invite failed");
                return internal_error();
            }
        };
        if owned.is_none() {
            return not_found("invite does not exist");
        }
    }

    let _guard = state.invite_lock.lock().await;

    let candidates_lower: Vec<String> = req.hostnames.iter().map(|h| h.to_lowercase()).collect();
    {
        let policy = state.policy.load();
        for (h_lower, h_orig) in candidates_lower.iter().zip(req.hostnames.iter()) {
            for (tenant, patterns) in policy.iter_patterns() {
                if patterns.contains(h_lower) && tenant != &row.tenant_id {
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

    match state
        .db
        .add_invite_hostnames(&invite_id, &req.hostnames)
        .await
    {
        Ok(true) => {
            state.policy_update(|policy| {
                for hostname in &req.hostnames {
                    policy.add_hostname(&row.tenant_id, hostname);
                }
            });
            json_ok(AddHostnamesResponse {
                status: "ok",
                hostnames: req.hostnames,
            })
        }
        Ok(false) => conflict(
            "hostname_conflict",
            "all hostnames already exist on this invite",
        ),
        Err(e) => {
            warn!(error = %e, "add_invite_hostnames failed");
            internal_error()
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct RemoveHostnameResponse {
    status: &'static str,
    hostname: String,
    remaining_hostnames: Vec<String>,
}

pub(super) async fn delete_invite_hostname(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path((invite_id_str, hostname)): Path<(String, String)>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&invite_id_str) else {
        return invalid_request("invite_id is not valid base64url");
    };

    if let Err(e) = towonel_common::hostname::validate_hostname(&hostname) {
        return invalid_request(format!("invalid hostname `{hostname}`: {e}"));
    }

    let row = match state.db.get_invite(&invite_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to look up invite");
            return internal_error();
        }
    };

    if row.status == InviteStatus::Revoked {
        return not_found("invite does not exist");
    }

    if let Principal::User(u) = &principal
        && u.role != "operator"
    {
        let owned = match state
            .db
            .find_tenant_ownership_by_invite(&u.id, &invite_id)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, "find_tenant_ownership_by_invite failed");
                return internal_error();
            }
        };
        if owned.is_none() {
            return not_found("invite does not exist");
        }
    }

    let _guard = state.invite_lock.lock().await;

    // Re-read under the lock so two concurrent removals can't both pass the
    // "more than one hostname" check and strand the invite with none — which
    // post_invite forbids on creation.
    let current = match state.db.get_invite(&invite_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to re-read invite under lock");
            return internal_error();
        }
    };
    if current.hostnames.len() <= 1 {
        return invalid_request("an invite must keep at least one hostname");
    }

    match state.db.remove_invite_hostname(&invite_id, &hostname).await {
        Ok(true) => {
            state.policy_update(|policy| {
                policy.remove_hostname(&row.tenant_id, &hostname);
            });
            let Some(updated_row) = state.db.get_invite(&invite_id).await.ok().flatten() else {
                warn!("failed to fetch updated invite after removing hostname");
                return internal_error();
            };
            json_ok(RemoveHostnameResponse {
                status: "ok",
                hostname,
                remaining_hostnames: updated_row.hostnames,
            })
        }
        Ok(false) => not_found("hostname not found on invite"),
        Err(e) => {
            warn!(error = %e, "remove_invite_hostname failed");
            internal_error()
        }
    }
}

pub(super) async fn delete_invite(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&id) else {
        return invalid_request("invite_id is not valid base64url");
    };

    let row = match state.db.get_invite(&invite_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("invite does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to look up invite");
            return internal_error();
        }
    };

    if row.status == InviteStatus::Revoked {
        return not_found("invite does not exist");
    }

    if let Principal::User(u) = &principal
        && u.role != "operator"
    {
        let owned = match state
            .db
            .find_tenant_ownership_by_invite(&u.id, &invite_id)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, "find_tenant_ownership_by_invite failed");
                return internal_error();
            }
        };
        if owned.is_none() {
            return not_found("invite does not exist");
        }
    }

    // Serialize the revoke+policy_update window against concurrent invite
    // creation so the policy snapshot never loses a freshly-created tenant
    // through a CoW race.
    let _guard = state.invite_lock.lock().await;
    match state.db.revoke_invite(&invite_id).await {
        Ok(true) => {
            let tid = row.tenant_id;
            if let Err(e) = state.db.remove_tenant(&tid, now_ms()).await {
                warn!(error = %e, tenant = %tid, "failed to persist tenant removal on invite revoke");
                return internal_error();
            }
            state.policy_update(|p| p.remove(&tid));
            json_ok(serde_json::json!({"status": "revoked"}))
        }
        Ok(false) => not_found("invite is already revoked or does not exist"),
        Err(e) => {
            warn!(error = %e, "failed to revoke invite");
            internal_error()
        }
    }
}
