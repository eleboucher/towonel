use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::time::now_ms;
use tracing::warn;
use utoipa::ToSchema;

use crate::hub::auth::middleware::{OperatorPrincipal, Principal};
use crate::hub::db::admin_actions::NewAdminAction;

use super::{
    AppState, Pagination, internal_error, invalid_request, json_ok, json_ok_paged, paginate,
};

const CODE_BYTES: usize = 18;
const ID_BYTES: usize = 16;
const ROLES: &[&str] = &["user", "operator"];

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct CreateSignupInviteRequest {
    /// `user` or `operator`. Defaults to `user`.
    #[serde(default = "default_role")]
    role: String,
    #[serde(default)]
    expires_in_days: Option<u32>,
    #[serde(default)]
    recipient_email: Option<String>,
}

fn default_role() -> String {
    "user".to_string()
}

#[derive(Debug, Serialize, ToSchema)]
struct CreateSignupInviteResponse {
    code: String,
    role: String,
    expires_at_ms: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
struct SignupInviteEntry {
    code: String,
    role: String,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
    redeemed_by_user_id: Option<String>,
    redeemed_at_ms: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/v1/signup-invites",
    tag = "signup-invites",
    request_body = CreateSignupInviteRequest,
    responses(
        (status = 200, description = "Signup invite created", body = CreateSignupInviteResponse),
        (status = 400, description = "Invalid role or recipient email"),
    ),
    security(("operator_key" = [])),
)]
pub(super) async fn post_signup_invite(
    State(state): State<Arc<AppState>>,
    OperatorPrincipal(actor): OperatorPrincipal,
    axum::Json(body): axum::Json<CreateSignupInviteRequest>,
) -> Response {
    if !ROLES.contains(&body.role.as_str()) {
        return invalid_request("role must be 'user' or 'operator'");
    }

    // Validate + normalize so a typo doesn't produce an invite that
    // can never be redeemed (binding check compares normalized forms).
    let recipient_email_normalized = match body.recipient_email.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if let Err(msg) = crate::hub::api::auth::validate_email(trimmed) {
                return invalid_request(msg);
            } else {
                Some(crate::hub::db::users::normalize_email(trimmed))
            }
        }
        None => None,
    };

    let now = now_ms_i64();
    let expires_at_ms = body
        .expires_in_days
        .map(|d| now.saturating_add(i64::from(d) * 24 * 60 * 60 * 1000));
    let code = random_code(CODE_BYTES);

    if let Err(e) = state
        .db
        .insert_signup_invite(
            &code,
            &body.role,
            expires_at_ms,
            recipient_email_normalized.as_deref(),
            now,
        )
        .await
    {
        warn!(error = %e, "insert_signup_invite failed");
        return internal_error();
    }

    // Send to the normalized form so mail "To:", audit, and the
    // claim-time comparison all use the same string.
    if let (Some(to), Some(mailer)) = (recipient_email_normalized.as_deref(), state.mailer.as_ref())
        && let Err(e) = mailer.send_signup_invite(to, &code).await
    {
        warn!(error = %e, recipient = %to, "send_signup_invite mail failed");
    }

    let (actor_kind, actor_user_id) = principal_actor(&actor);
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(ID_BYTES),
            actor_user_id: actor_user_id.as_deref(),
            actor_kind,
            action: "signup_invite.create",
            target_kind: "signup_invite",
            target_id: Some(&code),
            metadata: Some(serde_json::json!({
                "role": body.role,
                "expires_at_ms": expires_at_ms,
            })),
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action failed");
    }

    json_ok(CreateSignupInviteResponse {
        code,
        role: body.role,
        expires_at_ms,
    })
}

#[utoipa::path(
    get,
    path = "/v1/signup-invites",
    tag = "signup-invites",
    params(
        ("limit" = Option<usize>, Query, description = "Page size; omit to return all"),
        ("offset" = Option<usize>, Query, description = "Page offset (default 0)"),
    ),
    responses((status = 200, description = "Signup invites; total in X-Total-Count", body = [SignupInviteEntry])),
    security(("operator_key" = [])),
)]
pub(super) async fn list_signup_invites(
    State(state): State<Arc<AppState>>,
    _operator: OperatorPrincipal,
    Query(page): Query<Pagination>,
) -> Response {
    let rows = match state.db.list_signup_invites().await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_signup_invites failed");
            return internal_error();
        }
    };
    let entries: Vec<SignupInviteEntry> = rows
        .into_iter()
        .map(|r| SignupInviteEntry {
            code: r.code,
            role: r.role,
            created_at_ms: r.created_at_ms,
            expires_at_ms: r.expires_at_ms,
            redeemed_by_user_id: r.redeemed_by_user_id,
            redeemed_at_ms: r.redeemed_at_ms,
        })
        .collect();
    let (entries, total) = paginate(entries, &page);
    json_ok_paged(entries, total)
}

pub(super) fn random_code(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    getrandom::fill(&mut buf).expect("OS RNG");
    B64.encode(buf)
}

pub(super) fn now_ms_i64() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

pub(super) fn principal_actor(p: &Principal) -> (&'static str, Option<String>) {
    match p {
        Principal::OperatorKey => ("operator_key", None),
        Principal::User(u) => ("user", Some(u.id.clone())),
    }
}
