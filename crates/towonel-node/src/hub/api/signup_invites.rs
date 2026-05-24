use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::auth::middleware::{OperatorPrincipal, Principal};
use crate::hub::db::admin_actions::NewAdminAction;

use super::{AppState, internal_error, invalid_request, json_ok};

const CODE_BYTES: usize = 18;
const ID_BYTES: usize = 16;
const ROLES: &[&str] = &["user", "operator"];

#[derive(Debug, Deserialize)]
pub(super) struct MintRequest {
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

#[derive(Debug, Serialize)]
struct MintResponse {
    code: String,
    role: String,
    expires_at_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
struct SignupInviteEntry {
    code: String,
    role: String,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
    redeemed_by_user_id: Option<String>,
    redeemed_at_ms: Option<i64>,
}

pub(super) async fn post_signup_invite(
    State(state): State<Arc<AppState>>,
    OperatorPrincipal(actor): OperatorPrincipal,
    axum::Json(body): axum::Json<MintRequest>,
) -> Response {
    if !ROLES.contains(&body.role.as_str()) {
        return invalid_request("role must be 'user' or 'operator'");
    }

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
            body.recipient_email.as_deref(),
            now,
        )
        .await
    {
        warn!(error = %e, "insert_signup_invite failed");
        return internal_error();
    }

    if let (Some(to), Some(mailer)) = (body.recipient_email.as_deref(), state.mailer.as_ref())
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

    json_ok(MintResponse {
        code,
        role: body.role,
        expires_at_ms,
    })
}

pub(super) async fn list_signup_invites(
    State(state): State<Arc<AppState>>,
    _operator: OperatorPrincipal,
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
    json_ok(entries)
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
