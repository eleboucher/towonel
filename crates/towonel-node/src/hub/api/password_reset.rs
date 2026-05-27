use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::auth::password;
use crate::hub::db::auth_tokens::NewAuthToken;

use super::verify::{hash_token, mint_token};
use super::{AppState, error_response, internal_error, invalid_request, json_ok};

/// Shorter than verification: a leaked reset link grants full account access.
const RESET_TTL_MS: i64 = 60 * 60 * 1000;

const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_MAX_LEN: usize = 128;

#[derive(Debug, Deserialize)]
pub(super) struct RequestRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ConfirmRequest {
    token: String,
    new_password: String,
}

pub(super) async fn post_request(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<RequestRequest>,
) -> Response {
    let email = body.email.trim();
    let email_key = email.to_lowercase();

    // OIDC-only users (empty hash) have no password to reset.
    if let Ok(Some(user)) = state.db.find_user_by_email(email).await
        && user.disabled_at_ms.is_none()
        && !user.password_hash.is_empty()
        && let Err(e) = issue_and_send_reset(&state, &user.id, &user.email).await
    {
        warn!(error = %e, "issue_and_send_reset failed");
    }

    let counter = state
        .login_limiter
        .get_with(email_key, async {
            Arc::new(std::sync::atomic::AtomicU32::new(0))
        })
        .await;
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    generic_ok()
}

async fn issue_and_send_reset(
    state: &Arc<AppState>,
    user_id: &str,
    email: &str,
) -> anyhow::Result<()> {
    let Some(mailer) = state.mailer.as_ref() else {
        return Ok(());
    };
    let now_ms_i = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    if let Err(e) = state
        .db
        .revoke_password_reset_tokens_for_user(user_id, now_ms_i)
        .await
    {
        warn!(error = %e, "revoke_password_reset_tokens_for_user failed");
    }
    let token = mint_token();
    state
        .db
        .insert_password_reset_token(NewAuthToken {
            id: &token.id,
            user_id,
            token_hash: &token.hash,
            expires_at_ms: now_ms_i.saturating_add(RESET_TTL_MS),
            now_ms: now_ms_i,
        })
        .await?;
    if let Err(e) = mailer.send_password_reset(email, &token.value).await {
        warn!(error = %e, "send_password_reset mail failed");
    }
    Ok(())
}

pub(super) async fn post_confirm(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<ConfirmRequest>,
) -> Response {
    if let Err(msg) = validate_password(&body.new_password) {
        return invalid_request(msg);
    }
    let Some(hash) = hash_token(&body.token) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "token_invalid",
            "invalid or expired token",
        );
    };
    let now_ms_i = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let row = match state
        .db
        .find_active_password_reset_token(&hash, now_ms_i)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "token_invalid",
                "invalid or expired token",
            );
        }
        Err(e) => {
            warn!(error = %e, "find_active_password_reset_token failed");
            return internal_error();
        }
    };
    let pw_hash = match password::hash(&body.new_password).await {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "password hash failed");
            return internal_error();
        }
    };
    match state
        .db
        .consume_password_reset_and_set_password(&row.id, &row.user_id, &pw_hash, now_ms_i)
        .await
    {
        Ok(true) => json_ok(serde_json::json!({"ok": true})),
        Ok(false) => error_response(
            StatusCode::BAD_REQUEST,
            "token_invalid",
            "invalid or expired token",
        ),
        Err(e) => {
            warn!(error = %e, "consume_password_reset_and_set_password failed");
            internal_error()
        }
    }
}

fn generic_ok() -> Response {
    json_ok(serde_json::json!({
        "ok": true,
        "message": "If that address has an account, we've sent a password reset link."
    }))
}

const fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < PASSWORD_MIN_LEN {
        return Err("password too short");
    }
    if password.len() > PASSWORD_MAX_LEN {
        return Err("password too long");
    }
    Ok(())
}
