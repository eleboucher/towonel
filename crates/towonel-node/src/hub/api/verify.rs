//! Token format: `<id>.<secret>`. Only `sha256(secret)` is stored, so a
//! read-only DB leak can't verify someone else's email.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::db::auth_tokens::NewAuthToken;

use super::{AppState, error_response, internal_error, json_ok};

const VERIFICATION_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Deserialize)]
pub(super) struct ResendRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct VerifyTokenQuery {
    token: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct VerifyPostRequest {
    token: String,
}

/// Revokes prior tokens for the user so only the newest link works.
pub(super) async fn issue_and_send_verification(
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
        .revoke_email_verification_tokens_for_user(user_id, now_ms_i)
        .await
    {
        warn!(error = %e, "revoke_email_verification_tokens_for_user failed");
    }

    let token = mint_token();
    state
        .db
        .insert_email_verification_token(NewAuthToken {
            id: &token.id,
            user_id,
            token_hash: &token.hash,
            expires_at_ms: now_ms_i.saturating_add(VERIFICATION_TTL_MS),
            now_ms: now_ms_i,
        })
        .await?;

    if let Err(e) = mailer.send_verification(email, &token.value).await {
        warn!(error = %e, "send_verification mail failed");
    }
    Ok(())
}

/// Always 200 to avoid revealing whether the email exists. Shares the
/// login limiter so brute-force lookups trip the same lockout.
pub(super) async fn post_resend(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<ResendRequest>,
) -> Response {
    let email = body.email.trim();
    let email_key = email.to_lowercase();

    if let Ok(Some(user)) = state.db.find_user_by_email(email).await
        && user.disabled_at_ms.is_none()
        && user.email_verified_at_ms.is_none()
        && let Err(e) = issue_and_send_verification(&state, &user.id, &user.email).await
    {
        warn!(error = %e, "issue_and_send_verification on resend failed");
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

pub(super) async fn get_verify(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VerifyTokenQuery>,
) -> Response {
    match consume(&state, &q.token).await {
        ConsumeOutcome::Ok => html_page(
            StatusCode::OK,
            "Email verified",
            "Your email is verified. You can sign in now.",
        ),
        ConsumeOutcome::Invalid => html_page(
            StatusCode::BAD_REQUEST,
            "Link expired",
            "This link is invalid or has already been used. Request a fresh one from the sign-in page.",
        ),
        ConsumeOutcome::Internal => html_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "We couldn't verify your email. Try again in a minute.",
        ),
    }
}

pub(super) async fn post_verify(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<VerifyPostRequest>,
) -> Response {
    match consume(&state, &body.token).await {
        ConsumeOutcome::Ok => json_ok(serde_json::json!({"verified": true})),
        ConsumeOutcome::Invalid => error_response(
            StatusCode::BAD_REQUEST,
            "token_invalid",
            "invalid or expired token",
        ),
        ConsumeOutcome::Internal => internal_error(),
    }
}

enum ConsumeOutcome {
    Ok,
    Invalid,
    Internal,
}

async fn consume(state: &Arc<AppState>, token: &str) -> ConsumeOutcome {
    let Some(hash) = hash_token(token) else {
        return ConsumeOutcome::Invalid;
    };
    let now_ms_i = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let row = match state
        .db
        .find_active_email_verification_token(&hash, now_ms_i)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return ConsumeOutcome::Invalid,
        Err(e) => {
            warn!(error = %e, "find_active_email_verification_token failed");
            return ConsumeOutcome::Internal;
        }
    };
    match state
        .db
        .consume_email_verification_token_and_verify_user(&row.id, &row.user_id, now_ms_i)
        .await
    {
        Ok(true) => ConsumeOutcome::Ok,
        Ok(false) => ConsumeOutcome::Invalid,
        Err(e) => {
            warn!(error = %e, "consume_email_verification_token_and_verify_user failed");
            ConsumeOutcome::Internal
        }
    }
}

pub(super) fn hash_token(raw: &str) -> Option<Vec<u8>> {
    let (_id, secret) = raw.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    Some(hasher.finalize().to_vec())
}

pub(super) struct MintedToken {
    pub id: String,
    pub value: String,
    pub hash: [u8; 32],
}

pub(super) fn mint_token() -> MintedToken {
    let mut id_bytes = [0u8; 16];
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut id_bytes).expect("OS RNG");
    getrandom::fill(&mut secret_bytes).expect("OS RNG");
    let id = B64.encode(id_bytes);
    let secret = B64.encode(secret_bytes);
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let value = format!("{id}.{secret}");
    MintedToken { id, value, hash }
}

fn generic_ok() -> Response {
    json_ok(serde_json::json!({
        "ok": true,
        "message": "If that address has an unverified account, we've sent a new verification link."
    }))
}

/// `&'static str` only: inputs are interpolated raw into HTML.
fn html_page(status: StatusCode, heading: &'static str, body: &'static str) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{heading}</title>\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:48px 16px;background:#f5f5f5;color:#111}}\
         .card{{max-width:440px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e5e5}}\
         h1{{font-size:20px;margin:0 0 12px}}p{{font-size:15px;color:#444;margin:0;line-height:1.5}}</style>\
         </head><body><div class=\"card\"><h1>{heading}</h1><p>{body}</p></div></body></html>",
    );
    let mut resp = (status, Html(html)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}
