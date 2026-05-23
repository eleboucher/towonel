use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::auth::middleware::Principal;
use crate::hub::auth::{password, session};
use crate::hub::db;
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::users::NewUser;

use super::{
    AppState, LOGIN_MAX_FAILURES, conflict, error_response, internal_error, invalid_request,
    json_ok, json_with_status, unauthorized,
};

const SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_MAX_LEN: usize = 128;

#[derive(Debug, Deserialize)]
pub(super) struct SignupRequest {
    code: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthUser {
    id: String,
    email: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    user: AuthUser,
}

#[expect(
    clippy::too_many_lines,
    reason = "linear happy path with explicit rollback branches; splitting hides the ordering"
)]
pub(super) async fn post_signup(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<SignupRequest>,
) -> Response {
    if let Err(msg) = validate_email(&body.email) {
        return invalid_request(msg);
    }
    if let Err(msg) = validate_password(&body.password) {
        return invalid_request(msg);
    }
    if body.code.is_empty() {
        return invalid_request("code is required");
    }

    let now_ms_i = now_ms_i64();
    let sentinel = format!("claim:{now_ms_i}:{}", new_id(8));

    let claimed = match state
        .db
        .claim_signup_invite(&body.code, &sentinel, now_ms_i)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return invalid_request("invalid or expired invite code"),
        Err(e) => {
            warn!(error = %e, "claim_signup_invite failed");
            return internal_error();
        }
    };

    let user_id = new_id(16);
    let pw_hash = match password::hash(&body.password) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "password hash failed");
            if let Err(rel_err) = state
                .db
                .release_signup_invite(&claimed.code, &sentinel)
                .await
            {
                warn!(error = %rel_err, "release_signup_invite after failure");
            }
            return internal_error();
        }
    };

    if let Err(e) = state
        .db
        .insert_user(NewUser {
            id: &user_id,
            email: &body.email,
            password_hash: &pw_hash,
            role: &claimed.role,
            now_ms: now_ms_i,
        })
        .await
    {
        let is_dup = db::is_unique_violation(&e);
        if !is_dup {
            warn!(error = %e, "insert_user failed");
        }
        if let Err(rel_err) = state
            .db
            .release_signup_invite(&claimed.code, &sentinel)
            .await
        {
            warn!(error = %rel_err, "release_signup_invite after insert_user failure");
        }
        return if is_dup {
            conflict("email_taken", "email already in use")
        } else {
            internal_error()
        };
    }

    if let Err(e) = state
        .db
        .finalize_signup_invite(&claimed.code, &sentinel, &user_id)
        .await
    {
        warn!(error = %e, "finalize_signup_invite failed");
        if let Err(del_err) = state.db.delete_user(&user_id).await {
            warn!(error = %del_err, "delete_user during signup rollback");
        }
        if let Err(rel_err) = state
            .db
            .release_signup_invite(&claimed.code, &sentinel)
            .await
        {
            warn!(error = %rel_err, "release_signup_invite after finalize failure");
        }
        return internal_error();
    }

    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &new_id(16),
            actor_user_id: None,
            actor_kind: "system",
            action: "user.signup",
            target_kind: "user",
            target_id: Some(&user_id),
            metadata: Some(serde_json::json!({
                "role": claimed.role,
                "signup_invite_code": claimed.code,
            })),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action signup failed");
    }

    issue_session_response(&state, &user_id, &body.email, &claimed.role).await
}

pub(super) async fn post_login(
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<LoginRequest>,
) -> Response {
    if validate_email(&body.email).is_err() || body.password.is_empty() {
        return unauthorized("invalid credentials");
    }

    let lockout_key = body.email.to_lowercase();
    if let Some(counter) = state.login_limiter.get(&lockout_key).await
        && counter.load(std::sync::atomic::Ordering::Relaxed) >= LOGIN_MAX_FAILURES
    {
        return error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed login attempts; try again later",
        );
    }

    let user = match state.db.find_user_by_email(&body.email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            record_login_failure(&state, &lockout_key).await;
            return unauthorized("invalid credentials");
        }
        Err(e) => {
            warn!(error = %e, "find_user_by_email failed");
            return internal_error();
        }
    };
    if user.disabled_at_ms.is_some() {
        record_login_failure(&state, &lockout_key).await;
        return unauthorized("invalid credentials");
    }
    let ok = match password::verify(&body.password, &user.password_hash) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "password verify error");
            return internal_error();
        }
    };
    if !ok {
        record_login_failure(&state, &lockout_key).await;
        return unauthorized("invalid credentials");
    }

    state.login_limiter.invalidate(&lockout_key).await;
    issue_session_response(&state, &user.id, &user.email, &user.role).await
}

async fn record_login_failure(state: &Arc<AppState>, key: &str) {
    let counter = state
        .login_limiter
        .get_with(key.to_string(), async {
            Arc::new(std::sync::atomic::AtomicU32::new(0))
        })
        .await;
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub(super) async fn post_logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(cookie_header) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(cookie_value) = session::extract_from_cookie_header(cookie_header)
        && let Some((session_id, _)) = session::parse(cookie_value)
        && let Err(e) = state.db.delete_session(&session_id).await
    {
        warn!(error = %e, "delete_session on logout");
    }

    let secure = is_https_public_url(&state.public_url);
    let cookie = session::clear_cookie_header(secure);
    let mut resp = json_ok(serde_json::json!({"ok": true}));
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

pub(super) async fn get_me(principal: Principal) -> Response {
    match principal {
        Principal::User(u) => json_ok(AuthUser {
            id: u.id,
            email: u.email,
            role: u.role,
        }),
        Principal::OperatorKey => json_with_status(
            StatusCode::OK,
            serde_json::json!({"id": "operator-key", "email": null, "role": "operator"}),
        ),
    }
}

async fn issue_session_response(
    state: &Arc<AppState>,
    user_id: &str,
    email: &str,
    role: &str,
) -> Response {
    let now_ms_i = now_ms_i64();
    let s = session::mint();
    if let Err(e) = state
        .db
        .insert_session(crate::hub::db::sessions::NewSession {
            id: &s.id,
            user_id,
            token_hash: &s.token_hash,
            expires_at_ms: now_ms_i.saturating_add(SESSION_TTL_MS),
            ip_address: None,
            user_agent: None,
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_session failed");
        return internal_error();
    }

    let secure = is_https_public_url(&state.public_url);
    let cookie = session::set_cookie_header(
        &s.cookie_value,
        u64::try_from(SESSION_TTL_MS / 1000).unwrap_or(7 * 24 * 60 * 60),
        secure,
    );
    let mut resp = json_ok(AuthResponse {
        user: AuthUser {
            id: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
        },
    });
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.is_empty() || email.len() > 254 {
        return Err("email length out of range");
    }
    let (local, rest) = email.split_once('@').ok_or("email missing @")?;
    if local.is_empty() || rest.is_empty() {
        return Err("email malformed");
    }
    if !rest.contains('.') {
        return Err("email domain missing dot");
    }
    Ok(())
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

fn is_https_public_url(url: &str) -> bool {
    url.starts_with("https://")
}

fn now_ms_i64() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

fn new_id(byte_len: usize) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let mut buf = vec![0u8; byte_len];
    getrandom::fill(&mut buf).expect("OS RNG");
    B64.encode(buf)
}
