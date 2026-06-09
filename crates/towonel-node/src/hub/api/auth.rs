use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::time::now_ms;
use tracing::warn;
use utoipa::ToSchema;

use crate::hub::auth::middleware::Principal;
use crate::hub::auth::{password, session};
use crate::hub::db;
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::login_challenges::NewLoginChallenge;
use crate::hub::db::users::NewUser;

use super::verify::issue_and_send_verification;
use super::{
    AppState, LOGIN_MAX_FAILURES, conflict, error_response, internal_error, invalid_request,
    json_ok, json_with_status, unauthorized,
};

const SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const LOGIN_CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_MAX_LEN: usize = 128;

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct SignupRequest {
    /// Single-use signup invite code.
    code: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuthUser {
    id: String,
    email: String,
    role: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct MeResponse {
    id: String,
    email: Option<String>,
    role: String,
    twofa_enabled: bool,
    passkeys_enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuthResponse {
    user: AuthUser,
}

#[utoipa::path(
    post,
    path = "/v1/auth/signup",
    tag = "auth",
    request_body = SignupRequest,
    responses(
        (status = 200, description = "Account created; email verification required"),
        (status = 400, description = "Invalid email/password or missing code"),
        (status = 403, description = "Invite bound to a different email"),
        (status = 409, description = "Email already in use"),
    ),
)]
#[expect(clippy::too_many_lines, reason = "linear signup with rollback arms")]
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

    let claimed = match state.db.claim_signup_invite(&body.code, now_ms_i).await {
        Ok(Some(c)) => c,
        Ok(None) => return invalid_request("invalid or expired invite code"),
        Err(e) => {
            warn!(error = %e, "claim_signup_invite failed");
            return internal_error();
        }
    };

    if let Some(expected) = claimed.recipient_email.as_deref() {
        let supplied = db::users::normalize_email(&body.email);
        if supplied != expected {
            if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
                warn!(error = %rel_err, "release_signup_invite on recipient mismatch");
            }
            return error_response(
                StatusCode::FORBIDDEN,
                "invite_recipient_mismatch",
                "this invite is bound to a different email",
            );
        }
    }

    let user_id = new_id(16);
    let pw_hash = match password::hash(&body.password).await {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "password hash failed");
            if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
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
            email_verified_at_ms: None,
            now_ms: now_ms_i,
        })
        .await
    {
        let is_dup = db::is_unique_violation(&e);
        if !is_dup {
            warn!(error = %e, "insert_user failed");
        }
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
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
        .finalize_signup_invite(&claimed.code, &user_id)
        .await
    {
        warn!(error = %e, "finalize_signup_invite failed");
        if let Err(del_err) = state.db.delete_user(&user_id).await {
            warn!(error = %del_err, "delete_user during signup rollback");
        }
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
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
                "email": db::users::normalize_email(&body.email),
                "role": claimed.role,
                "signup_invite_code": claimed.code,
            })),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action signup failed");
    }

    if let Err(e) = issue_and_send_verification(&state, &user_id, &body.email).await {
        warn!(error = %e, "issue_and_send_verification on signup failed");
    }

    json_ok(serde_json::json!({
        "verification_required": true,
        "email": body.email,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Session issued (sets the session cookie), \
                                      or a 2FA challenge when a second factor is enrolled", body = AuthResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 403, description = "Email not verified"),
        (status = 429, description = "Too many failed attempts from this IP"),
    ),
)]
pub(super) async fn post_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<LoginRequest>,
) -> Response {
    let bad_request = validate_email(&body.email).is_err() || body.password.is_empty();
    let email_key = db::users::normalize_email(&body.email);
    let ip_key = client_ip_key(&peer, &headers);

    // IP-keyed lockout is what actually blocks. Per-email is also counted
    // (audit/observability) but never blocks alone, so a third party can't
    // freeze a known account by sending wrong passwords from anywhere.
    if let Some(counter) = state.ip_login_limiter.get(&ip_key).await
        && counter.load(std::sync::atomic::Ordering::Relaxed) >= LOGIN_MAX_FAILURES
    {
        return error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed login attempts from this IP; try again later",
        );
    }

    if bad_request {
        // Spend the same argon2 CPU as a real verify so this branch isn't a
        // timing oracle that distinguishes "malformed input" from "valid
        // email but wrong password".
        if let Err(e) = password::verify(&body.password, &state.login_sentinel_hash).await {
            warn!(error = %e, "sentinel verify error on bad_request login");
        }
        record_login_failure(&state, &email_key, &ip_key).await;
        return unauthorized("invalid credentials");
    }

    let user_opt = match state.db.find_user_by_email(&body.email).await {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "find_user_by_email failed");
            return internal_error();
        }
    };
    // Determine the hash to verify against. For unknown / disabled users —
    // and for OIDC-only users (empty password_hash sentinel) — verify
    // against the sentinel so the CPU cost is identical and OIDC-only
    // accounts aren't disclosed via response timing.
    let (hash, real_user) = match &user_opt {
        Some(u) if u.disabled_at_ms.is_none() && !u.password_hash.is_empty() => {
            (u.password_hash.as_str(), true)
        }
        _ => (state.login_sentinel_hash.as_str(), false),
    };
    let ok = match password::verify(&body.password, hash).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "password verify error");
            return internal_error();
        }
    };
    if !ok || !real_user {
        record_login_failure(&state, &email_key, &ip_key).await;
        return unauthorized("invalid credentials");
    }

    let Some(user) = user_opt else {
        // unreachable per real_user check above, but be defensive
        return unauthorized("invalid credentials");
    };
    // Don't bump the IP lockout: the password was correct. Otherwise an
    // attacker could freeze any known-unverified email from anywhere.
    if user.email_verified_at_ms.is_none() {
        return error_response(
            StatusCode::FORBIDDEN,
            "email_unverified",
            "verify your email — check your inbox or request a new link",
        );
    }
    // IP counter only cleared once a session is actually issued; otherwise
    // a stolen-password attacker could refresh it on every challenge.
    state.login_limiter.invalidate(&email_key).await;

    let methods = match enrolled_second_factors(&state, &user.id).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    if methods.is_empty() {
        state.ip_login_limiter.invalidate(&ip_key).await;
        issue_session_response(&state, &user.id, &user.email, &user.role).await
    } else {
        issue_login_challenge_response(&state, &user.id, &methods).await
    }
}

/// Second-factor methods enrolled for `user_id` (`"totp"`, `"passkey"`); empty
/// means single-factor. Shared by the password and OIDC paths.
pub(super) async fn enrolled_second_factors(
    state: &Arc<AppState>,
    user_id: &str,
) -> Result<Vec<&'static str>, Response> {
    let totp_enabled = match state.db.find_user_totp(user_id).await {
        Ok(r) => r.is_some_and(|row| row.confirmed_at_ms.is_some()),
        Err(e) => {
            warn!(error = %e, "find_user_totp failed during login");
            return Err(internal_error());
        }
    };
    let passkeys_enabled = match state.db.count_passkeys_for_user(user_id).await {
        Ok(n) => n > 0,
        Err(e) => {
            warn!(error = %e, "count_passkeys_for_user failed during login");
            return Err(internal_error());
        }
    };
    let mut methods = Vec::new();
    if totp_enabled {
        methods.push("totp");
    }
    if passkeys_enabled {
        methods.push("passkey");
    }
    Ok(methods)
}

/// Mint a login challenge for `user_id`, returning the token the client later
/// presents to `POST /v1/auth/2fa/verify`.
pub(super) async fn mint_login_challenge(
    state: &Arc<AppState>,
    user_id: &str,
) -> Result<String, Response> {
    let now = now_ms_i64();
    let s = session::mint();
    if let Err(e) = state
        .db
        .insert_login_challenge(NewLoginChallenge {
            id: &s.id,
            user_id,
            token_hash: &s.token_hash,
            expires_at_ms: now.saturating_add(LOGIN_CHALLENGE_TTL_MS),
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_login_challenge failed");
        return Err(internal_error());
    }
    Ok(s.cookie_value)
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct TwoFaVerifyRequest {
    /// The `challenge_token` returned by `POST /v1/auth/login`.
    challenge_token: String,
    /// TOTP code or a single-use backup code.
    code: String,
}

#[utoipa::path(
    post,
    path = "/v1/auth/2fa/verify",
    tag = "auth",
    request_body = TwoFaVerifyRequest,
    responses(
        (status = 200, description = "Second factor accepted; session issued", body = AuthResponse),
        (status = 401, description = "Invalid code or expired challenge"),
        (status = 429, description = "Too many failed attempts from this IP"),
    ),
)]
pub(super) async fn post_twofa_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<TwoFaVerifyRequest>,
) -> Response {
    let ip_key = client_ip_key(&peer, &headers);
    if let Some(counter) = state.ip_login_limiter.get(&ip_key).await
        && counter.load(std::sync::atomic::Ordering::Relaxed) >= LOGIN_MAX_FAILURES
    {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed attempts from this IP; try again later",
        );
    }

    let Some((challenge_id, token_hash)) = session::parse(body.challenge_token.trim()) else {
        record_login_failure(&state, "<twofa>", &ip_key).await;
        return unauthorized("invalid or expired challenge");
    };
    let now = now_ms_i64();
    let row = match state
        .db
        .find_active_login_challenge(&challenge_id, &token_hash, now)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            record_login_failure(&state, "<twofa>", &ip_key).await;
            return unauthorized("invalid or expired challenge");
        }
        Err(e) => {
            warn!(error = %e, "find_active_login_challenge failed");
            return internal_error();
        }
    };

    let user = match state.db.find_user_by_id(&row.user_id).await {
        Ok(Some(u)) if u.disabled_at_ms.is_none() => u,
        Ok(_) => {
            record_login_failure(&state, "<twofa>", &ip_key).await;
            return unauthorized("account unavailable");
        }
        Err(e) => {
            warn!(error = %e, "find_user_by_id during 2fa verify");
            return internal_error();
        }
    };
    let totp_row = match state.db.find_user_totp(&user.id).await {
        Ok(Some(r)) if r.confirmed_at_ms.is_some() => r,
        _ => {
            record_login_failure(&state, "<twofa>", &ip_key).await;
            return unauthorized("invalid or expired challenge");
        }
    };

    let ok = super::twofa::verify_code_or_backup(&state, &user, &totp_row, body.code.trim()).await;
    if !ok {
        record_login_failure(&state, "<twofa>", &ip_key).await;
        let attempts = state
            .twofa_attempt_limiter
            .get_with(row.id.clone(), async {
                Arc::new(std::sync::atomic::AtomicU32::new(0))
            })
            .await
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if attempts >= super::TWOFA_MAX_ATTEMPTS_PER_CHALLENGE
            && let Err(e) = state.db.consume_login_challenge(&row.id, now).await
        {
            warn!(error = %e, "consume_login_challenge after max attempts failed");
        }
        return unauthorized("invalid code");
    }
    match state.db.consume_login_challenge(&row.id, now).await {
        Ok(true) => {}
        Ok(false) => return unauthorized("invalid or expired challenge"),
        Err(e) => {
            warn!(error = %e, "consume_login_challenge failed");
            return internal_error();
        }
    }
    state.twofa_attempt_limiter.invalidate(&row.id).await;
    state.ip_login_limiter.invalidate(&ip_key).await;
    issue_session_response(&state, &user.id, &user.email, &user.role).await
}

pub(super) async fn issue_login_challenge_response(
    state: &Arc<AppState>,
    user_id: &str,
    methods: &[&str],
) -> Response {
    match mint_login_challenge(state, user_id).await {
        Ok(challenge_token) => json_ok(serde_json::json!({
            "twofa_required": true,
            "challenge_token": challenge_token,
            "methods": methods,
        })),
        Err(resp) => resp,
    }
}

/// Resolve the client IP used for the lockout counter.
pub(super) fn client_ip_key(peer: &SocketAddr, headers: &axum::http::HeaderMap) -> String {
    if !peer_is_trusted_proxy(peer.ip()) {
        return peer.ip().to_string();
    }
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(last) = value.rsplit(',').next()
    {
        let trimmed = last.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    peer.ip().to_string()
}

const fn peer_is_trusted_proxy(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

pub(super) async fn record_login_failure(state: &Arc<AppState>, email_key: &str, ip_key: &str) {
    let email_counter = state
        .login_limiter
        .get_with(email_key.to_string(), async {
            Arc::new(std::sync::atomic::AtomicU32::new(0))
        })
        .await;
    email_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ip_counter = state
        .ip_login_limiter
        .get_with(ip_key.to_string(), async {
            Arc::new(std::sync::atomic::AtomicU32::new(0))
        })
        .await;
    ip_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "auth",
    responses((status = 200, description = "Session cleared")),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

    let secure = state.use_secure_cookies;
    let cookie = session::clear_cookie_header(secure);
    let mut resp = json_ok(serde_json::json!({"ok": true}));
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current authenticated principal", body = MeResponse),
        (status = 401, description = "Not authenticated"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_me(State(state): State<Arc<AppState>>, principal: Principal) -> Response {
    match principal {
        Principal::User(u) => {
            let twofa_enabled = state
                .db
                .find_user_totp(&u.id)
                .await
                .ok()
                .flatten()
                .is_some_and(|r| r.confirmed_at_ms.is_some());
            let passkeys_enabled = state.db.count_passkeys_for_user(&u.id).await.unwrap_or(0) > 0;
            json_ok(MeResponse {
                id: u.id,
                email: Some(u.email),
                role: u.role,
                twofa_enabled,
                passkeys_enabled,
            })
        }
        Principal::OperatorKey => json_with_status(
            StatusCode::OK,
            serde_json::json!({
                "id": "operator-key",
                "email": null,
                "role": "operator",
                "twofa_enabled": true,
                "passkeys_enabled": false,
            }),
        ),
    }
}

pub(super) async fn issue_session_response(
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

    let secure = state.use_secure_cookies;
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

pub(super) fn validate_email(email: &str) -> Result<(), &'static str> {
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

fn now_ms_i64() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

pub(super) fn new_id(byte_len: usize) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let mut buf = vec![0u8; byte_len];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG failure at runtime is unrecoverable"
    )]
    getrandom::fill(&mut buf).expect("OS RNG");
    B64.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:1234").parse().unwrap()
    }

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    #[test]
    fn ip_key_uses_peer_when_not_loopback() {
        let h = headers_with_xff("8.8.8.8");
        assert_eq!(client_ip_key(&peer("203.0.113.5"), &h), "203.0.113.5");
    }

    #[test]
    fn ip_key_uses_xff_when_peer_is_loopback() {
        let h = headers_with_xff("203.0.113.5");
        assert_eq!(client_ip_key(&peer("127.0.0.1"), &h), "203.0.113.5");
    }

    #[test]
    fn ip_key_uses_last_xff_entry() {
        let h = headers_with_xff("198.51.100.10, 203.0.113.5");
        assert_eq!(client_ip_key(&peer("127.0.0.1"), &h), "203.0.113.5");
    }

    #[test]
    fn ip_key_falls_back_to_peer_when_xff_missing() {
        let h = HeaderMap::new();
        assert_eq!(client_ip_key(&peer("127.0.0.1"), &h), "127.0.0.1");
    }

    #[test]
    fn ip_key_uses_xff_when_peer_is_private() {
        let h = headers_with_xff("203.0.113.5");
        assert_eq!(client_ip_key(&peer("10.42.0.7"), &h), "203.0.113.5");
    }

    #[test]
    fn ip_key_handles_ipv6_loopback() {
        let h = headers_with_xff("2001:db8::1");
        assert_eq!(client_ip_key(&peer("[::1]"), &h), "2001:db8::1");
    }
}
