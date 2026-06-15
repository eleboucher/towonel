use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tracing::warn;
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RegisterPublicKeyCredential, WebauthnError,
};

use crate::hub::auth::middleware::Principal;
use crate::hub::auth::{password, session};
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::user_passkeys::NewPasskey;

use super::auth::{
    client_ip_key, issue_session_response, reauth_rate_limited, record_login_failure,
};
use super::signup_invites::{now_ms_i64, random_code};
use super::twofa::verify_code_or_backup;
use super::{
    AppState, LOGIN_MAX_FAILURES, TWOFA_MAX_ATTEMPTS_PER_CHALLENGE, error_response, internal_error,
    invalid_request, json_ok, unauthorized, user_required,
};

const PASSKEY_NS: Uuid = Uuid::from_u128(0x6b_a7_b8_11_9d_ad_11_d1_80_b4_00_c0_4f_d4_30_c8);

fn user_uuid(user_id: &str) -> Uuid {
    Uuid::new_v5(&PASSKEY_NS, user_id.as_bytes())
}

#[derive(Debug, Serialize, ToSchema)]
struct PasskeyItem {
    id: String,
    name: String,
    created_at_ms: i64,
}

#[utoipa::path(
    get,
    path = "/v1/auth/passkeys",
    tag = "passkeys",
    responses(
        (status = 200, description = "The caller's registered passkeys"),
        (status = 403, description = "User session required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_passkeys(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(ref user) = principal else {
        return user_required("user session required");
    };
    let rows = match state.db.find_passkeys_for_user(&user.id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "find_passkeys_for_user failed");
            return internal_error();
        }
    };
    let items: Vec<PasskeyItem> = rows
        .into_iter()
        .map(|r| PasskeyItem {
            id: r.id,
            name: r.name,
            created_at_ms: r.created_at_ms,
        })
        .collect();
    json_ok(serde_json::json!({ "passkeys": items }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkeys/register/begin",
    tag = "passkeys",
    responses(
        (status = 200, description = "WebAuthn creation options; returns `challenge_id` and `options`"),
        (status = 403, description = "User session required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn post_register_begin(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(ref user) = principal else {
        return user_required("user session required");
    };
    let existing = match state.db.find_passkeys_for_user(&user.id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "find_passkeys_for_user failed");
            return internal_error();
        }
    };
    let exclude: Vec<_> = existing
        .iter()
        .map(|r| r.passkey.cred_id().clone())
        .collect();
    let user_uuid = user_uuid(&user.id);
    let display_name = user.email.as_str();
    let (ccr, reg_state) = match state.webauthn.start_passkey_registration(
        user_uuid,
        display_name,
        display_name,
        Some(exclude),
    ) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "start_passkey_registration failed");
            return internal_error();
        }
    };
    let challenge_id = random_code(16);
    state
        .passkey_reg_states
        .insert(challenge_id.clone(), reg_state)
        .await;
    json_ok(serde_json::json!({
        "challenge_id": challenge_id,
        "options": ccr,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct RegisterFinishRequest {
    challenge_id: String,
    name: String,
    password: String,
    /// `WebAuthn` credential from `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    credential: RegisterPublicKeyCredential,
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkeys/register/finish",
    tag = "passkeys",
    request_body = RegisterFinishRequest,
    responses(
        (status = 200, description = "Passkey registered; returns its `id`"),
        (status = 400, description = "Invalid name, challenge, or credential"),
        (status = 401, description = "Invalid password"),
        (status = 403, description = "User session required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn post_register_finish(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    principal: Principal,
    axum::Json(body): axum::Json<RegisterFinishRequest>,
) -> Response {
    let Principal::User(ref user) = principal else {
        return user_required("user session required");
    };
    let ip_key = client_ip_key(&state.trusted_proxies, &peer, &headers);
    if let Some(resp) = reauth_rate_limited(&state, &ip_key).await {
        return resp;
    }
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return invalid_request("name must be 1-64 characters");
    }
    // Fresh password so a session-hijack can't plant a backdoor credential.
    if !matches!(
        password::verify(&body.password, &user.password_hash).await,
        Ok(true)
    ) {
        record_login_failure(&state, &user.email, &ip_key).await;
        return unauthorized("invalid credentials");
    }
    let Some(reg_state) = state.passkey_reg_states.remove(&body.challenge_id).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "challenge not found or expired",
        );
    };
    let passkey = match state
        .webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
    {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "finish_passkey_registration failed");
            return error_response(
                StatusCode::BAD_REQUEST,
                "registration_failed",
                "passkey registration failed",
            );
        }
    };
    let now = now_ms_i64();
    let passkey_id = random_code(16);
    if let Err(e) = state
        .db
        .insert_passkey(NewPasskey {
            id: &passkey_id,
            user_id: &user.id,
            passkey: &passkey,
            name: &name,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_passkey failed");
        return internal_error();
    }
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: Some(&user.id),
            actor_kind: "user",
            action: "user.passkey.register",
            target_kind: "user",
            target_id: Some(&user.id),
            metadata: Some(serde_json::json!({ "name": name })),
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action passkey.register failed");
    }
    json_ok(serde_json::json!({ "id": passkey_id }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct DeletePasskeyRequest {
    password: String,
    /// TOTP/backup code, required when the account also has TOTP enabled.
    #[serde(default)]
    code: Option<String>,
}

#[utoipa::path(
    delete,
    path = "/v1/auth/passkeys/{id}",
    tag = "passkeys",
    params(("id" = String, Path, description = "Passkey id")),
    request_body = DeletePasskeyRequest,
    responses(
        (status = 200, description = "Passkey removed"),
        (status = 401, description = "Invalid password or code"),
        (status = 403, description = "User session required"),
        (status = 404, description = "Passkey not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_passkey(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    principal: Principal,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<DeletePasskeyRequest>,
) -> Response {
    let Principal::User(ref user) = principal else {
        return user_required("user session required");
    };
    let ip_key = client_ip_key(&state.trusted_proxies, &peer, &headers);
    if let Some(resp) = reauth_rate_limited(&state, &ip_key).await {
        return resp;
    }
    // Mirrors twofa::post_disable: password + existing factor so a session
    // hijack can't silently strip 2FA.
    if !matches!(
        password::verify(&body.password, &user.password_hash).await,
        Ok(true)
    ) {
        record_login_failure(&state, &user.email, &ip_key).await;
        return unauthorized("invalid credentials");
    }
    if let Ok(Some(totp_row)) = state.db.find_user_totp(&user.id).await
        && totp_row.confirmed_at_ms.is_some()
    {
        let code = body.code.as_deref().unwrap_or("").trim();
        if code.is_empty() || !verify_code_or_backup(&state, user, &totp_row, code).await {
            return unauthorized("invalid code");
        }
    }
    let deleted = match state.db.delete_passkey(&id, &user.id).await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "delete_passkey failed");
            return internal_error();
        }
    };
    if !deleted {
        return error_response(StatusCode::NOT_FOUND, "not_found", "passkey not found");
    }
    let now = now_ms_i64();
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: Some(&user.id),
            actor_kind: "user",
            action: "user.passkey.delete",
            target_kind: "user",
            target_id: Some(&user.id),
            metadata: Some(serde_json::json!({ "passkey_id": id })),
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action passkey.delete failed");
    }
    json_ok(serde_json::json!({}))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct AuthenticateBeginRequest {
    /// The `challenge_token` from `POST /v1/auth/login`.
    challenge_token: String,
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkeys/authenticate/begin",
    tag = "passkeys",
    request_body = AuthenticateBeginRequest,
    responses(
        (status = 200, description = "WebAuthn request options; returns `passkey_challenge_id` and `options`"),
        (status = 400, description = "No passkeys registered"),
        (status = 401, description = "Invalid or expired challenge"),
        (status = 429, description = "Too many failed attempts from this IP"),
    ),
)]
pub(super) async fn post_authenticate_begin(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<AuthenticateBeginRequest>,
) -> Response {
    let ip_key = client_ip_key(&state.trusted_proxies, &peer, &headers);
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
        record_login_failure(&state, "<passkey>", &ip_key).await;
        return unauthorized("invalid or expired challenge");
    };
    let now = now_ms_i64();
    let login_challenge = match state
        .db
        .find_active_login_challenge(&challenge_id, &token_hash, now)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            record_login_failure(&state, "<passkey>", &ip_key).await;
            return unauthorized("invalid or expired challenge");
        }
        Err(e) => {
            warn!(error = %e, "find_active_login_challenge failed");
            return internal_error();
        }
    };
    let passkey_rows = match state
        .db
        .find_passkeys_for_user(&login_challenge.user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "find_passkeys_for_user failed");
            return internal_error();
        }
    };
    if passkey_rows.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "no_passkeys",
            "no passkeys registered for this user",
        );
    }
    let passkeys: Vec<Passkey> = passkey_rows.into_iter().map(|r| r.passkey).collect();
    let (rcr, auth_state) = match state.webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "start_passkey_authentication failed");
            return internal_error();
        }
    };
    let passkey_challenge_id = random_code(16);
    state
        .passkey_auth_states
        .insert(
            passkey_challenge_id.clone(),
            (login_challenge.user_id, auth_state),
        )
        .await;
    json_ok(serde_json::json!({
        "passkey_challenge_id": passkey_challenge_id,
        "options": rcr,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct AuthenticateFinishRequest {
    challenge_token: String,
    passkey_challenge_id: String,
    /// `WebAuthn` credential from `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    credential: PublicKeyCredential,
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkeys/authenticate/finish",
    tag = "passkeys",
    request_body = AuthenticateFinishRequest,
    responses(
        (status = 200, description = "Passkey accepted; session issued (sets the session cookie)"),
        (status = 401, description = "Authentication failed or challenge expired"),
        (status = 429, description = "Too many failed attempts from this IP"),
    ),
)]
#[expect(
    clippy::too_many_lines,
    reason = "linear 2FA verify with branch per failure mode"
)]
pub(super) async fn post_authenticate_finish(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<AuthenticateFinishRequest>,
) -> Response {
    let ip_key = client_ip_key(&state.trusted_proxies, &peer, &headers);
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
        record_login_failure(&state, "<passkey>", &ip_key).await;
        return unauthorized("invalid or expired challenge");
    };
    let now = now_ms_i64();
    let login_challenge = match state
        .db
        .find_active_login_challenge(&challenge_id, &token_hash, now)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            record_login_failure(&state, "<passkey>", &ip_key).await;
            return unauthorized("invalid or expired challenge");
        }
        Err(e) => {
            warn!(error = %e, "find_active_login_challenge failed");
            return internal_error();
        }
    };

    // .remove() is atomic: prevents replaying the same passkey_challenge_id.
    let Some((stored_user_id, auth_state)) = state
        .passkey_auth_states
        .remove(&body.passkey_challenge_id)
        .await
    else {
        bump_passkey_attempt(&state, &login_challenge.id, &ip_key, now).await;
        return unauthorized("invalid or expired challenge");
    };

    if stored_user_id != login_challenge.user_id {
        bump_passkey_attempt(&state, &login_challenge.id, &ip_key, now).await;
        return unauthorized("invalid or expired challenge");
    }

    let auth_result = match state
        .webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
    {
        Ok(r) => r,
        Err(WebauthnError::CredentialPossibleCompromise) => {
            // Sign-counter regression → likely cloned authenticator. Disable
            // the credential, write an audit record, and treat as a hard
            // failure (the user must re-enroll).
            handle_possible_clone(&state, &login_challenge.user_id, &body.credential, now).await;
            bump_passkey_attempt(&state, &login_challenge.id, &ip_key, now).await;
            return unauthorized("passkey authentication failed");
        }
        Err(e) => {
            warn!(error = %e, "finish_passkey_authentication failed");
            bump_passkey_attempt(&state, &login_challenge.id, &ip_key, now).await;
            return unauthorized("passkey authentication failed");
        }
    };

    if auth_result.needs_update() {
        match state
            .db
            .find_passkeys_for_user(&login_challenge.user_id)
            .await
        {
            Ok(rows) => {
                if let Some(mut row) = rows
                    .into_iter()
                    .find(|r| r.passkey.cred_id() == auth_result.cred_id())
                {
                    if row.passkey.update_credential(&auth_result) == Some(true) {
                        match state.db.update_passkey(&row.id, &row.passkey).await {
                            Ok(true) => {}
                            Ok(false) => warn!(
                                passkey_id = %row.id,
                                "update_passkey sign_count matched no row"
                            ),
                            Err(e) => warn!(error = %e, "update_passkey sign_count failed"),
                        }
                    }
                } else {
                    warn!(
                        cred_id = ?auth_result.cred_id(),
                        "auth succeeded but no matching passkey row"
                    );
                }
            }
            Err(e) => warn!(error = %e, "find_passkeys_for_user for sign_count update failed"),
        }
    }

    match state
        .db
        .consume_login_challenge(&login_challenge.id, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            record_login_failure(&state, "<passkey>", &ip_key).await;
            return unauthorized("invalid or expired challenge");
        }
        Err(e) => {
            warn!(error = %e, "consume_login_challenge failed");
            return internal_error();
        }
    }

    state
        .twofa_attempt_limiter
        .invalidate(&login_challenge.id)
        .await;
    state.ip_login_limiter.invalidate(&ip_key).await;

    let user = match state.db.find_user_by_id(&login_challenge.user_id).await {
        Ok(Some(u)) if u.disabled_at_ms.is_none() => u,
        Ok(_) => return unauthorized("account unavailable"),
        Err(e) => {
            warn!(error = %e, "find_user_by_id after passkey auth");
            return internal_error();
        }
    };
    issue_session_response(&state, &user.id, &user.email, &user.role).await
}

/// Deletes the credential and writes an `admin_action` on sign-counter regression.
async fn handle_possible_clone(
    state: &Arc<AppState>,
    user_id: &str,
    credential: &PublicKeyCredential,
    now: i64,
) {
    let cred_id = credential.raw_id.as_ref();
    let rows = match state.db.find_passkeys_for_user(user_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "find_passkeys_for_user during clone detection failed");
            return;
        }
    };
    let Some(row) = rows
        .into_iter()
        .find(|r| r.passkey.cred_id().as_ref() == cred_id)
    else {
        warn!(?cred_id, "clone detected but no matching passkey row");
        return;
    };
    match state.db.delete_passkey(&row.id, user_id).await {
        Ok(true) => warn!(passkey_id = %row.id, "passkey disabled — sign-counter regression"),
        Ok(false) => {}
        Err(e) => warn!(error = %e, "delete_passkey on clone detection failed"),
    }
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: Some(user_id),
            actor_kind: "user",
            action: "user.passkey.clone_detected",
            target_kind: "user",
            target_id: Some(user_id),
            metadata: Some(serde_json::json!({ "passkey_id": row.id })),
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action passkey.clone_detected failed");
    }
}

/// Bumps IP + per-challenge counters; consumes the login challenge at the cap.
async fn bump_passkey_attempt(
    state: &Arc<AppState>,
    login_challenge_id: &str,
    ip_key: &str,
    now: i64,
) {
    record_login_failure(state, "<passkey>", ip_key).await;
    let attempts = state
        .twofa_attempt_limiter
        .get_with(login_challenge_id.to_string(), async {
            Arc::new(std::sync::atomic::AtomicU32::new(0))
        })
        .await
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    if attempts >= TWOFA_MAX_ATTEMPTS_PER_CHALLENGE
        && let Err(e) = state
            .db
            .consume_login_challenge(login_challenge_id, now)
            .await
    {
        warn!(error = %e, "consume_login_challenge after max passkey attempts failed");
    }
}
