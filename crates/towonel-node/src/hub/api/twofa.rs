use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::hub::auth::backup_codes;
use crate::hub::auth::middleware::Principal;
use crate::hub::auth::{password, totp};
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::user_backup_codes::NewBackupCode;
use crate::hub::db::user_totp::UserTotpRow;

use super::signup_invites::{now_ms_i64, principal_actor, random_code};
use super::{AppState, error_response, internal_error, invalid_request, json_ok, unauthorized};

#[derive(Debug, Serialize)]
pub(super) struct StatusResponse {
    enabled: bool,
    pending: bool,
    backup_codes_remaining: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct ConfirmRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DisableRequest {
    password: String,
    code: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct RegenerateRequest {
    code: String,
}

pub(super) async fn get_status(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(ref user) = principal else {
        return error_response(
            StatusCode::FORBIDDEN,
            "user_required",
            "2FA management is per-user",
        );
    };
    let row = match state.db.find_user_totp(&user.id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "find_user_totp failed");
            return internal_error();
        }
    };
    let remaining = if matches!(&row, Some(r) if r.confirmed_at_ms.is_some()) {
        state
            .db
            .count_unused_backup_codes(&user.id)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let (enabled, pending) = match &row {
        Some(r) if r.confirmed_at_ms.is_some() => (true, false),
        Some(_) => (false, true),
        None => (false, false),
    };
    json_ok(StatusResponse {
        enabled,
        pending,
        backup_codes_remaining: remaining,
    })
}

pub(super) async fn post_setup(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(ref user) = principal else {
        return error_response(
            StatusCode::FORBIDDEN,
            "user_required",
            "2FA management is per-user",
        );
    };
    if let Ok(Some(row)) = state.db.find_user_totp(&user.id).await
        && row.confirmed_at_ms.is_some()
    {
        return error_response(
            StatusCode::CONFLICT,
            "twofa_already_enabled",
            "2FA is already enabled",
        );
    }

    let secret = totp::generate_secret();
    let sealed = match totp::seal(&secret, &state.kek) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "totp seal failed");
            return internal_error();
        }
    };
    if let Err(e) = state
        .db
        .upsert_pending_totp(&user.id, &sealed, now_ms_i64())
        .await
    {
        warn!(error = %e, "upsert_pending_totp failed");
        return internal_error();
    }

    let secret_base32 = totp::secret_base32(&secret);
    let otpauth = totp::otpauth_url(&secret, &user.email, "Towonel");
    json_ok(serde_json::json!({
        "secret_base32": secret_base32,
        "otpauth_url": otpauth,
    }))
}

pub(super) async fn post_confirm(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    axum::Json(body): axum::Json<ConfirmRequest>,
) -> Response {
    let Principal::User(ref user) = principal else {
        return error_response(
            StatusCode::FORBIDDEN,
            "user_required",
            "2FA management is per-user",
        );
    };
    let row = match state.db.find_user_totp(&user.id).await {
        Ok(Some(r)) if r.confirmed_at_ms.is_none() => r,
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                "twofa_already_enabled",
                "2FA is already enabled",
            );
        }
        Ok(None) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "no_pending_setup",
                "start setup before confirming",
            );
        }
        Err(e) => {
            warn!(error = %e, "find_user_totp failed");
            return internal_error();
        }
    };
    let secret = match totp::unseal(&row.secret_encrypted, &state.kek) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "totp unseal failed");
            return internal_error();
        }
    };
    if totp::verify_code(&secret, body.code.trim(), now_unix(), None).is_err() {
        return invalid_request("invalid code");
    }
    let now = now_ms_i64();
    if !state.db.confirm_totp(&user.id, now).await.unwrap_or(false) {
        return error_response(
            StatusCode::CONFLICT,
            "twofa_already_enabled",
            "2FA is already enabled",
        );
    }
    // last_used_step is intentionally left unset: confirm happens inside an
    // already-authenticated session, so an immediate login with the same
    // code is the same legitimate user.

    let codes = match issue_backup_codes(&state, &user.id, now).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "issue_backup_codes failed");
            return internal_error();
        }
    };

    let (actor_kind, actor_user_id) = principal_actor(&principal);
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: actor_user_id.as_deref(),
            actor_kind,
            action: "user.2fa.enable",
            target_kind: "user",
            target_id: Some(&user.id),
            metadata: None,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action 2fa.enable failed");
    }

    json_ok(serde_json::json!({ "backup_codes": codes }))
}

pub(super) async fn post_disable(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    axum::Json(body): axum::Json<DisableRequest>,
) -> Response {
    let Principal::User(ref user) = principal else {
        return error_response(
            StatusCode::FORBIDDEN,
            "user_required",
            "2FA management is per-user",
        );
    };
    // Both factors required so a session-hijack attacker can't silently
    // strip 2FA. Pending (never-confirmed) rows accept password-only.
    let Ok(Some(row)) = state.db.find_user_totp(&user.id).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "twofa_not_enabled",
            "2FA is not enabled",
        );
    };
    if row.confirmed_at_ms.is_none() {
        match password::verify(&body.password, &user.password_hash).await {
            Ok(true) => {}
            _ => return unauthorized("invalid credentials"),
        }
        if let Err(e) = state.db.delete_user_totp(&user.id).await {
            warn!(error = %e, "delete_user_totp failed");
            return internal_error();
        }
        return json_ok(serde_json::json!({"ok": true}));
    }

    match password::verify(&body.password, &user.password_hash).await {
        Ok(true) => {}
        _ => return unauthorized("invalid credentials"),
    }
    if !verify_code_or_backup(&state, user, &row, body.code.trim()).await {
        return unauthorized("invalid code");
    }

    let now = now_ms_i64();
    if let Err(e) = state.db.delete_user_totp(&user.id).await {
        warn!(error = %e, "delete_user_totp failed");
        return internal_error();
    }
    if let Err(e) = state.db.delete_backup_codes_for_user(&user.id).await {
        warn!(error = %e, "delete_backup_codes_for_user failed");
    }

    let (actor_kind, actor_user_id) = principal_actor(&principal);
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: actor_user_id.as_deref(),
            actor_kind,
            action: "user.2fa.disable",
            target_kind: "user",
            target_id: Some(&user.id),
            metadata: None,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action 2fa.disable failed");
    }

    json_ok(serde_json::json!({"ok": true}))
}

pub(super) async fn post_regenerate(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    axum::Json(body): axum::Json<RegenerateRequest>,
) -> Response {
    let Principal::User(ref user) = principal else {
        return error_response(
            StatusCode::FORBIDDEN,
            "user_required",
            "2FA management is per-user",
        );
    };
    let Ok(Some(row)) = state.db.find_user_totp(&user.id).await else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "twofa_not_enabled",
            "2FA is not enabled",
        );
    };
    if row.confirmed_at_ms.is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "twofa_not_enabled",
            "2FA is not enabled",
        );
    }
    let secret = match totp::unseal(&row.secret_encrypted, &state.kek) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "totp unseal failed");
            return internal_error();
        }
    };
    let last_used = row.last_used_step.and_then(|v| u64::try_from(v).ok());
    let Ok(step) = totp::verify_code(&secret, body.code.trim(), now_unix(), last_used) else {
        return unauthorized("invalid code");
    };
    let Ok(step_i) = i64::try_from(step) else {
        return internal_error();
    };
    if let Err(e) = state.db.set_totp_last_used_step(&user.id, step_i).await {
        warn!(error = %e, "set_totp_last_used_step failed");
    }

    let now = now_ms_i64();
    let codes = match issue_backup_codes(&state, &user.id, now).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "issue_backup_codes (regen) failed");
            return internal_error();
        }
    };
    json_ok(serde_json::json!({ "backup_codes": codes }))
}

/// Verify a 6-digit TOTP or a backup code. On a TOTP match the step is
/// persisted as `last_used_step`; on a backup match the row is consumed.
pub(super) async fn verify_code_or_backup(
    state: &Arc<AppState>,
    user: &crate::hub::db::users::UserRow,
    row: &UserTotpRow,
    code: &str,
) -> bool {
    if code.len() == totp::DIGITS && code.bytes().all(|b| b.is_ascii_digit()) {
        let secret = match totp::unseal(&row.secret_encrypted, &state.kek) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "totp unseal failed");
                return false;
            }
        };
        let last = row.last_used_step.and_then(|v| u64::try_from(v).ok());
        let Ok(step) = totp::verify_code(&secret, code, now_unix(), last) else {
            return false;
        };
        let Ok(step_i) = i64::try_from(step) else {
            return false;
        };
        if let Err(e) = state.db.set_totp_last_used_step(&user.id, step_i).await {
            warn!(error = %e, "set_totp_last_used_step failed");
        }
        return true;
    }

    if !backup_codes::looks_like_backup_code(code) {
        return false;
    }
    let candidates = match state.db.list_unused_backup_codes(&user.id).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "list_unused_backup_codes failed");
            return false;
        }
    };
    for cand in candidates {
        match backup_codes::verify(code, &cand.code_hash).await {
            Ok(true) => match state.db.consume_backup_code(&cand.id, now_ms_i64()).await {
                Ok(true) => return true,
                Ok(false) => return false,
                Err(e) => {
                    warn!(error = %e, "consume_backup_code failed");
                    return false;
                }
            },
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "backup_codes::verify failed");
                return false;
            }
        }
    }
    false
}

async fn issue_backup_codes(
    state: &Arc<AppState>,
    user_id: &str,
    now: i64,
) -> anyhow::Result<Vec<String>> {
    let plain = backup_codes::generate_set();
    let mut hashes = Vec::with_capacity(plain.len());
    for code in &plain {
        hashes.push(backup_codes::hash(code).await?);
    }
    let ids: Vec<String> = (0..plain.len()).map(|_| random_code(12)).collect();
    let news: Vec<NewBackupCode> = ids
        .iter()
        .zip(hashes.iter())
        .map(|(id, code_hash)| NewBackupCode {
            id,
            user_id,
            code_hash,
            now_ms: now,
        })
        .collect();
    state.db.replace_backup_codes(user_id, &news).await?;
    Ok(plain)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
