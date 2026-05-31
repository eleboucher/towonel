#![allow(dead_code, reason = "consumed by web routes once mounted")]

use std::sync::Arc;

use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::Response;
use towonel_common::time::now_ms;

use super::{api_key, session};
use crate::hub::api::{AppState, error_response, internal_error, not_found, unauthorized};
use crate::hub::db::users::UserRow;

/// Don't write `api_keys.last_used_at_ms` on every authenticated request —
/// only once the stored value is at least this stale. Bounds key-table writes
/// to ~1/min/key while still giving users a usable "last used" signal.
const LAST_USED_REFRESH_MS: i64 = 60 * 1000;

// Routes an unenrolled operator can still reach so the UI can drive
// enrollment + offer a way out.
const TWOFA_ENROLLMENT_ALLOWED_PATHS: &[&str] = &[
    "/v1/auth/me",
    "/v1/auth/logout",
    "/v1/auth/2fa/setup",
    "/v1/auth/2fa/confirm",
    "/v1/auth/2fa/status",
    "/v1/auth/2fa/disable",
    "/v1/auth/passkeys",
    "/v1/auth/passkeys/register/begin",
    "/v1/auth/passkeys/register/finish",
    "/v1/auth/passkeys/{id}",
];

#[derive(Debug, Clone)]
pub enum Principal {
    OperatorKey,
    User(UserRow),
}

impl Principal {
    #[must_use]
    pub fn is_operator(&self) -> bool {
        match self {
            Self::OperatorKey => true,
            Self::User(u) => u.role == "operator",
        }
    }
}

impl FromRequestParts<Arc<AppState>> for Principal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            // Operator key: a bare token, constant-time compared.
            if super::super::api::constant_time_eq(
                token.as_bytes(),
                state.operator_api_key.as_bytes(),
            ) {
                return Ok(Self::OperatorKey);
            }
            // Personal API key (`twk_…`): authenticates as the owning user.
            // Deliberately skips the operator-2FA gate enforced on the cookie
            // path below — the key itself is the strong credential, so
            // automation can run without an interactive second factor.
            if let Some(key_hash) = api_key::parse(token)
                && let Some(user) = authenticate_api_key(state, &key_hash).await?
            {
                return Ok(Self::User(user));
            }
        }

        if let Some(cookie_header) = parts
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            && let Some(cookie_value) = session::extract_from_cookie_header(cookie_header)
            && let Some((session_id, token_hash)) = session::parse(cookie_value)
        {
            let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
            let row = state
                .db
                .find_active_session(&session_id, &token_hash, now)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "session lookup failed");
                    internal_error()
                })?;
            if let Some(row) = row {
                let user = state.db.find_user_by_id(&row.user_id).await.map_err(|e| {
                    tracing::warn!(error = %e, "user lookup failed");
                    internal_error()
                })?;
                if let Some(user) = user
                    && user.disabled_at_ms.is_none()
                {
                    enforce_operator_twofa(parts, state, &user).await?;
                    return Ok(Self::User(user));
                }
            }
        }

        Err(unauthorized("authentication required"))
    }
}

/// Resolve a personal API key hash to its owning, enabled user. Returns
/// `Ok(None)` when the key is unknown/expired, or the user is missing or
/// disabled — callers fall through to other auth rather than 401 outright.
async fn authenticate_api_key(
    state: &Arc<AppState>,
    key_hash: &[u8],
) -> Result<Option<UserRow>, Response> {
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let Some(key) = state
        .db
        .find_valid_api_key(key_hash, now)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "api key lookup failed");
            internal_error()
        })?
    else {
        return Ok(None);
    };
    let Some(user) = state.db.find_user_by_id(&key.user_id).await.map_err(|e| {
        tracing::warn!(error = %e, "user lookup failed for api key");
        internal_error()
    })?
    else {
        return Ok(None);
    };
    if user.disabled_at_ms.is_some() {
        return Ok(None);
    }

    // Best-effort, throttled last-used stamp. Runs detached so it never adds
    // a DB round-trip to the request's critical path.
    let needs_refresh = key
        .last_used_at_ms
        .is_none_or(|t| now.saturating_sub(t) >= LAST_USED_REFRESH_MS);
    if needs_refresh {
        let state = state.clone();
        let key_id = key.id;
        tokio::spawn(async move {
            if let Err(e) = state.db.touch_api_key_last_used(&key_id, now).await {
                tracing::warn!(error = %e, "touch_api_key_last_used failed");
            }
        });
    }

    Ok(Some(user))
}

async fn enforce_operator_twofa(
    parts: &Parts,
    state: &Arc<AppState>,
    user: &UserRow,
) -> Result<(), Response> {
    if user.role != "operator" {
        return Ok(());
    }
    let matched = parts
        .extensions
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    if matches!(matched, Some(p) if TWOFA_ENROLLMENT_ALLOWED_PATHS.contains(&p)) {
        return Ok(());
    }
    let totp_confirmed = state
        .db
        .find_user_totp(&user.id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "find_user_totp failed");
            internal_error()
        })?
        .is_some_and(|r| r.confirmed_at_ms.is_some());
    if totp_confirmed {
        return Ok(());
    }
    let passkey_count = state
        .db
        .count_passkeys_for_user(&user.id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "count_passkeys_for_user failed");
            internal_error()
        })?;
    if passkey_count > 0 {
        return Ok(());
    }
    Err(error_response(
        StatusCode::FORBIDDEN,
        "twofa_setup_required",
        "enroll in two-factor authentication before using this endpoint",
    ))
}

pub struct OperatorPrincipal(pub Principal);

impl FromRequestParts<Arc<AppState>> for OperatorPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let p = Principal::from_request_parts(parts, state).await?;
        if !p.is_operator() {
            // 404 on admin paths to hide endpoint existence from non-operators.
            return Err(not_found("not found"));
        }
        Ok(Self(p))
    }
}
