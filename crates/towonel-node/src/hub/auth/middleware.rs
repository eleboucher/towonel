#![allow(dead_code, reason = "consumed by web routes once mounted")]

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use towonel_common::time::now_ms;

use super::session;
use crate::hub::api::AppState;
use crate::hub::db::users::UserRow;

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
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            && let Some(token) = auth.strip_prefix("Bearer ")
            && super::super::api::constant_time_eq(
                token.as_bytes(),
                state.operator_api_key.as_bytes(),
            )
        {
            return Ok(Self::OperatorKey);
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
                    (StatusCode::INTERNAL_SERVER_ERROR, "session lookup failed")
                })?;
            if let Some(row) = row {
                let user = state.db.find_user_by_id(&row.user_id).await.map_err(|e| {
                    tracing::warn!(error = %e, "user lookup failed");
                    (StatusCode::INTERNAL_SERVER_ERROR, "user lookup failed")
                })?;
                if let Some(user) = user
                    && user.disabled_at_ms.is_none()
                {
                    return Ok(Self::User(user));
                }
            }
        }

        Err((StatusCode::UNAUTHORIZED, "authentication required"))
    }
}

pub struct OperatorPrincipal(pub Principal);

impl FromRequestParts<Arc<AppState>> for OperatorPrincipal {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let p = Principal::from_request_parts(parts, state).await?;
        if !p.is_operator() {
            // 404 on admin paths to hide endpoint existence from non-operators.
            return Err((StatusCode::NOT_FOUND, "not found"));
        }
        Ok(Self(p))
    }
}
