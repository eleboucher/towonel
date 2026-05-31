use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::hub::auth::api_key;
use crate::hub::auth::middleware::Principal;
use crate::hub::db;
use crate::hub::db::api_keys::NewApiKey;

use super::auth::new_id;
use super::signup_invites::now_ms_i64;
use super::{
    AppState, internal_error, invalid_request, json_ok, json_with_status, not_found, user_required,
};

/// Cap per user so a runaway client can't fill the table.
const MAX_KEYS_PER_USER: u64 = 50;
const NAME_MAX_LEN: usize = 128;
const MAX_EXPIRY_DAYS: i64 = 365;
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Deserialize)]
pub(super) struct CreateApiKeyRequest {
    name: String,
    /// Optional lifetime. Omit for a non-expiring key.
    expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ApiKeyInfo {
    id: String,
    name: String,
    expires_at_ms: Option<i64>,
    last_used_at_ms: Option<i64>,
    created_at_ms: i64,
}

impl From<db::api_keys::ApiKeyRow> for ApiKeyInfo {
    fn from(r: db::api_keys::ApiKeyRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            expires_at_ms: r.expires_at_ms,
            last_used_at_ms: r.last_used_at_ms,
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct CreateApiKeyResponse {
    id: String,
    name: String,
    expires_at_ms: Option<i64>,
    created_at_ms: i64,
    /// Plaintext token, returned exactly once.
    token: String,
}

#[derive(Debug, Serialize)]
struct ListApiKeysResponse {
    keys: Vec<ApiKeyInfo>,
}

pub(super) async fn post_api_key(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    axum::Json(body): axum::Json<CreateApiKeyRequest>,
) -> Response {
    let Principal::User(user) = principal else {
        return user_required("api keys can only be created by a user account");
    };

    let name = body.name.trim();
    if name.is_empty() || name.len() > NAME_MAX_LEN {
        return invalid_request("name must be 1-128 characters");
    }
    let now = now_ms_i64();
    let expires_at_ms = match body.expires_in_days {
        None => None,
        Some(days) if (1..=MAX_EXPIRY_DAYS).contains(&days) => {
            Some(now.saturating_add(days.saturating_mul(MS_PER_DAY)))
        }
        Some(_) => return invalid_request("expires_in_days must be between 1 and 365"),
    };

    match state.db.count_api_keys_for_user(&user.id).await {
        Ok(n) if n >= MAX_KEYS_PER_USER => {
            return invalid_request("api key limit reached; revoke an existing key first");
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "count_api_keys_for_user failed");
            return internal_error();
        }
    }

    let id = new_id(16);
    let minted = api_key::mint();
    if let Err(e) = state
        .db
        .insert_api_key(NewApiKey {
            id: &id,
            user_id: &user.id,
            key_hash: &minted.key_hash,
            name,
            expires_at_ms,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_api_key failed");
        return internal_error();
    }

    json_with_status(
        StatusCode::CREATED,
        CreateApiKeyResponse {
            id,
            name: name.to_string(),
            expires_at_ms,
            created_at_ms: now,
            token: minted.token,
        },
    )
}

pub(super) async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(user) = principal else {
        return user_required("api keys are scoped to a user account");
    };
    match state.db.list_api_keys_for_user(&user.id).await {
        Ok(rows) => json_ok(ListApiKeysResponse {
            keys: rows.into_iter().map(ApiKeyInfo::from).collect(),
        }),
        Err(e) => {
            warn!(error = %e, "list_api_keys_for_user failed");
            internal_error()
        }
    }
}

pub(super) async fn delete_api_key(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let Principal::User(user) = principal else {
        return user_required("api keys are scoped to a user account");
    };
    match state.db.delete_api_key(&id, &user.id).await {
        Ok(0) => not_found("api key not found"),
        Ok(_) => json_ok(serde_json::json!({"ok": true})),
        Err(e) => {
            warn!(error = %e, "delete_api_key failed");
            internal_error()
        }
    }
}
