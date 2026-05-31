use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

use crate::hub::auth::middleware::{OperatorPrincipal, Principal};
use crate::hub::db::admin_actions::NewAdminAction;

use super::signup_invites::{now_ms_i64, principal_actor, random_code};
use super::{AppState, internal_error, invalid_request, json_ok};

#[derive(Debug, Serialize, ToSchema)]
struct UserEntry {
    id: String,
    email: String,
    role: String,
    disabled_at_ms: Option<i64>,
    created_at_ms: i64,
}

#[utoipa::path(
    get,
    path = "/v1/users",
    tag = "users",
    responses((status = 200, description = "All users", body = [UserEntry])),
    security(("operator_key" = [])),
)]
pub(super) async fn list_users(
    State(state): State<Arc<AppState>>,
    _operator: OperatorPrincipal,
) -> Response {
    let rows = match state.db.list_users().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list_users failed");
            return internal_error();
        }
    };
    let entries: Vec<UserEntry> = rows
        .into_iter()
        .map(|u| UserEntry {
            id: u.id,
            email: u.email,
            role: u.role,
            disabled_at_ms: u.disabled_at_ms,
            created_at_ms: u.created_at_ms,
        })
        .collect();
    json_ok(entries)
}

#[utoipa::path(
    post,
    path = "/v1/users/{id}/disable",
    tag = "users",
    params(("id" = String, Path, description = "User id")),
    responses(
        (status = 200, description = "User disabled and their sessions revoked"),
        (status = 400, description = "Cannot disable yourself"),
    ),
    security(("operator_key" = [])),
)]
pub(super) async fn post_user_disable(
    State(state): State<Arc<AppState>>,
    OperatorPrincipal(actor): OperatorPrincipal,
    Path(id): Path<String>,
) -> Response {
    if let Principal::User(ref u) = actor
        && u.id == id
    {
        return invalid_request("cannot disable yourself");
    }

    let now = now_ms_i64();
    if let Err(e) = state.db.disable_user(&id, now).await {
        warn!(error = %e, "disable_user failed");
        return internal_error();
    }
    if let Err(e) = state.db.delete_sessions_for_user(&id).await {
        warn!(error = %e, "delete_sessions_for_user failed");
    }

    let (actor_kind, actor_user_id) = principal_actor(&actor);
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: actor_user_id.as_deref(),
            actor_kind,
            action: "user.disable",
            target_kind: "user",
            target_id: Some(&id),
            metadata: None,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action failed");
    }

    json_ok(serde_json::json!({"ok": true}))
}
