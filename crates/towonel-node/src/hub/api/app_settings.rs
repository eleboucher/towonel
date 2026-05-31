use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::time::now_ms;
use tracing::warn;
use utoipa::ToSchema;

use crate::hub::auth::middleware::OperatorPrincipal;
use crate::hub::db::app_settings::{DEFAULT_USER_PORT_QUOTA, USER_PORT_QUOTA_KEY};

use super::{AppState, internal_error, invalid_request, json_ok};

#[derive(Debug, Serialize, ToSchema)]
struct QuotaResponse {
    value: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct UpdateQuotaRequest {
    value: i64,
}

#[utoipa::path(
    get,
    path = "/v1/settings/user-port-quota",
    tag = "settings",
    responses((status = 200, description = "Per-user port quota", body = QuotaResponse)),
    security(("operator_key" = [])),
)]
pub(super) async fn get_user_port_quota(
    State(state): State<Arc<AppState>>,
    _operator: OperatorPrincipal,
) -> Response {
    match state.db.get_setting_int(USER_PORT_QUOTA_KEY).await {
        Ok(Some(v)) => json_ok(QuotaResponse { value: v }),
        Ok(None) => json_ok(QuotaResponse {
            value: DEFAULT_USER_PORT_QUOTA,
        }),
        Err(e) => {
            warn!(error = %e, "get_setting_int user_port_quota failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    put,
    path = "/v1/settings/user-port-quota",
    tag = "settings",
    request_body = UpdateQuotaRequest,
    responses(
        (status = 200, description = "Quota updated", body = QuotaResponse),
        (status = 400, description = "Value must be >= 0"),
    ),
    security(("operator_key" = [])),
)]
pub(super) async fn put_user_port_quota(
    State(state): State<Arc<AppState>>,
    _operator: OperatorPrincipal,
    axum::Json(body): axum::Json<UpdateQuotaRequest>,
) -> Response {
    if body.value < 0 {
        return invalid_request("value must be >= 0");
    }
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    if let Err(e) = state
        .db
        .set_setting_int(USER_PORT_QUOTA_KEY, body.value, now)
        .await
    {
        warn!(error = %e, "set_setting_int user_port_quota failed");
        return internal_error();
    }
    json_ok(QuotaResponse { value: body.value })
}
