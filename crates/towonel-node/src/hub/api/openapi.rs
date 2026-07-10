//! `OpenAPI` documents for the hub HTTP API, split by audience:
//! [`UserApiDoc`] (the `/v1/auth/*` + tenant-port surface) and
//! [`OperatorApiDoc`] (operator-only management).

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::hub::auth::session::COOKIE_NAME;

struct UserSecurity;

impl Modify for UserSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                COOKIE_NAME,
                "Session cookie set by `POST /v1/auth/login`.",
            ))),
        );
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Personal API key (`twk_…`) passed as `Authorization: Bearer <key>`.",
                    ))
                    .build(),
            ),
        );
    }
}

struct OperatorSecurity;

impl Modify for OperatorSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "operator_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Operator API key passed as `Authorization: Bearer <key>`.",
                    ))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Towonel User API"),
    modifiers(&UserSecurity),
    paths(
        super::auth::post_signup,
        super::auth::post_login,
        super::auth::post_logout,
        super::auth::get_me,
        super::auth::post_twofa_verify,
        super::verify::post_verify,
        super::verify::get_verify,
        super::verify::post_resend,
        super::password_reset::post_request,
        super::password_reset::post_confirm,
        super::api_keys::post_api_key,
        super::api_keys::list_api_keys,
        super::api_keys::delete_api_key,
        super::twofa::get_status,
        super::twofa::post_setup,
        super::twofa::post_confirm,
        super::twofa::post_disable,
        super::twofa::post_regenerate,
        super::passkey::list_passkeys,
        super::passkey::post_register_begin,
        super::passkey::post_register_finish,
        super::passkey::delete_passkey,
        super::passkey::post_authenticate_begin,
        super::passkey::post_authenticate_finish,
        super::oidc::list_providers,
        super::oidc::start,
        super::oidc::link,
        super::oidc::unlink,
        super::oidc::list_identities,
        super::oidc::callback,
        super::ports::post_port,
        super::ports::list_ports,
        super::ports::delete_port,
        super::ports::get_available_ports,
        super::invites::post_invite,
        super::invites::list_invites,
        super::invites::get_invite,
        super::invites::get_invite_status,
        super::invites::delete_invite,
        super::invites::post_invite_hostnames,
        super::invites::delete_invite_hostname,
    ),
)]
pub struct UserApiDoc;

#[derive(OpenApi)]
#[openapi(
    info(title = "Towonel Operator API"),
    modifiers(&OperatorSecurity),
    paths(
        super::invites::post_invite,
        super::invites::list_invites,
        super::invites::get_invite,
        super::invites::get_invite_status,
        super::invites::list_user_invites,
        super::invites::delete_invite,
        super::invites::post_invite_hostnames,
        super::invites::delete_invite_hostname,
        super::entries::delete_tenant,
        super::entries::list_edges,
        super::ports::list_all_ports,
        super::ports::post_port,
        super::ports::list_ports,
        super::ports::delete_port,
        super::ports::get_available_ports,
        super::app_settings::get_user_port_quota,
        super::app_settings::put_user_port_quota,
        super::signup_invites::post_signup_invite,
        super::signup_invites::list_signup_invites,
        super::users::list_users,
        super::users::get_user,
        super::users::post_user_disable,
    ),
)]
pub struct OperatorApiDoc;

/// Swagger UI at `/swagger-ui`; raw specs at `/api-docs/{user,operator}.json`.
#[must_use]
pub fn swagger_ui() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui")
        .url("/api-docs/user.json", UserApiDoc::openapi())
        .url("/api-docs/operator.json", OperatorApiDoc::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openapi()` runs schema collection, catching duplicate operationIds
    /// and bad schemas that the type checker misses.
    #[test]
    fn specs_generate() {
        UserApiDoc::openapi().to_json().unwrap();
        OperatorApiDoc::openapi().to_json().unwrap();
    }
}
