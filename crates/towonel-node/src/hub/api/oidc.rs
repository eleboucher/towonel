//! `OpenID` Connect login.
//!
//! Flow:
//! 1. `GET /v1/auth/oidc/{provider}/start?signup_code=&next=` — generate
//!    PKCE + nonce, stash in [`PendingOidcFlow`], 302 to the provider.
//! 2. Provider redirects back to `/v1/auth/oidc/{provider}/callback?code=&state=`.
//! 3. Look up the pending flow by state, exchange code, verify the
//!    `id_token`, and either mint a session for the linked user, or claim
//!    the attached `signup_code` and create a new linked account.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

use crate::config::OidcProviderConfig;
use crate::hub::auth::session;
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::user_oauth_identities::NewOauthIdentity;
use crate::hub::db::users::NewUser;

use super::signup_invites::{now_ms_i64, random_code};
use super::{AppState, json_with_status};

const FLOW_TTL: Duration = Duration::from_mins(10);
const SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

pub type OidcHttpClient = openidconnect::reqwest::Client;

#[derive(Clone)]
pub struct OidcProviderRuntime {
    pub display_name: &'static str,
    pub client: Arc<
        CoreClient<
            openidconnect::EndpointSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointMaybeSet,
            openidconnect::EndpointMaybeSet,
        >,
    >,
    pub http: Arc<OidcHttpClient>,
    pub scopes: Vec<String>,
    /// Pending flows, keyed by the CSRF state nonce we sent to the provider.
    pub pending: moka::future::Cache<String, PendingOidcFlow>,
}

#[derive(Clone)]
pub struct PendingOidcFlow {
    pub pkce_verifier_secret: Zeroizing<String>,
    pub nonce: String,
    pub signup_code: Option<String>,
    pub next: String,
}

#[derive(Default, Clone)]
pub struct OidcRuntimes {
    pub codeberg: Option<OidcProviderRuntime>,
}

impl std::fmt::Debug for OidcRuntimes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcRuntimes")
            .field("codeberg", &self.codeberg.as_ref().map(|_| "<configured>"))
            .finish()
    }
}

impl OidcRuntimes {
    pub fn get(&self, provider: &str) -> Option<&OidcProviderRuntime> {
        match provider {
            "codeberg" => self.codeberg.as_ref(),
            _ => None,
        }
    }
}

/// Discovery failure is fatal so a deploy with wrong issuer/client-id
/// surfaces at startup, not on the first user's callback.
pub async fn build_runtimes(cfg: &crate::config::OidcConfig) -> anyhow::Result<OidcRuntimes> {
    Ok(OidcRuntimes {
        codeberg: match cfg.codeberg.as_ref() {
            Some(c) => Some(build_provider("Codeberg", c).await?),
            None => None,
        },
    })
}

async fn build_provider(
    display_name: &'static str,
    cfg: &OidcProviderConfig,
) -> anyhow::Result<OidcProviderRuntime> {
    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| anyhow::anyhow!("oidc http client build failed: {e}"))?;
    let issuer = IssuerUrl::new(cfg.issuer.clone())
        .map_err(|e| anyhow::anyhow!("invalid OIDC issuer {}: {e}", cfg.issuer))?;
    let metadata = CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery for {display_name} failed: {e}"))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(cfg.client_id.clone()),
        Some(ClientSecret::new(cfg.client_secret.to_string())),
    )
    .set_redirect_uri(
        RedirectUrl::new(cfg.redirect_uri.clone())
            .map_err(|e| anyhow::anyhow!("invalid redirect_uri {}: {e}", cfg.redirect_uri))?,
    );
    let pending = moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(FLOW_TTL)
        .build();
    Ok(OidcProviderRuntime {
        display_name,
        client: Arc::new(client),
        http: Arc::new(http),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        pending,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct StartParams {
    #[serde(default)]
    signup_code: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

pub(super) async fn start(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<StartParams>,
) -> Response {
    let Some(runtime) = state.oidc.get(&provider) else {
        return error_redirect(&provider, "provider_disabled");
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = runtime
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);
    for s in &runtime.scopes {
        req = req.add_scope(Scope::new(s.clone()));
    }
    let (auth_url, csrf, nonce) = req.url();

    let flow = PendingOidcFlow {
        pkce_verifier_secret: Zeroizing::new(pkce_verifier.secret().clone()),
        nonce: nonce.secret().clone(),
        signup_code: params
            .signup_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        next: sanitize_next(params.next.as_deref()),
    };
    runtime.pending.insert(csrf.secret().clone(), flow).await;

    redirect_to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
pub(super) struct CallbackParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub(super) async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let Some(runtime) = state.oidc.get(&provider) else {
        return error_redirect(&provider, "provider_disabled");
    };

    if let Some(err) = params.error.as_deref() {
        warn!(provider = %provider, error = %err, "OIDC callback returned error");
        return error_redirect(&provider, "provider_error");
    }
    let (Some(code), Some(csrf_state)) = (params.code, params.state) else {
        return error_redirect(&provider, "bad_callback");
    };
    let Some(flow) = runtime.pending.remove(&csrf_state).await else {
        return error_redirect(&provider, "expired_or_unknown_state");
    };

    let pkce_verifier = PkceCodeVerifier::new(flow.pkce_verifier_secret.to_string());

    let token_response = match runtime.client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => match req
            .set_pkce_verifier(pkce_verifier)
            .request_async(&*runtime.http)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "OIDC token exchange failed");
                return error_redirect(&provider, "token_exchange_failed");
            }
        },
        Err(e) => {
            warn!(error = %e, "OIDC exchange_code build failed");
            return error_redirect(&provider, "token_exchange_failed");
        }
    };

    let Some(id_token) = token_response.id_token() else {
        warn!("OIDC token response missing id_token");
        return error_redirect(&provider, "no_id_token");
    };
    let verifier = runtime.client.id_token_verifier();
    let nonce_check = Nonce::new(flow.nonce.clone());
    let claims = match id_token.claims(&verifier, &nonce_check) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "OIDC id_token verification failed");
            return error_redirect(&provider, "id_token_invalid");
        }
    };

    let subject = claims.subject().as_str().to_string();
    let email = claims.email().map(|e| e.as_str().to_string());

    let existing = match state.db.find_oauth_identity(&provider, &subject).await {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "find_oauth_identity failed");
            return error_redirect(&provider, "internal_error");
        }
    };

    let user_id = if let Some(ident) = existing {
        match state.db.find_user_by_id(&ident.user_id).await {
            Ok(Some(u)) if u.disabled_at_ms.is_none() => u.id,
            Ok(Some(_)) => return error_redirect(&provider, "account_disabled"),
            Ok(None) => return error_redirect(&provider, "linked_user_missing"),
            Err(e) => {
                warn!(error = %e, "find_user_by_id failed");
                return error_redirect(&provider, "internal_error");
            }
        }
    } else {
        let Some(code) = flow.signup_code.as_deref() else {
            return error_redirect(&provider, "signup_required");
        };
        let Some(email_val) = email else {
            return error_redirect(&provider, "no_email");
        };
        match signup_via_oidc(&state, &provider, &subject, &email_val, code).await {
            Ok(id) => id,
            Err(why) => return error_redirect(&provider, why),
        }
    };

    let next = sanitize_next(Some(&flow.next));
    issue_session_redirect(&state, &user_id, &next).await
}

#[derive(Serialize)]
struct AdvertisedProvider {
    id: &'static str,
    display_name: &'static str,
}

pub(super) async fn list_providers(State(state): State<Arc<AppState>>) -> Response {
    let mut providers: Vec<AdvertisedProvider> = Vec::new();
    if let Some(r) = state.oidc.codeberg.as_ref() {
        providers.push(AdvertisedProvider {
            id: "codeberg",
            display_name: r.display_name,
        });
    }
    json_with_status(
        StatusCode::OK,
        serde_json::json!({ "providers": providers }),
    )
}

async fn signup_via_oidc(
    state: &Arc<AppState>,
    provider: &str,
    subject: &str,
    email: &str,
    code: &str,
) -> Result<String, &'static str> {
    let now_ms_i = now_ms_i64();
    let sentinel = format!("oidc:{now_ms_i}:{}", random_code(8));

    let claimed = match state
        .db
        .claim_signup_invite(code, &sentinel, now_ms_i)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return Err("invite_invalid"),
        Err(e) => {
            warn!(error = %e, "claim_signup_invite failed (oidc)");
            return Err("internal_error");
        }
    };

    let user_id = random_code(16);

    // Empty password_hash sentinel marks an OIDC-only account; the
    // password-login handler routes these through the timing-constant
    // sentinel verify path.
    if let Err(e) = state
        .db
        .insert_user(NewUser {
            id: &user_id,
            email,
            password_hash: "",
            role: &claimed.role,
            now_ms: now_ms_i,
        })
        .await
    {
        let dup = crate::hub::db::is_unique_violation(&e);
        if !dup {
            warn!(error = %e, "insert_user (oidc) failed");
        }
        if let Err(rel_err) = state
            .db
            .release_signup_invite(&claimed.code, &sentinel)
            .await
        {
            warn!(error = %rel_err, "release_signup_invite after oidc insert_user failure");
        }
        return Err(if dup { "email_taken" } else { "internal_error" });
    }

    if let Err(e) = state
        .db
        .finalize_signup_invite(&claimed.code, &sentinel, &user_id)
        .await
    {
        warn!(error = %e, "finalize_signup_invite failed (oidc)");
        if let Err(del_err) = state.db.delete_user(&user_id).await {
            warn!(error = %del_err, "delete_user rollback (oidc)");
        }
        return Err("internal_error");
    }

    if let Err(e) = state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider,
            subject,
            user_id: &user_id,
            email: Some(email),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_oauth_identity failed");
        if let Err(del_err) = state.db.delete_user(&user_id).await {
            warn!(error = %del_err, "delete_user rollback (oidc link)");
        }
        return Err("internal_error");
    }

    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: None,
            actor_kind: "system",
            action: "user.signup.oidc",
            target_kind: "user",
            target_id: Some(&user_id),
            metadata: Some(serde_json::json!({
                "provider": provider,
                "signup_invite_code": claimed.code,
            })),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action oidc signup failed");
    }

    Ok(user_id)
}

async fn issue_session_redirect(state: &Arc<AppState>, user_id: &str, next: &str) -> Response {
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
        warn!(error = %e, "insert_session failed (oidc)");
        return error_redirect("oidc", "session_failed");
    }

    let secure = state.public_url.starts_with("https://");
    let cookie = session::set_cookie_header(
        &s.cookie_value,
        u64::try_from(SESSION_TTL_MS / 1000).unwrap_or(7 * 24 * 60 * 60),
        secure,
    );

    let mut resp = redirect_to(next);
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

fn redirect_to(url: &str) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(url) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

fn error_redirect(provider: &str, reason: &'static str) -> Response {
    let target = format!("/login?oidc_error={reason}&provider={provider}");
    redirect_to(&target)
}

/// Browsers normalise `Location: /\evil.com` to `//evil.com`, so reject
/// backslashes alongside protocol-relative paths.
fn sanitize_next(raw: Option<&str>) -> String {
    let candidate = raw.unwrap_or("/").trim();
    let ok = candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.starts_with("/\\")
        && !candidate
            .chars()
            .any(|c| c == '\\' || c.is_control() || c.is_whitespace());
    if ok {
        candidate.to_string()
    } else {
        "/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_next;

    #[test]
    fn accepts_plain_absolute_path() {
        assert_eq!(sanitize_next(Some("/tunnels")), "/tunnels");
        assert_eq!(sanitize_next(Some("/")), "/");
        assert_eq!(sanitize_next(Some("/a/b?c=d#e")), "/a/b?c=d#e");
    }

    #[test]
    fn rejects_protocol_relative() {
        assert_eq!(sanitize_next(Some("//evil.com")), "/");
        assert_eq!(sanitize_next(Some("//evil.com/x")), "/");
    }

    #[test]
    fn rejects_backslash_path() {
        // Browsers normalise `Location: /\evil.com` to `//evil.com`.
        assert_eq!(sanitize_next(Some("/\\evil.com")), "/");
        assert_eq!(sanitize_next(Some("/foo\\bar")), "/");
        assert_eq!(sanitize_next(Some("\\\\evil.com")), "/");
    }

    #[test]
    fn rejects_absolute_url() {
        assert_eq!(sanitize_next(Some("https://evil/")), "/");
        assert_eq!(sanitize_next(Some("javascript:alert(1)")), "/");
    }

    #[test]
    fn rejects_control_and_whitespace() {
        assert_eq!(sanitize_next(Some("/foo\nbar")), "/");
        assert_eq!(sanitize_next(Some("/foo bar")), "/");
        assert_eq!(sanitize_next(Some("/foo\tbar")), "/");
    }

    #[test]
    fn defaults_when_absent() {
        assert_eq!(sanitize_next(None), "/");
        assert_eq!(sanitize_next(Some("")), "/");
    }
}
