//! `OpenID` Connect login, signup-via-invite, and identity linking.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
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
use crate::hub::auth::middleware::Principal;
use crate::hub::auth::session;
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::user_oauth_identities::NewOauthIdentity;
use crate::hub::db::users::NewUser;

use super::signup_invites::{now_ms_i64, random_code};
use super::{AppState, json_ok, json_with_status};

const FLOW_TTL: Duration = Duration::from_mins(10);
const SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

pub type OidcHttpClient = openidconnect::reqwest::Client;

type ConfiguredCoreClient = CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct OidcProviderRuntime {
    pub display_name: &'static str,
    /// Swapped by the JWKS refresher on `IdP` key rotation.
    pub client: Arc<arc_swap::ArcSwap<Option<ConfiguredCoreClient>>>,
    pub http: Arc<OidcHttpClient>,
    pub scopes: Vec<String>,
    pub pending: moka::future::Cache<String, PendingOidcFlow>,
}

#[derive(Clone)]
pub struct PendingOidcFlow {
    pub pkce_verifier_secret: Zeroizing<String>,
    pub nonce: String,
    pub next: String,
    pub kind: OidcFlowKind,
}

#[derive(Clone)]
pub enum OidcFlowKind {
    LoginOrSignup { signup_code: Option<String> },
    Link { user_id: String },
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

pub fn build_runtimes(
    cfg: &crate::config::OidcConfig,
    metrics: &super::super::metrics::HubMetrics,
) -> OidcRuntimes {
    OidcRuntimes {
        codeberg: cfg
            .codeberg
            .as_ref()
            .map(|c| build_provider_lazy("codeberg", "Codeberg", c, metrics)),
    }
}

const JWKS_REFRESH_INTERVAL: Duration = Duration::from_hours(12);
const OIDC_INIT_RETRY_INITIAL: Duration = Duration::from_secs(2);
const OIDC_INIT_RETRY_MAX: Duration = Duration::from_mins(1);
const OIDC_INIT_RETRY_MULTIPLIER: f32 = 2.0;
const OIDC_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Build the runtime without blocking startup. The provider metadata
/// discovery runs in the background with retries until success.
fn build_provider_lazy(
    provider_id: &'static str,
    display_name: &'static str,
    cfg: &OidcProviderConfig,
    metrics: &super::super::metrics::HubMetrics,
) -> OidcProviderRuntime {
    let http = Arc::new(
        openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .expect("oidc http client build failed"),
    );
    let issuer = IssuerUrl::new(cfg.issuer.clone()).expect("invalid OIDC issuer");
    let redirect_uri = RedirectUrl::new(cfg.redirect_uri.clone()).expect("invalid redirect_uri");
    let parts = ClientParts {
        client_id: cfg.client_id.clone(),
        client_secret: cfg.client_secret.clone(),
        redirect_uri,
    };

    let pending = moka::future::Cache::builder()
        .max_capacity(1_000_000)
        .time_to_live(FLOW_TTL)
        .build();

    let runtime = OidcProviderRuntime {
        display_name,
        client: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        http: Arc::clone(&http),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        pending,
    };

    spawn_oidc_initializer(
        provider_id,
        display_name,
        issuer,
        http,
        parts,
        Arc::clone(&runtime.client),
        metrics.clone(),
    );

    runtime
}

fn spawn_oidc_initializer(
    provider_id: &'static str,
    display_name: &'static str,
    issuer: IssuerUrl,
    http: Arc<OidcHttpClient>,
    parts: ClientParts,
    client_swap: Arc<arc_swap::ArcSwap<Option<ConfiguredCoreClient>>>,
    metrics: super::super::metrics::HubMetrics,
) {
    tokio::spawn(async move {
        let mut delay = OIDC_INIT_RETRY_INITIAL;
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            let discovery = tokio::time::timeout(
                OIDC_DISCOVERY_TIMEOUT,
                CoreProviderMetadata::discover_async(issuer.clone(), &*http),
            );

            match discovery.await {
                Ok(Ok(meta)) => {
                    let client = build_client(meta, &parts);
                    client_swap.store(Arc::new(Some(client)));
                    metrics
                        .oidc_jwks_last_refresh_success_timestamp_seconds
                        .with_label_values(&[provider_id])
                        .set(
                            i64::try_from(towonel_common::time::now_ms() / 1000)
                                .unwrap_or(i64::MAX),
                        );
                    tracing::info!(
                        provider = %display_name,
                        attempts,
                        "OIDC provider metadata discovered"
                    );
                    break;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        provider = %display_name,
                        error = %e,
                        attempts,
                        next_retry_secs = delay.as_secs(),
                        "OIDC provider metadata discovery failed (retrying)"
                    );
                    metrics
                        .oidc_jwks_refresh_total
                        .with_label_values(&[provider_id, "failure"])
                        .inc();
                }
                Err(_) => {
                    tracing::warn!(
                        provider = %display_name,
                        attempts,
                        timeout_secs = OIDC_DISCOVERY_TIMEOUT.as_secs(),
                        next_retry_secs = delay.as_secs(),
                        "OIDC provider metadata discovery timed out (retrying)"
                    );
                    metrics
                        .oidc_jwks_refresh_total
                        .with_label_values(&[provider_id, "failure"])
                        .inc();
                }
            }

            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = towonel_common::shutdown::shutdown_signal() => {
                    tracing::info!(provider = %display_name, "OIDC initializer cancelled by shutdown");
                    return;
                }
            }
            delay = std::cmp::min(
                OIDC_INIT_RETRY_MAX,
                Duration::from_secs_f32(delay.as_secs_f32() * OIDC_INIT_RETRY_MULTIPLIER),
            );
        }

        spawn_jwks_refresher_after_init(
            provider_id,
            display_name,
            issuer,
            http,
            parts,
            client_swap,
            metrics,
        );
    });
}

#[derive(Clone)]
struct ClientParts {
    client_id: String,
    client_secret: zeroize::Zeroizing<String>,
    redirect_uri: RedirectUrl,
}

fn build_client(metadata: CoreProviderMetadata, parts: &ClientParts) -> ConfiguredCoreClient {
    CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(parts.client_id.clone()),
        Some(ClientSecret::new(parts.client_secret.to_string())),
    )
    .set_redirect_uri(parts.redirect_uri.clone())
}

fn spawn_jwks_refresher_after_init(
    provider_id: &'static str,
    display_name: &'static str,
    issuer: IssuerUrl,
    http: Arc<OidcHttpClient>,
    parts: ClientParts,
    client_swap: Arc<arc_swap::ArcSwap<Option<ConfiguredCoreClient>>>,
    metrics: super::super::metrics::HubMetrics,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(JWKS_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = towonel_common::shutdown::shutdown_signal() => {
                    tracing::info!(provider = %display_name, "JWKS refresher cancelled by shutdown");
                    return;
                }
            }
            refresh_provider_metadata(
                provider_id,
                display_name,
                &issuer,
                &http,
                &parts,
                &client_swap,
                &metrics,
            )
            .await;
        }
    });
}

async fn refresh_provider_metadata(
    provider_id: &'static str,
    display_name: &'static str,
    issuer: &IssuerUrl,
    http: &OidcHttpClient,
    parts: &ClientParts,
    client_swap: &arc_swap::ArcSwap<Option<ConfiguredCoreClient>>,
    metrics: &super::super::metrics::HubMetrics,
) {
    let discovery = tokio::time::timeout(
        OIDC_DISCOVERY_TIMEOUT,
        CoreProviderMetadata::discover_async(issuer.clone(), http),
    );

    match discovery.await {
        Ok(Ok(meta)) => {
            let client = build_client(meta, parts);
            client_swap.store(Arc::new(Some(client)));
            metrics
                .oidc_jwks_refresh_total
                .with_label_values(&[provider_id, "success"])
                .inc();
            metrics
                .oidc_jwks_last_refresh_success_timestamp_seconds
                .with_label_values(&[provider_id])
                .set(i64::try_from(towonel_common::time::now_ms() / 1000).unwrap_or(i64::MAX));
            tracing::info!(provider = %display_name, "OIDC provider metadata refreshed");
        }
        Ok(Err(e)) => {
            metrics
                .oidc_jwks_refresh_total
                .with_label_values(&[provider_id, "failure"])
                .inc();
            tracing::warn!(
                provider = %display_name,
                error = %e,
                "OIDC provider metadata refresh failed; keeping previous client",
            );
        }
        Err(_) => {
            metrics
                .oidc_jwks_refresh_total
                .with_label_values(&[provider_id, "failure"])
                .inc();
            tracing::warn!(
                provider = %display_name,
                timeout_secs = OIDC_DISCOVERY_TIMEOUT.as_secs(),
                "OIDC provider metadata refresh timed out; keeping previous client",
            );
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StartParams {
    #[serde(default)]
    signup_code: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/auth/oidc/{provider}/start",
    tag = "oidc",
    params(
        ("provider" = String, Path, description = "OIDC provider id (e.g. `codeberg`)"),
        ("signup_code" = Option<String>, Query, description = "Signup invite code, for first-time OIDC signup"),
        ("next" = Option<String>, Query, description = "Relative path to return to after login"),
    ),
    responses((status = 302, description = "Redirect to the provider's authorization endpoint")),
)]
pub(super) async fn start(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<StartParams>,
) -> Response {
    let signup_code = params
        .signup_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    begin_flow(
        &state,
        &provider,
        OidcFlowKind::LoginOrSignup { signup_code },
        params.next.as_deref(),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub(super) struct LinkParams {
    #[serde(default)]
    next: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/auth/oidc/{provider}/link",
    tag = "oidc",
    params(
        ("provider" = String, Path, description = "OIDC provider id"),
        ("next" = Option<String>, Query, description = "Relative path to return to afterwards"),
    ),
    responses((status = 302, description = "Redirect to the provider to link the identity to the current user")),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn link(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<LinkParams>,
    principal: Principal,
) -> Response {
    let Principal::User(user) = principal else {
        return error_redirect(&provider, "link_requires_user");
    };
    begin_flow(
        &state,
        &provider,
        OidcFlowKind::Link { user_id: user.id },
        params.next.as_deref(),
    )
    .await
}

async fn begin_flow(
    state: &Arc<AppState>,
    provider: &str,
    kind: OidcFlowKind,
    next: Option<&str>,
) -> Response {
    let Some(runtime) = state.oidc.get(provider) else {
        return error_redirect(provider, "provider_disabled");
    };

    let client_opt = runtime.client.load_full();
    let Some(client) = client_opt.as_ref() else {
        return error_redirect(provider, "provider_initializing");
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client
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
        next: sanitize_next(next),
        kind,
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

#[utoipa::path(
    get,
    path = "/v1/auth/oidc/{provider}/callback",
    tag = "oidc",
    params(
        ("provider" = String, Path, description = "OIDC provider id"),
        ("code" = Option<String>, Query, description = "Authorization code from the provider"),
        ("state" = Option<String>, Query, description = "CSRF state echoed by the provider"),
        ("error" = Option<String>, Query, description = "Error code if the provider denied the request"),
    ),
    responses((status = 302, description = "Redirect back to the app; sets the session cookie on success")),
)]
#[expect(clippy::too_many_lines, reason = "linear OIDC callback")]
pub(super) async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Response {
    let Some(runtime) = state.oidc.get(&provider) else {
        return error_redirect(&provider, "provider_disabled");
    };

    if let Some(err) = params.error.as_deref() {
        // attacker-controlled — sanitize before logging
        let sanitized = sanitize_log_field(err, 128);
        warn!(provider = %provider, error = %sanitized, "OIDC callback returned error");
        return error_redirect(&provider, "provider_error");
    }
    let (Some(code), Some(csrf_state)) = (params.code, params.state) else {
        return error_redirect(&provider, "bad_callback");
    };
    let Some(flow) = runtime.pending.remove(&csrf_state).await else {
        return error_redirect(&provider, "expired_or_unknown_state");
    };

    // `PkceCodeVerifier::new` drops the Zeroizing wrapper (upstream
    // takes plain String); secret lingers until request_async below.
    let pkce_verifier = PkceCodeVerifier::new(flow.pkce_verifier_secret.to_string());

    let client_opt = runtime.client.load_full();
    let Some(client) = client_opt.as_ref() else {
        return error_redirect(&provider, "provider_initializing");
    };
    let token_response = match client.exchange_code(AuthorizationCode::new(code)) {
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
    let verifier = client.id_token_verifier();
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
    let email_verified = claims.email_verified();

    let existing = match state.db.find_oauth_identity(&provider, &subject).await {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "find_oauth_identity failed");
            return error_redirect(&provider, "internal_error");
        }
    };

    let next = sanitize_next(Some(&flow.next));
    match flow.kind {
        OidcFlowKind::LoginOrSignup { signup_code } => {
            let user_id = if let Some(ident) = existing {
                let resolved_id = match state.db.find_user_by_id(&ident.user_id).await {
                    Ok(Some(u)) if u.disabled_at_ms.is_none() => u.id,
                    Ok(Some(_)) => return error_redirect(&provider, "account_disabled"),
                    Ok(None) => return error_redirect(&provider, "linked_user_missing"),
                    Err(e) => {
                        warn!(error = %e, "find_user_by_id failed");
                        return error_redirect(&provider, "internal_error");
                    }
                };
                // Keep the cached email in sync on every login.
                if email.is_some()
                    && let Err(e) = state
                        .db
                        .touch_oauth_identity_email(
                            &provider,
                            &subject,
                            email.as_deref(),
                            now_ms_i64(),
                        )
                        .await
                {
                    warn!(error = %e, "touch_oauth_identity_email failed (login)");
                }
                resolved_id
            } else {
                let Some(code) = signup_code.as_deref() else {
                    return error_redirect(&provider, "signup_required");
                };
                let Some(email_val) = email else {
                    return error_redirect(&provider, "no_email");
                };
                // IdP-verified email required: otherwise an invite
                // could be claimed under any address the attacker
                // wants, pre-squatting the real recipient.
                if email_verified != Some(true) {
                    return error_redirect(&provider, "email_unverified_by_idp");
                }
                match signup_via_oidc(
                    &state,
                    &provider,
                    &subject,
                    &email_val,
                    email_verified,
                    code,
                )
                .await
                {
                    Ok(id) => id,
                    // Point users at the link-from-settings path instead
                    // of a dead-end "email taken" message.
                    Err("email_taken") => {
                        return error_redirect_with_hint(
                            &provider,
                            "email_taken",
                            "link_from_settings",
                        );
                    }
                    Err(why) => return error_redirect(&provider, why),
                }
            };
            issue_session_redirect(&state, &user_id, &next).await
        }
        OidcFlowKind::Link { user_id } => {
            link_callback(
                &state,
                &provider,
                &subject,
                email.as_deref(),
                email_verified,
                &user_id,
                &headers,
                &next,
            )
            .await
        }
    }
}

/// Attach an identity to `expected_user_id` after re-verifying the
/// current session still belongs to them.
#[expect(clippy::too_many_arguments, reason = "linear link callback")]
async fn link_callback(
    state: &Arc<AppState>,
    provider: &str,
    subject: &str,
    email: Option<&str>,
    email_verified: Option<bool>,
    expected_user_id: &str,
    headers: &HeaderMap,
    next: &str,
) -> Response {
    match current_session_user_id(state, headers).await {
        Err(()) => return error_redirect_link(provider, "internal_error"),
        Ok(None) => return error_redirect(provider, "link_session_expired"),
        Ok(Some(uid)) if uid != expected_user_id => {
            return error_redirect_link(provider, "session_mismatch");
        }
        Ok(Some(_)) => {}
    }

    if email_verified != Some(true) {
        return error_redirect_link(provider, "email_unverified_by_idp");
    }

    let now_ms_i = now_ms_i64();
    match state.db.find_oauth_identity(provider, subject).await {
        // Idempotent re-link: refresh cached email and audit the change.
        Ok(Some(ident)) if ident.user_id == expected_user_id => {
            let previous_email = ident.email.clone();
            if let Err(e) = state
                .db
                .touch_oauth_identity_email(provider, subject, email, now_ms_i)
                .await
            {
                warn!(error = %e, "touch_oauth_identity_email failed (re-link)");
            } else if let Err(audit_err) = state
                .db
                .insert_admin_action(NewAdminAction {
                    id: &random_code(16),
                    actor_user_id: Some(expected_user_id),
                    actor_kind: "user",
                    action: "user.oidc.relink",
                    target_kind: "user",
                    target_id: Some(expected_user_id),
                    metadata: Some(serde_json::json!({
                        "provider": provider,
                        "subject": subject,
                        "previous_email": previous_email,
                        "email_claim": email,
                    })),
                    now_ms: now_ms_i,
                })
                .await
            {
                warn!(error = %audit_err, "insert_admin_action oidc relink failed");
            }
            return redirect_to(next);
        }
        Ok(Some(_)) => return error_redirect_link(provider, "identity_in_use"),
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "find_oauth_identity failed (link)");
            return error_redirect_link(provider, "internal_error");
        }
    }

    if let Err(e) = state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider,
            subject,
            user_id: expected_user_id,
            email,
            now_ms: now_ms_i,
        })
        .await
    {
        if !crate::hub::db::is_unique_violation(&e) {
            warn!(error = %e, "insert_oauth_identity failed (link)");
            return error_redirect_link(provider, "internal_error");
        }
        // (provider, subject) PK vs (user_id, provider) — re-query to
        // tell which constraint fired.
        let reason = match state.db.find_oauth_identity(provider, subject).await {
            Ok(Some(ident)) if ident.user_id != expected_user_id => "identity_in_use",
            Ok(_) => "provider_already_linked",
            Err(lookup_err) => {
                warn!(error = %lookup_err, "find_oauth_identity after dup failed (link)");
                "internal_error"
            }
        };
        return error_redirect_link(provider, reason);
    }

    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: Some(expected_user_id),
            actor_kind: "user",
            action: "user.oidc.link",
            target_kind: "user",
            target_id: Some(expected_user_id),
            metadata: Some(serde_json::json!({
                "provider": provider,
                "subject": subject,
                "email_claim": email,
                "email_verified": email_verified,
            })),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action oidc link failed");
    }

    redirect_to(next)
}

/// `Ok(None)` = no/expired session, `Err(())` = DB error.
async fn current_session_user_id(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Option<String>, ()> {
    let Some(cookie_header) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(cookie_value) = session::extract_from_cookie_header(cookie_header) else {
        return Ok(None);
    };
    let Some((session_id, token_hash)) = session::parse(cookie_value) else {
        return Ok(None);
    };
    let row = state
        .db
        .find_active_session(&session_id, &token_hash, now_ms_i64())
        .await
        .map_err(|e| {
            warn!(error = %e, "find_active_session failed (link callback)");
        })?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user = state.db.find_user_by_id(&row.user_id).await.map_err(|e| {
        warn!(error = %e, "find_user_by_id failed (link callback)");
    })?;
    Ok(user.filter(|u| u.disabled_at_ms.is_none()).map(|u| u.id))
}

#[derive(Serialize)]
struct AdvertisedProvider {
    id: &'static str,
    display_name: &'static str,
}

#[utoipa::path(
    get,
    path = "/v1/auth/providers",
    tag = "oidc",
    responses((status = 200, description = "Configured OIDC providers advertised to the login UI")),
)]
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

#[derive(Serialize)]
struct ListedIdentity {
    provider: String,
    subject: String,
    email: Option<String>,
    linked_at_ms: i64,
}

#[utoipa::path(
    get,
    path = "/v1/auth/oidc/identities",
    tag = "oidc",
    responses(
        (status = 200, description = "OIDC identities linked to the current user"),
        (status = 401, description = "Not authenticated"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_identities(
    State(state): State<Arc<AppState>>,
    principal: Principal,
) -> Response {
    let Principal::User(user) = principal else {
        return super::unauthorized("authentication required");
    };
    let rows = match state.db.list_oauth_identities_for_user(&user.id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "list_oauth_identities_for_user failed");
            return super::internal_error();
        }
    };
    let identities: Vec<ListedIdentity> = rows
        .into_iter()
        .map(|r| ListedIdentity {
            provider: r.provider,
            subject: r.subject,
            email: r.email,
            linked_at_ms: r.linked_at_ms,
        })
        .collect();
    json_with_status(
        StatusCode::OK,
        serde_json::json!({ "identities": identities }),
    )
}

#[utoipa::path(
    post,
    path = "/v1/auth/oidc/{provider}/unlink",
    tag = "oidc",
    params(("provider" = String, Path, description = "OIDC provider id")),
    responses(
        (status = 200, description = "Identity unlinked"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Refused — would remove the last sign-in method"),
        (status = 404, description = "No such identity linked"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn unlink(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    principal: Principal,
) -> Response {
    use crate::hub::db::user_oauth_identities::UnlinkOutcome;
    let Principal::User(user) = principal else {
        return super::unauthorized("authentication required");
    };

    let removed = match state.db.unlink_oauth_identity(&user.id, &provider).await {
        Ok(UnlinkOutcome::Deleted(r)) => r,
        Ok(UnlinkOutcome::NotFound) => {
            return super::error_response(
                StatusCode::NOT_FOUND,
                "identity_not_found",
                "no such identity is linked to this account",
            );
        }
        Ok(UnlinkOutcome::WouldLockOut) => {
            return super::error_response(
                StatusCode::FORBIDDEN,
                "would_lock_out",
                "set a password or link another provider before unlinking your last sign-in method",
            );
        }
        Err(e) => {
            warn!(error = %e, "unlink_oauth_identity failed");
            return super::internal_error();
        }
    };

    let now_ms_i = now_ms_i64();
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &random_code(16),
            actor_user_id: Some(&user.id),
            actor_kind: "user",
            action: "user.oidc.unlink",
            target_kind: "user",
            target_id: Some(&user.id),
            metadata: Some(serde_json::json!({
                "provider": provider,
                "subject": removed.subject,
                "previous_email": removed.email,
            })),
            now_ms: now_ms_i,
        })
        .await
    {
        warn!(error = %e, "insert_admin_action oidc unlink failed");
    }

    json_ok(serde_json::json!({ "ok": true }))
}

async fn signup_via_oidc(
    state: &Arc<AppState>,
    provider: &str,
    subject: &str,
    email: &str,
    email_verified: Option<bool>,
    code: &str,
) -> Result<String, &'static str> {
    let now_ms_i = now_ms_i64();

    let claimed = match state.db.claim_signup_invite(code, now_ms_i).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err("invite_invalid"),
        Err(e) => {
            warn!(error = %e, "claim_signup_invite failed (oidc)");
            return Err("internal_error");
        }
    };

    let normalized_email = crate::hub::db::users::normalize_email(email);
    if let Some(expected) = claimed.recipient_email.as_deref()
        && normalized_email != expected
    {
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
            warn!(error = %rel_err, "release_signup_invite after oidc recipient mismatch");
        }
        return Err("invite_recipient_mismatch");
    }

    let user_id = random_code(16);

    // Empty password_hash = OIDC-only sentinel — auth.rs login routes
    // these through the timing-constant verify path.
    if let Err(e) = state
        .db
        .insert_user(NewUser {
            id: &user_id,
            email,
            password_hash: "",
            role: &claimed.role,
            email_verified_at_ms: Some(now_ms_i),
            now_ms: now_ms_i,
        })
        .await
    {
        let dup = crate::hub::db::is_unique_violation(&e);
        if !dup {
            warn!(error = %e, "insert_user (oidc) failed");
        }
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
            warn!(error = %rel_err, "release_signup_invite after oidc insert_user failure");
        }
        return Err(if dup { "email_taken" } else { "internal_error" });
    }

    // Rollback arms must release the invite too — orphaned-claim
    // blocks the legitimate recipient from retrying.
    if let Err(e) = state
        .db
        .finalize_signup_invite(&claimed.code, &user_id)
        .await
    {
        warn!(error = %e, "finalize_signup_invite failed (oidc)");
        if let Err(del_err) = state.db.delete_user(&user_id).await {
            warn!(error = %del_err, "delete_user rollback (oidc)");
        }
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
            warn!(error = %rel_err, "release_signup_invite after oidc finalize failure");
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
        if let Err(rel_err) = state.db.release_signup_invite(&claimed.code).await {
            warn!(error = %rel_err, "release_signup_invite after oidc identity insert failure");
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
                "subject": subject,
                "email_claim": email,
                "email_verified": email_verified,
                "role": claimed.role,
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

    let secure = state.use_secure_cookies;
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

fn error_redirect_with_hint(provider: &str, reason: &'static str, hint: &'static str) -> Response {
    let target = format!("/login?oidc_error={reason}&provider={provider}&hint={hint}");
    redirect_to(&target)
}

/// Link-flow errors land on `/settings` — the user is already
/// authenticated, `/login` would be confusing.
fn error_redirect_link(provider: &str, reason: &'static str) -> Response {
    let target = format!("/settings?oidc_error={reason}&provider={provider}");
    redirect_to(&target)
}

/// Strip controls + Unicode line/paragraph separators + Bidi overrides
/// (Trojan-Source class), then truncate. For any attacker-controlled
/// string we pass through `warn!`.
fn sanitize_log_field(raw: &str, max_len: usize) -> String {
    raw.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{2028}'
                        | '\u{2029}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
        .take(max_len)
        .collect()
}

/// Browsers normalise `/\evil.com` to `//evil.com`, so reject
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
    use super::{sanitize_log_field, sanitize_next};

    #[test]
    fn log_field_strips_ascii_controls() {
        let polluted = "access_denied\nfake_event=evil\r\t\x1b[31m";
        assert_eq!(
            sanitize_log_field(polluted, 128),
            "access_deniedfake_event=evil[31m"
        );
    }

    #[test]
    fn log_field_strips_unicode_line_separators() {
        let polluted = "ok\u{2028}injected\u{2029}line";
        assert_eq!(sanitize_log_field(polluted, 128), "okinjectedline");
    }

    #[test]
    fn log_field_strips_bidi_overrides() {
        let polluted = "front\u{202E}reversed\u{202C}back";
        assert_eq!(sanitize_log_field(polluted, 128), "frontreversedback");
    }

    #[test]
    fn log_field_truncates_to_max_len() {
        let long = "x".repeat(200);
        assert_eq!(sanitize_log_field(&long, 32).len(), 32);
    }

    #[test]
    fn log_field_keeps_plain_text() {
        assert_eq!(
            sanitize_log_field("interaction_required", 128),
            "interaction_required",
        );
    }

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
