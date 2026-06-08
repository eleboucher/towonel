//! Shared scaffolding for `hub` integration tests.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;
use towonel_common::identity::TenantKeypair;
use towonel_common::invite::InviteToken;
use towonel_common::kek::HubKek;
use towonel_common::ownership::OwnershipPolicy;

use super::api::{
    AppState, health_router, new_login_limiter, new_nonce_cache, new_refresh_limiter,
    router_unlimited,
};
use super::db::temp_db;
use super::mail::Mailer;
use super::signing::get_or_create_active_signing_key;

/// Recording mailer used by API tests; captures every send so tests can
/// inspect the recipient, kind, and one-shot token.
#[derive(Debug, Default)]
pub(super) struct TestMailer {
    pub sent: tokio::sync::Mutex<Vec<TestMail>>,
}

#[derive(Debug, Clone)]
pub(super) struct TestMail {
    pub kind: TestMailKind,
    pub to: String,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TestMailKind {
    Verification,
    PasswordReset,
    SignupInvite,
}

#[async_trait::async_trait]
impl Mailer for TestMailer {
    async fn send_verification(&self, to: &str, token: &str) -> anyhow::Result<()> {
        self.sent.lock().await.push(TestMail {
            kind: TestMailKind::Verification,
            to: to.to_string(),
            token: token.to_string(),
        });
        Ok(())
    }
    async fn send_password_reset(&self, to: &str, token: &str) -> anyhow::Result<()> {
        self.sent.lock().await.push(TestMail {
            kind: TestMailKind::PasswordReset,
            to: to.to_string(),
            token: token.to_string(),
        });
        Ok(())
    }
    async fn send_signup_invite(&self, to: &str, code: &str) -> anyhow::Result<()> {
        self.sent.lock().await.push(TestMail {
            kind: TestMailKind::SignupInvite,
            to: to.to_string(),
            token: code.to_string(),
        });
        Ok(())
    }
}

pub(super) const OPERATOR_KEY: &str = "test-operator-api-key";

/// Deterministic iroh `EndpointId` derived from a fixed seed. Used across
/// hub tests that need a syntactically valid `node_id` / `edge_node_id`.
fn fake_endpoint_id() -> iroh::EndpointId {
    iroh::SecretKey::from([1u8; 32]).public()
}

pub(super) struct TestHub {
    pub base_url: String,
    pub state: Arc<AppState>,
    pub mailer: Arc<TestMailer>,
    _task: tokio::task::JoinHandle<()>,
}

impl TestHub {
    pub(super) async fn start() -> Self {
        Self::start_with(false).await
    }

    pub(super) async fn start_with(ports_require_reservation: bool) -> Self {
        Self::start_full(
            ports_require_reservation,
            vec!["127.0.0.1".to_string()],
            Vec::new(),
        )
        .await
    }

    /// Start a hub with a non-empty default failover-region set so bootstrap
    /// hands agents edges outside their invite's primary region.
    pub(super) async fn start_with_default_failover(regions: Vec<String>) -> Self {
        Self::start_full(false, vec!["127.0.0.1".to_string()], regions).await
    }

    /// Start a hub whose edge advertises no public IPs, for exercising the
    /// "nothing to assign" path in port reservation.
    pub(super) async fn start_without_edge_ips() -> Self {
        Self::start_full(false, Vec::new(), Vec::new()).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear AppState construction for tests; mirrors the production builder"
    )]
    async fn start_full(
        ports_require_reservation: bool,
        edge_public_ips: Vec<String>,
        default_failover_regions: Vec<String>,
    ) -> Self {
        // Init once so test failures show the hub's `warn!`/`error!` lines.
        // Safe to call repeatedly; only the first wins.
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            drop(
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "warn".into()),
                    )
                    .with_test_writer()
                    .try_init(),
            );
        });
        let db = temp_db().await;
        let (route_tx, _route_rx) = broadcast::channel(16);
        let policy = arc_swap::ArcSwap::from_pointee(OwnershipPolicy::new());

        let kek = Arc::new(HubKek::generate());
        let signer = Arc::new(
            get_or_create_active_signing_key(&db, &kek)
                .await
                .expect("generate test signing key"),
        );

        let mailer = Arc::new(TestMailer::default());
        let state = Arc::new(AppState {
            db: db.clone(),
            is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            route_tx,
            policy,
            identity: super::HubIdentity {
                node_id: fake_endpoint_id(),
                edge_addresses: vec!["127.0.0.1:4443".to_string()],
                edge_iroh_addresses: vec!["127.0.0.1:51820".to_string()],
                edge_public_ips,
                edge_node_id: Some(fake_endpoint_id()),
                edge_region: Some(towonel_common::DEFAULT_REGION.to_string()),
                relay_url: None,
                software_version: "0.0.0-test",
            },
            operator_api_key: zeroize::Zeroizing::new(OPERATOR_KEY.to_string()),
            use_secure_cookies: true,
            public_url: "https://hub.test.example".to_string(),
            invite_lock: tokio::sync::Mutex::new(()),
            metrics: super::metrics::HubMetrics::new(),
            invite_hash_key: std::sync::Arc::new(towonel_common::invite::InviteHashKey::generate()),
            signed_request_nonces: new_nonce_cache(),
            tcp_port_lock: tokio::sync::Mutex::new(()),
            udp_port_lock: tokio::sync::Mutex::new(()),
            signer,
            kek: Arc::clone(&kek),
            refresh_limiter: new_refresh_limiter(),
            login_limiter: new_login_limiter(),
            ip_login_limiter: new_login_limiter(),
            login_sentinel_hash: super::api::compute_login_sentinel_hash()
                .await
                .expect("compute sentinel hash for tests"),
            twofa_attempt_limiter: super::api::new_twofa_attempt_limiter(),
            port_index: arc_swap::ArcSwap::from_pointee(super::api::PortIndex::default()),
            live_edges: Arc::new(super::live_edges::LiveEdges::new()),
            live_agents: Arc::new(super::live_agents::LiveAgents::new()),
            route_rebuild_notify: Arc::new(tokio::sync::Notify::new()),
            web_enabled: true,
            mailer: Some(Arc::clone(&mailer) as super::mail::SharedMailer),
            ports_require_reservation,
            oidc: super::api::OidcRuntimes::default(),
            webauthn: {
                let origin =
                    url::Url::parse("https://hub.test.example").expect("test WebAuthn origin");
                Arc::new(
                    webauthn_rs::WebauthnBuilder::new("hub.test.example", &origin)
                        .expect("test WebauthnBuilder")
                        .build()
                        .expect("test Webauthn"),
                )
            },
            passkey_reg_states: super::api::new_passkey_reg_states(),
            passkey_auth_states: super::api::new_passkey_auth_states(),
            tls: None,
            default_failover_regions,
        });

        let app = router_unlimited(state.clone()).merge(health_router(state.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        let base_url = format!("http://{addr}");

        // ConnectInfo<SocketAddr> is required by handlers that key on the
        // peer IP (login lockout, etc). Production uses this same call shape.
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("server task");
        });

        Self {
            base_url,
            state,
            mailer,
            _task: task,
        }
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

async fn send_json(
    req: reqwest::RequestBuilder,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let req = if let Some(k) = bearer {
        req.bearer_auth(k)
    } else {
        req
    };
    let resp = req.send().await.expect("send request");
    let status = resp.status();
    let bytes = resp.bytes().await.expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "decode json (status={status}, body={:?}): {e}",
            std::str::from_utf8(&bytes).unwrap_or("<non-utf8>")
        )
    });
    (status, json)
}

pub(super) async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    send_json(client.post(url).json(&body), bearer).await
}

pub(super) async fn get_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    send_json(client.get(url), bearer).await
}

pub(super) async fn delete_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    send_json(client.delete(url), bearer).await
}

pub(super) async fn create_invite(
    hub: &TestHub,
    client: &reqwest::Client,
    name: &str,
    hostnames: &[&str],
) -> InviteToken {
    let (status, body) = post_json(
        client,
        &hub.url("/v1/invites"),
        json!({
            "name": name,
            "hostnames": hostnames,
            "expires_in_secs": 3600,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200, "create_invite failed: {body}");
    InviteToken::decode(body["token"].as_str().expect("token field")).expect("decode token")
}

/// Derive the deterministic tenant keypair baked into a v2 invite token.
/// Pods do this at boot; tests use the same helper to verify the hub has
/// pre-registered that tenant at invite-creation time.
pub(super) fn tenant_from_token(token: &InviteToken) -> TenantKeypair {
    TenantKeypair::from_seed(token.tenant_seed)
}
