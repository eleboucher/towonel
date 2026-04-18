//! Shared scaffolding for `hub` integration tests.
#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tokio::sync::{RwLock, broadcast};
use towonel_common::identity::{AgentKeypair, TenantKeypair};
use towonel_common::invite::InviteToken;
use towonel_common::ownership::OwnershipPolicy;

use super::api::{AppState, FederationState, OutboundFederation, router_unlimited};
use super::db::temp_db;

pub(super) const OPERATOR_KEY: &str = "test-operator-api-key";
pub(super) const FAKE_NODE_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

pub(super) struct TestHub {
    pub base_url: String,
    pub state: Arc<AppState>,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
pub(super) struct OutboundConfig {
    pub peer_urls: Vec<String>,
    pub signing_key: Option<iroh::SecretKey>,
    pub sync_invite_redeem: bool,
}

impl TestHub {
    pub(super) async fn start() -> Self {
        Self::start_with(OutboundConfig::default()).await
    }

    pub(super) async fn start_with(outbound: OutboundConfig) -> Self {
        let db = temp_db().await;
        let (route_tx, _route_rx) = broadcast::channel(16);
        let policy = Arc::new(RwLock::new(OwnershipPolicy::new()));

        let OutboundConfig {
            peer_urls,
            signing_key,
            sync_invite_redeem,
        } = outbound;
        let outbound_federation = signing_key.map(|sk| OutboundFederation {
            peer_urls,
            signing_key: sk,
        });

        let state = Arc::new(AppState {
            db,
            route_tx,
            policy,
            http_client: reqwest::Client::new(),
            identity: super::HubIdentity {
                node_id: FAKE_NODE_ID.to_string(),
                edge_addresses: vec!["127.0.0.1:4443".to_string()],
                edge_node_id: Some(FAKE_NODE_ID.to_string()),
                software_version: "0.0.0-test",
            },
            operator_api_key: OPERATOR_KEY.to_string(),
            public_url: "https://hub.test.example".to_string(),
            invite_lock: tokio::sync::Mutex::new(()),
            federation: FederationState {
                trusted_peers: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
                nonces: super::federation::new_nonce_cache(),
                outbound: outbound_federation,
                sync_invite_redeem,
            },
            dns_webhook_url: None,
            prev_hostnames: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            metrics: super::metrics::HubMetrics::new(),
            peer_statuses: super::peer_status::new_peer_status_map(&[]),
        });

        let app = router_unlimited(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        let base_url = format!("http://{addr}");

        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server task");
        });

        Self {
            base_url,
            state,
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
    let json = resp.json::<Value>().await.expect("decode json");
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

pub(super) fn redeem_body(
    token: &InviteToken,
    tenant: &TenantKeypair,
    agent: &AgentKeypair,
) -> Value {
    json!({
        "invite_id": B64.encode(token.invite_id),
        "invite_secret": B64.encode(token.invite_secret),
        "tenant_pq_public_key": tenant.public_key().to_string(),
        "agent_node_id": agent.id().to_string(),
    })
}
