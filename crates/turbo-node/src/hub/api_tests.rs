use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tokio::sync::{RwLock, broadcast};
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::{AgentKeypair, TenantKeypair};
use turbo_common::invite::{INVITE_ID_LEN, InviteToken, hash_invite_secret};
use turbo_common::ownership::OwnershipPolicy;

use super::api::{AppState, router_unlimited};
use super::db::{PendingInvite, temp_db};

const OPERATOR_KEY: &str = "test-operator-api-key";
/// Fake 64-hex node id for places that only need a string (no iroh endpoint
/// is spun up for these tests).
const FAKE_NODE_ID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// A running hub bound to an ephemeral port, plus the pieces the tests need
/// to poke at its internal state.
struct TestHub {
    base_url: String,
    state: Arc<AppState>,
    _task: tokio::task::JoinHandle<()>,
}

impl TestHub {
    async fn start() -> Self {
        let db = temp_db().await;
        let (route_tx, _route_rx) = broadcast::channel(16);
        let policy = Arc::new(RwLock::new(OwnershipPolicy::new()));

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
            federation: super::api::FederationState {
                trusted_peers: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
                nonces: super::federation::new_nonce_cache(),
            },
            dns_webhook_url: None,
            prev_hostnames: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        });

        let app = router_unlimited(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            base_url,
            state,
            _task: task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Shortcut: POST JSON to a path, returning (status, body as JSON).
async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let mut req = client.post(url).json(&body);
    if let Some(k) = bearer {
        req = req.bearer_auth(k);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let json = resp.json::<Value>().await.unwrap();
    (status, json)
}

async fn get_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let mut req = client.get(url);
    if let Some(k) = bearer {
        req = req.bearer_auth(k);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let json = resp.json::<Value>().await.unwrap();
    (status, json)
}

async fn delete_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let mut req = client.delete(url);
    if let Some(k) = bearer {
        req = req.bearer_auth(k);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let json = resp.json::<Value>().await.unwrap();
    (status, json)
}

// POST /v1/invites (create)

#[tokio::test]
async fn create_invite_happy_path() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({
            "name": "alice",
            "hostnames": ["app.alice.test", "*.alice.test"],
            "expires_in_secs": 3600,
        }),
        Some(OPERATOR_KEY),
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    let token = body["token"].as_str().unwrap();
    assert!(token.starts_with("tt_inv_1_"));
    // Decoding the emitted token must succeed and embed the hub's public URL.
    let parsed = InviteToken::decode(token).unwrap();
    assert_eq!(parsed.hub_url, "https://hub.test.example");

    // Round-trip: the invite_id in the response must match the token's id.
    assert_eq!(body["invite_id"], parsed.invite_id_b64());
}

#[tokio::test]
async fn create_invite_missing_auth_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "alice", "hostnames": ["h.test"], "expires_in_secs": 3600}),
        None,
    )
    .await;

    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn create_invite_wrong_auth_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "alice", "hostnames": ["h.test"], "expires_in_secs": 3600}),
        Some("definitely-not-the-key"),
    )
    .await;

    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn create_invite_empty_hostnames_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "alice", "hostnames": [], "expires_in_secs": 3600}),
        Some(OPERATOR_KEY),
    )
    .await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn create_invite_expiry_out_of_range_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // 0 seconds.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "a", "hostnames": ["h.test"], "expires_in_secs": 0}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");

    // > 30 days.
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "a", "hostnames": ["h.test"], "expires_in_secs": 31 * 24 * 3600}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn create_invite_hostname_conflict_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Pre-seed the policy with a tenant that already owns the hostname.
    let existing = TenantKeypair::generate();
    hub.state.policy.write().await.register_tenant(
        &existing.id(),
        existing.public_key().clone(),
        ["shared.test".to_string()],
    );

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "alice", "hostnames": ["shared.test"], "expires_in_secs": 3600}),
        Some(OPERATOR_KEY),
    )
    .await;

    assert_eq!(status, 409);
    assert_eq!(body["error"]["code"], "hostname_conflict");
}

/// Two sequential (not concurrent, but equivalent under the invite_lock)
/// `POST /v1/invites` with overlapping hostnames: the first creates a
/// pending invite, the second must be rejected with `hostname_conflict`
/// even though no tenant has redeemed yet, so the policy itself is empty.
///
/// Before the pending-invite check was added, this case slipped through:
/// the policy was the only gate and didn't know about pending invites.
#[tokio::test]
async fn create_invite_rejects_overlap_with_pending_invite() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({
            "name": "alice",
            "hostnames": ["shared.test", "alice.test"],
            "expires_in_secs": 3600,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    // Second invite overlaps on `shared.test` with the still-pending first.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({
            "name": "bob",
            "hostnames": ["shared.test", "bob.test"],
            "expires_in_secs": 3600,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["error"]["code"], "hostname_conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pending invite"),
        "message should mention the pending invite, got: {}",
        body["error"]["message"]
    );
}

/// Revoking the first invite must free its hostnames for a new invite.
#[tokio::test]
async fn create_invite_reuses_hostname_after_revoke() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (_, first) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "alice", "hostnames": ["reusable.test"], "expires_in_secs": 3600}),
        Some(OPERATOR_KEY),
    )
    .await;

    let (status, _) = delete_json(
        &client,
        &hub.url(&format!(
            "/v1/invites/{}",
            first["invite_id"].as_str().unwrap()
        )),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    // Same hostname, new invite -- must succeed now that the first is revoked.
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "bob", "hostnames": ["reusable.test"], "expires_in_secs": 3600}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
}

// GET /v1/invites (list)

#[tokio::test]
async fn list_invites_returns_all() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    for (i, name) in ["alice", "bob"].iter().enumerate() {
        let (status, _) = post_json(
            &client,
            &hub.url("/v1/invites"),
            json!({
                "name": name,
                "hostnames": [format!("app{}.test", i)],
                "expires_in_secs": 3600,
            }),
            Some(OPERATOR_KEY),
        )
        .await;
        assert_eq!(status, 200);
    }

    let (status, body) = get_json(&client, &hub.url("/v1/invites"), Some(OPERATOR_KEY)).await;
    assert_eq!(status, 200);
    let invites = body["invites"].as_array().unwrap();
    assert_eq!(invites.len(), 2);
    for inv in invites {
        assert_eq!(inv["status"], "pending");
    }
}

#[tokio::test]
async fn list_invites_requires_operator_auth() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, _) = get_json(&client, &hub.url("/v1/invites"), None).await;
    assert_eq!(status, 401);
}

// DELETE /v1/invites/{id} (revoke)

#[tokio::test]
async fn revoke_invite_happy_path() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (_, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "a", "hostnames": ["h.test"], "expires_in_secs": 3600}),
        Some(OPERATOR_KEY),
    )
    .await;
    let invite_id = body["invite_id"].as_str().unwrap();

    let (status, body) = delete_json(
        &client,
        &hub.url(&format!("/v1/invites/{invite_id}")),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn revoke_invite_missing_returns_404() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let fake_id = B64.encode([0xaa; INVITE_ID_LEN]);
    let (status, body) = delete_json(
        &client,
        &hub.url(&format!("/v1/invites/{fake_id}")),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn revoke_invite_bad_id_returns_400() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = delete_json(
        &client,
        &hub.url("/v1/invites/not-base64"),
        Some(OPERATOR_KEY),
    )
    .await;
    // "not-base64" _is_ valid base64url for some bytes, but the decoded
    // length is not INVITE_ID_LEN, so parse_invite_id rejects with 400.
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");
}

// POST /v1/invites/redeem

/// Create a pending invite via the API, returning the parsed token + invite_id.
async fn create_invite(
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
    InviteToken::decode(body["token"].as_str().unwrap()).unwrap()
}

fn redeem_body(token: &InviteToken, tenant: &TenantKeypair, agent: &AgentKeypair) -> Value {
    json!({
        "invite_id": B64.encode(token.invite_id),
        "invite_secret": B64.encode(token.invite_secret),
        "tenant_pq_public_key": tenant.public_key().to_string(),
        "agent_node_id": agent.id().to_string(),
    })
}

#[tokio::test]
async fn redeem_invite_happy_path() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;

    assert_eq!(status, 200, "redeem failed: {body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["tenant_id"], tenant.id().to_string());
    assert_eq!(body["hostnames"][0], "app.alice.test");
    assert_eq!(body["hub_node_id"], FAKE_NODE_ID);
    assert_eq!(body["edge_node_id"], FAKE_NODE_ID);

    // Side effect: the tenant is now in the in-memory policy with the
    // invite's hostnames, so subsequent entry submissions will pass.
    let policy = hub.state.policy.read().await;
    assert!(policy.is_known_tenant(&tenant.id()));
    assert!(policy.is_hostname_allowed(&tenant.id(), "app.alice.test"));
}

#[tokio::test]
async fn redeem_invite_bad_secret_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    let mut body = redeem_body(&token, &tenant, &agent);
    body["invite_secret"] = json!(B64.encode([0xdd; 32])); // wrong secret

    let (status, resp) = post_json(&client, &hub.url("/v1/invites/redeem"), body, None).await;
    assert_eq!(status, 401);
    assert_eq!(resp["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn redeem_invite_expired_returns_410() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Skip the API and inject an already-expired invite directly into the
    // DB so we don't have to sleep.
    let invite_id = [0x77; INVITE_ID_LEN];
    let secret = [0x88u8; 32];
    let hostnames = vec!["expired.test".to_string()];
    hub.state
        .db
        .insert_invite(&PendingInvite {
            invite_id,
            name: "ghost",
            hostnames: &hostnames,
            secret_hash: hash_invite_secret(&secret),
            expires_at_ms: 1, // unix epoch + 1ms, definitely in the past
            created_at_ms: 0,
        })
        .await
        .unwrap();

    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        json!({
            "invite_id": B64.encode(invite_id),
            "invite_secret": B64.encode(secret),
            "tenant_pq_public_key": tenant.public_key().to_string(),
            "agent_node_id": agent.id().to_string(),
        }),
        None,
    )
    .await;
    assert_eq!(status, 410);
    assert_eq!(body["error"]["code"], "invite_expired");
}

#[tokio::test]
async fn redeem_invite_is_idempotent_with_valid_secret() {
    // Redeeming an already-redeemed invite is allowed when the caller presents
    // the correct invite secret: the old tenant binding is replaced by the new
    // one. This matches Cloudflare Tunnel's idempotency and lets an agent
    // recover after its key-bearing PVC is lost.
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let t1 = TenantKeypair::generate();
    let t2 = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &t1, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &t2, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["tenant_id"], t2.id().to_string());
}

#[tokio::test]
async fn redeem_invite_revoked_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    // Revoke via API.
    let (status, _) = delete_json(
        &client,
        &hub.url(&format!("/v1/invites/{}", B64.encode(token.invite_id))),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["error"]["code"], "invite_revoked");
}

#[tokio::test]
async fn redeem_invite_missing_returns_404() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        json!({
            "invite_id": B64.encode([0; INVITE_ID_LEN]),
            "invite_secret": B64.encode([0u8; 32]),
            "tenant_pq_public_key": tenant.public_key().to_string(),
            "agent_node_id": agent.id().to_string(),
        }),
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], "not_found");
}

// End-to-end: redeem -> submit signed entry

/// The marquee phase-2 test: after a fresh tenant redeems an invite, the
/// hub accepts the signed entries they submit. This proves that the in-memory
/// policy mutation done by the redeem handler is actually picked up by the
/// `/v1/entries` validator -- regressing this would break onboarding.
#[tokio::test]
async fn redeemed_tenant_can_submit_signed_entries() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Submit UpsertHostname for the pre-approved hostname.
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertHostname {
            hostname: "app.alice.test".into(),
        },
    };
    let entry = SignedConfigEntry::sign(&payload, &tenant).unwrap();
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body).unwrap();

    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "entry submission failed");
}

// DELETE /v1/tenants/{id} (operator tenant remove)

#[tokio::test]
async fn delete_tenant_drops_from_policy_and_records_removal() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Register a tenant via the invite flow so they're in the policy.
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(hub.state.policy.read().await.is_known_tenant(&tenant.id()));

    // Remove.
    let (status, body) = delete_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "removed");

    // In-memory policy evicted.
    assert!(!hub.state.policy.read().await.is_known_tenant(&tenant.id()));

    // Persistent removal recorded (so a hub restart stays consistent).
    let removals = hub.state.db.list_tenant_removals().await.unwrap();
    assert!(removals.contains(&tenant.id()));
}

#[tokio::test]
async fn delete_tenant_blocks_future_entry_submissions() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Operator removes the tenant.
    let (status, _) = delete_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    // The tenant's signed entries are now rejected at the `tenant_not_allowed`
    // gate -- no need to wait for hub restart.
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertHostname {
            hostname: "app.alice.test".into(),
        },
    };
    let entry = SignedConfigEntry::sign(&payload, &tenant).unwrap();
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body).unwrap();

    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let json = resp.json::<Value>().await.unwrap();
    assert_eq!(json["error"]["code"], "tenant_not_allowed");
}

#[tokio::test]
async fn delete_tenant_requires_operator_auth() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let tenant = TenantKeypair::generate();
    let url = hub.url(&format!("/v1/tenants/{}", tenant.id()));

    let (status, body) = delete_json(&client, &url, None).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");

    let (status, _) = delete_json(&client, &url, Some("wrong-key")).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn delete_tenant_bad_id_returns_400() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) =
        delete_json(&client, &hub.url("/v1/tenants/not-hex"), Some(OPERATOR_KEY)).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");
}

/// Removing a tenant that was never registered is still a 200 — the
/// endpoint is idempotent and the operator may legitimately want to
/// pre-emptively blacklist a key.
#[tokio::test]
async fn delete_tenant_unregistered_succeeds() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let tenant = TenantKeypair::generate();
    let (status, body) = delete_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "removed");
}

#[tokio::test]
async fn redeemed_tenant_cannot_claim_unapproved_hostname() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Invite only pre-approves `app.alice.test`.
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Try to claim a hostname the operator did NOT pre-approve.
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertHostname {
            hostname: "evil.example.com".into(),
        },
    };
    let entry = SignedConfigEntry::sign(&payload, &tenant).unwrap();
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body).unwrap();

    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let json = resp.json::<Value>().await.unwrap();
    assert_eq!(json["error"]["code"], "hostname_not_owned");
}
