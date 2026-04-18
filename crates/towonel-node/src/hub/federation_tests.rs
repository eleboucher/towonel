#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use reqwest::StatusCode;
use serde_json::Value;
use towonel_common::CBOR_CONTENT_TYPE;
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::TenantKeypair;
use towonel_common::time::now_ms;

use super::federation::{RemovalPush, TenantPush, push_round};
use super::test_helpers::{FAKE_NODE_ID, OutboundConfig, TestHub, create_invite};

const FEDERATION_AUTH_DOMAIN: &str = "towonel/federation/v1";

fn peer_secret(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from([seed; 32])
}

fn node_id_bytes(sk: &iroh::SecretKey) -> [u8; 32] {
    *sk.public().as_bytes()
}

fn signed_auth_header_at(sk: &iroh::SecretKey, ts_ms: u64) -> String {
    // Federation handlers consume the request body before auth runs, so the
    // production signer hashes an empty slice. Tests must match.
    let body_hex = crate::hub::auth::body_hash_hex(&[]);
    let node_id = sk.public();
    let message = format!("{FEDERATION_AUTH_DOMAIN}/{node_id}/{ts_ms}/{body_hex}");
    let sig = sk.sign(message.as_bytes());
    format!("Signature {node_id}.{ts_ms}.{}", B64.encode(sig.to_bytes()))
}

async fn trust(hub: &TestHub, sk: &iroh::SecretKey) {
    hub.state
        .federation
        .trusted_peers
        .write()
        .await
        .insert(node_id_bytes(sk));
}

async fn post_signed_json(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    auth: &str,
) -> (StatusCode, Value) {
    let resp = client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(body)
        .send()
        .await
        .expect("send");
    let status = resp.status();
    let json = resp.json::<Value>().await.expect("decode");
    (status, json)
}

async fn post_signed_cbor(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    auth: &str,
) -> StatusCode {
    client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(body)
        .send()
        .await
        .expect("send")
        .status()
}

fn tenant_push_body(tenant: &TenantKeypair, hostname: &str) -> Value {
    serde_json::to_value(TenantPush {
        tenant_id: tenant.id().to_string(),
        pq_public_key: tenant.public_key().to_string(),
        hostnames: vec![hostname.to_string()],
        registered_at_ms: 0,
    })
    .expect("serialize")
}

fn removal_push_body(tenant: &TenantKeypair) -> Value {
    serde_json::to_value(RemovalPush {
        tenant_id: tenant.id().to_string(),
        removed_at_ms: 0,
    })
    .expect("serialize")
}

fn cbor_entry(tenant: &TenantKeypair, sequence: u64, hostname: &str) -> Vec<u8> {
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertHostname {
            hostname: hostname.to_string(),
        },
    };
    let entry = SignedConfigEntry::sign(&payload, tenant).expect("sign");
    let mut buf = Vec::new();
    ciborium::into_writer(&entry, &mut buf).expect("cbor");
    buf
}

#[tokio::test]
async fn health_exposes_node_id_for_peer_bootstrap() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let resp: Value = client
        .get(hub.url("/v1/health"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("decode");
    assert_eq!(resp["node_id"].as_str().expect("node_id"), FAKE_NODE_ID);
    assert_eq!(resp["status"], "ok");
}

#[tokio::test]
async fn push_tenant_missing_auth_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = TenantKeypair::generate();

    let resp = client
        .post(hub.url("/v1/federation/tenants"))
        .json(&tenant_push_body(&tenant, "a.test"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn push_tenant_malformed_auth_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = TenantKeypair::generate();

    let (status, body) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "a.test"),
        "Bearer not-a-signature",
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn push_tenant_untrusted_peer_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(7);
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms());
    let (status, body) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "a.test"),
        &auth,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn push_tenant_stale_timestamp_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(8);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    // Production allows ±60s skew.
    let stale_ts = now_ms().saturating_sub(10 * 60 * 1000);
    let auth = signed_auth_header_at(&peer, stale_ts);
    let (status, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "a.test"),
        &auth,
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn push_tenant_replay_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(9);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms());

    let (status1, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "a.test"),
        &auth,
    )
    .await;
    assert_eq!(status1, 200);

    let (status2, body2) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "a.test"),
        &auth,
    )
    .await;
    assert_eq!(status2, 401);
    assert_eq!(body2["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn push_tenant_inserts_into_db_and_policy() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(10);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms());
    let (status, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "app.alice.test"),
        &auth,
    )
    .await;
    assert_eq!(status, 200);

    let fed = hub.state.db.list_federated_tenants().await.expect("list");
    assert_eq!(fed.len(), 1);
    assert_eq!(fed[0].tenant_id, tenant.id());
    assert_eq!(fed[0].hostnames, vec!["app.alice.test".to_string()]);

    let (is_known, hostname_allowed) = {
        let policy = hub.state.policy.read().await;
        (
            policy.is_known_tenant(&tenant.id()),
            policy.is_hostname_allowed(&tenant.id(), "app.alice.test"),
        )
    };
    assert!(is_known);
    assert!(hostname_allowed);
}

#[tokio::test]
async fn push_tenant_is_idempotent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(11);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    // Distinct timestamps to bypass replay protection.
    for offset in [0u64, 1000] {
        let auth = signed_auth_header_at(&peer, now_ms().saturating_sub(offset));
        let (status, _) = post_signed_json(
            &client,
            &hub.url("/v1/federation/tenants"),
            &tenant_push_body(&tenant, "app.alice.test"),
            &auth,
        )
        .await;
        assert_eq!(status, 200);
    }

    let fed = hub.state.db.list_federated_tenants().await.expect("list");
    assert_eq!(fed.len(), 1);
}

#[tokio::test]
async fn push_removal_evicts_from_policy_and_persists() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(12);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms().saturating_sub(2000));
    let (s, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "app.alice.test"),
        &auth,
    )
    .await;
    assert_eq!(s, 200);
    assert!(hub.state.policy.read().await.is_known_tenant(&tenant.id()));

    let auth = signed_auth_header_at(&peer, now_ms());
    let (s, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenant-removals"),
        &removal_push_body(&tenant),
        &auth,
    )
    .await;
    assert_eq!(s, 200);

    assert!(!hub.state.policy.read().await.is_known_tenant(&tenant.id()));
    let removals = hub.state.db.list_tenant_removals().await.expect("list");
    assert!(removals.contains(&tenant.id()));
}

#[tokio::test]
async fn push_entry_propagates_signed_entry() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(13);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms().saturating_sub(2000));
    let (s, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "app.alice.test"),
        &auth,
    )
    .await;
    assert_eq!(s, 200);

    let cbor = cbor_entry(&tenant, 1, "app.alice.test");
    let auth = signed_auth_header_at(&peer, now_ms());
    let status = post_signed_cbor(&client, &hub.url("/v1/federation/entries"), cbor, &auth).await;
    assert_eq!(status, 200);

    let entries = hub.state.db.get_all_entries().await.expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tenant_id, tenant.id());
}

#[tokio::test]
async fn push_entry_unknown_tenant_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(14);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let cbor = cbor_entry(&tenant, 1, "orphan.test");
    let auth = signed_auth_header_at(&peer, now_ms());
    let status = post_signed_cbor(&client, &hub.url("/v1/federation/entries"), cbor, &auth).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn push_entry_duplicate_sequence_is_idempotent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer = peer_secret(15);
    trust(&hub, &peer).await;
    let tenant = TenantKeypair::generate();

    let auth = signed_auth_header_at(&peer, now_ms().saturating_sub(3000));
    let (s, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant, "app.alice.test"),
        &auth,
    )
    .await;
    assert_eq!(s, 200);

    let cbor = cbor_entry(&tenant, 1, "app.alice.test");
    for offset in [0u64, 1500] {
        let auth = signed_auth_header_at(&peer, now_ms().saturating_sub(offset));
        let status = post_signed_cbor(
            &client,
            &hub.url("/v1/federation/entries"),
            cbor.clone(),
            &auth,
        )
        .await;
        assert_eq!(status, 200);
    }

    let entries = hub.state.db.get_all_entries().await.expect("entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn create_invite_with_sync_push_propagates_immediately() {
    let hub_b = TestHub::start().await;
    let a_key = peer_secret(22);
    trust(&hub_b, &a_key).await;

    let hub_a = TestHub::start_with(OutboundConfig {
        peer_urls: vec![hub_b.base_url.clone()],
        signing_key: Some(a_key),
        sync_invite_redeem: true,
    })
    .await;

    let client = reqwest::Client::new();
    let token = create_invite(&hub_a, &client, "alice", &["app.alice.test"]).await;
    let expected = towonel_common::identity::TenantKeypair::from_seed(token.tenant_seed).id();

    // v2: the tenant is registered at invite-create time, so sync push fires
    // immediately from inside POST /v1/invites -- no separate redeem call.
    let fed = hub_b.state.db.list_federated_tenants().await.expect("list");
    assert_eq!(fed.len(), 1);
    assert_eq!(fed[0].tenant_id, expected);
    assert_eq!(fed[0].hostnames, vec!["app.alice.test".to_string()]);
}

#[tokio::test]
async fn create_invite_without_sync_flag_does_not_push() {
    let hub_b = TestHub::start().await;
    let a_key = peer_secret(23);
    trust(&hub_b, &a_key).await;

    let hub_a = TestHub::start_with(OutboundConfig {
        peer_urls: vec![hub_b.base_url.clone()],
        signing_key: Some(a_key),
        sync_invite_redeem: false,
    })
    .await;

    let client = reqwest::Client::new();
    let _ = create_invite(&hub_a, &client, "alice", &["app.alice.test"]).await;

    let fed = hub_b.state.db.list_federated_tenants().await.expect("list");
    assert!(fed.is_empty());
}

#[tokio::test]
async fn create_invite_sync_push_survives_unreachable_peer() {
    // Peer URL that will fail to connect (reserved loopback port we never bind).
    let hub_a = TestHub::start_with(OutboundConfig {
        peer_urls: vec!["http://127.0.0.1:1".to_string()],
        signing_key: Some(peer_secret(24)),
        sync_invite_redeem: true,
    })
    .await;

    let client = reqwest::Client::new();
    let token = create_invite(&hub_a, &client, "alice", &["app.alice.test"]).await;
    let tenant_id = towonel_common::identity::TenantKeypair::from_seed(token.tenant_seed).id();
    // Invite creation must succeed locally even though the peer push fails.
    assert!(hub_a.state.policy.read().await.is_known_tenant(&tenant_id));
}

#[tokio::test]
async fn two_hubs_reach_consistency_after_push_round() {
    let hub_a = TestHub::start().await;
    let hub_b = TestHub::start().await;

    let a_key = peer_secret(21);
    trust(&hub_b, &a_key).await;

    let client = reqwest::Client::new();
    let token = create_invite(&hub_a, &client, "alice", &["app.alice.test"]).await;
    let tenant = towonel_common::identity::TenantKeypair::from_seed(token.tenant_seed);

    let cbor = cbor_entry(&tenant, 1, "app.alice.test");
    let resp = client
        .post(hub_a.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(cbor)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let b_node_id = node_id_bytes(&peer_secret(21));
    push_round(
        &client,
        &hub_b.base_url,
        &b_node_id,
        &a_key,
        hub_a.state.as_ref(),
    )
    .await
    .expect("push round");

    let fed = hub_b.state.db.list_federated_tenants().await.expect("list");
    assert_eq!(fed.len(), 1);
    assert_eq!(fed[0].tenant_id, tenant.id());

    let entries = hub_b.state.db.get_all_entries().await.expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tenant_id, tenant.id());
}

#[tokio::test]
async fn conflicting_pubkey_push_is_first_writer_wins() {
    // Two peers push the same `tenant_id` but with different pq_public_key
    // values. The hub's `federated_tenants` PK on tenant_id means the second
    // peer's row is silently dropped (see `insert_federated_tenant`'s
    // `ON CONFLICT DO NOTHING`). This only matters under adversarial peers:
    // under honest peers a `tenant_id` collision would require a SHA-256
    // preimage on a distinct ML-DSA-65 public key, which is computationally
    // infeasible. The test constructs the collision artificially by reusing
    // `tenant.id()` with a second keypair's bytes — verifying the hub keeps
    // the first writer and does not let a hostile peer overwrite state.
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let peer_one = peer_secret(101);
    let peer_two = peer_secret(102);
    trust(&hub, &peer_one).await;
    trust(&hub, &peer_two).await;

    let tenant_one = TenantKeypair::generate();
    let tenant_two = TenantKeypair::generate();

    // Peer 1 pushes the real (tenant_id, pubkey) pair.
    let auth = signed_auth_header_at(&peer_one, now_ms().saturating_sub(2000));
    let (s, _) = post_signed_json(
        &client,
        &hub.url("/v1/federation/tenants"),
        &tenant_push_body(&tenant_one, "app.alice.test"),
        &auth,
    )
    .await;
    assert_eq!(s, 200);

    // Peer 2 pushes the same tenant_id but with a different pubkey. The hub
    // validates tenant_id == sha256(pubkey), so peer 2 has to claim the
    // matching tenant_id for its own key. The interesting attack is when
    // peer 2 tries to push tenant_one.id() alongside tenant_two's pubkey —
    // the hub must reject it with 400.
    let mut body = tenant_push_body(&tenant_two, "app.mallory.test");
    body["tenant_id"] = serde_json::Value::String(tenant_one.id().to_string());
    let auth = signed_auth_header_at(&peer_two, now_ms());
    let (s, body_json) =
        post_signed_json(&client, &hub.url("/v1/federation/tenants"), &body, &auth).await;
    assert_eq!(s, 400, "mismatched tenant_id/pubkey must be rejected");
    assert_eq!(body_json["error"]["code"], "invalid_request");

    // And peer 1's record is still the sole source of truth.
    let fed = hub.state.db.list_federated_tenants().await.expect("list");
    assert_eq!(fed.len(), 1);
    assert_eq!(fed[0].tenant_id, tenant_one.id());
    assert_eq!(fed[0].pq_public_key, *tenant_one.public_key());
}

#[tokio::test]
async fn push_round_persists_state_across_calls() {
    let hub_a = TestHub::start().await;
    let hub_b = TestHub::start().await;
    let a_key = peer_secret(21);
    trust(&hub_b, &a_key).await;

    let client = reqwest::Client::new();
    let token = create_invite(&hub_a, &client, "alice", &["app.alice.test"]).await;
    let tenant = towonel_common::identity::TenantKeypair::from_seed(token.tenant_seed);

    let b_node_id = node_id_bytes(&peer_secret(77));
    push_round(
        &client,
        &hub_b.base_url,
        &b_node_id,
        &a_key,
        hub_a.state.as_ref(),
    )
    .await
    .expect("first push");

    let state = hub_a
        .state
        .db
        .load_federation_push_state(&b_node_id)
        .await
        .expect("load push state");
    assert!(state.tenants.contains(&tenant.id()));

    // Kill hub_b so a second round without persisted state would re-push,
    // but persisted state should skip it entirely (no peer contact needed).
    drop(hub_b);

    push_round(
        &client,
        "http://127.0.0.1:1",
        &b_node_id,
        &a_key,
        hub_a.state.as_ref(),
    )
    .await
    .expect("second push (no-op because state is persisted)");
}
