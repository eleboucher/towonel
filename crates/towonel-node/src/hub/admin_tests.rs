#![allow(clippy::expect_used, clippy::unwrap_used, clippy::large_futures)]

use serde_json::json;
use towonel_common::CBOR_CONTENT_TYPE;
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::{AgentKeypair, TenantKeypair};

use super::test_helpers::{
    OPERATOR_KEY, TestHub, create_invite, delete_json, get_json, post_json, redeem_body,
};

async fn seed_tenant_with_entry(hub: &TestHub, client: &reqwest::Client) -> TenantKeypair {
    let token = create_invite(hub, client, "alice", &["app.alice.test"]).await;
    let tenant = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let (status, _) = post_json(
        client,
        &hub.url("/v1/invites/redeem"),
        redeem_body(&token, &tenant, &agent),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertHostname {
            hostname: "app.alice.test".into(),
        },
    };
    let entry = SignedConfigEntry::sign(&payload, &tenant).expect("sign");
    let mut buf = Vec::new();
    ciborium::into_writer(&entry, &mut buf).expect("cbor");
    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(buf)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    tenant
}

#[tokio::test]
async fn snapshot_requires_operator_auth() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, _) = get_json(&client, &hub.url("/v1/admin/federation/snapshot"), None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn snapshot_returns_tenants_and_entries() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = seed_tenant_with_entry(&hub, &client).await;

    let (status, body) = get_json(
        &client,
        &hub.url("/v1/admin/federation/snapshot"),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    let tenants = body["tenants"].as_array().expect("tenants");
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0]["tenant_id"], tenant.id().to_string());
    assert_eq!(tenants[0]["hostnames"][0], "app.alice.test");
    let entries = body["entries_cbor_b64"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert!(body["removals"].as_array().expect("removals").is_empty());
}

#[tokio::test]
async fn snapshot_includes_removed_tenant_in_removals() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = seed_tenant_with_entry(&hub, &client).await;

    let (status, _) = delete_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = get_json(
        &client,
        &hub.url("/v1/admin/federation/snapshot"),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    let removals = body["removals"].as_array().expect("removals");
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0]["tenant_id"], tenant.id().to_string());
}

#[tokio::test]
async fn resync_requires_operator_auth() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, _) = post_json(
        &client,
        &hub.url("/v1/admin/resync"),
        json!({
            "peer_url": "http://127.0.0.1:0",
            "peer_operator_key": "irrelevant",
        }),
        None,
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn resync_pulls_tenant_and_entry_from_peer() {
    let source = TestHub::start().await;
    let target = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = seed_tenant_with_entry(&source, &client).await;

    let (status, body) = post_json(
        &client,
        &target.url("/v1/admin/resync"),
        json!({
            "peer_url": source.base_url,
            "peer_operator_key": OPERATOR_KEY,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200, "resync failed: {body}");
    assert_eq!(body["tenants_ingested"], 1);
    assert_eq!(body["entries_ingested"], 1);
    assert_eq!(body["removals_ingested"], 0);

    let fed = target
        .state
        .db
        .list_federated_tenants()
        .await
        .expect("list");
    assert_eq!(fed.len(), 1);
    assert_eq!(fed[0].tenant_id, tenant.id());
    let entries = target.state.db.get_all_entries().await.expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tenant_id, tenant.id());
    let is_known = {
        let policy = target.state.policy.read().await;
        policy.is_known_tenant(&tenant.id())
    };
    assert!(is_known);
}

#[tokio::test]
async fn resync_is_idempotent() {
    let source = TestHub::start().await;
    let target = TestHub::start().await;
    let client = reqwest::Client::new();
    seed_tenant_with_entry(&source, &client).await;

    let body = json!({
        "peer_url": source.base_url,
        "peer_operator_key": OPERATOR_KEY,
    });

    let (status, _) = post_json(
        &client,
        &target.url("/v1/admin/resync"),
        body.clone(),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    let (status, second) = post_json(
        &client,
        &target.url("/v1/admin/resync"),
        body,
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(second["tenants_ingested"], 1);
    assert_eq!(second["entries_ingested"], 0, "entry was already present");
    assert_eq!(second["entries_skipped"], 1);

    let entries = target.state.db.get_all_entries().await.expect("entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn resync_propagates_removal() {
    let source = TestHub::start().await;
    let target = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = seed_tenant_with_entry(&source, &client).await;

    let (status, _) = delete_json(
        &client,
        &source.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = post_json(
        &client,
        &target.url("/v1/admin/resync"),
        json!({
            "peer_url": source.base_url,
            "peer_operator_key": OPERATOR_KEY,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200, "resync failed: {body}");
    assert_eq!(body["removals_ingested"], 1);

    let is_known = {
        let policy = target.state.policy.read().await;
        policy.is_known_tenant(&tenant.id())
    };
    assert!(!is_known, "removed tenant must not be active on target");
    let removals = target.state.db.list_tenant_removals().await.expect("list");
    assert!(removals.contains(&tenant.id()));
}
