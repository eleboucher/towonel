use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use serde_json::{Value, json};
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::{AgentKeypair, TenantId, TenantKeypair};
use towonel_common::invite::{INVITE_ID_LEN, InviteToken};

use super::test_helpers::{
    OPERATOR_KEY, TestHub, TestMailKind, create_invite, delete_json, get_json, post_json,
    tenant_from_token,
};

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
    assert!(token.starts_with("tt_inv_2_"));
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
async fn create_invite_zero_expiry_means_forever() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "a", "hostnames": ["h.test"], "expires_in_secs": 0}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body["expires_at_ms"].is_null(),
        "0 secs should mean forever"
    );
}

#[tokio::test]
async fn create_invite_omitted_expiry_means_forever() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/invites"),
        json!({"name": "a", "hostnames": ["h.test"]}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["expires_at_ms"].is_null());
}

#[tokio::test]
async fn create_invite_expiry_beyond_cap_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

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
    hub.state.policy_update(|p| {
        p.register_tenant(
            &existing.id(),
            existing.public_key().clone(),
            ["shared.test".to_string()],
        );
    });

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

/// Two sequential (not concurrent, but equivalent under the `invite_lock`)
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

#[tokio::test]
async fn list_invites_scope_for_operator_role_user() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let user_cookie =
        signup_and_login_user(&hub, &client, "regular@example.test", "hunter22!").await;
    let admin_cookie =
        signup_and_login_user(&hub, &client, "admin@example.test", "hunter22!").await;
    let admin_id = user_id_by_email(&hub, "admin@example.test").await;

    for (cookie, host) in [
        (&user_cookie, "u.regular.test"),
        (&admin_cookie, "u.admin.test"),
    ] {
        let resp = client
            .post(hub.url("/v1/invites"))
            .header(reqwest::header::COOKIE, cookie.as_str())
            .json(&json!({
                "name": host,
                "hostnames": [host],
                "expires_in_secs": 3600,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    hub.state
        .db
        .set_user_role(&admin_id, "operator", 1)
        .await
        .expect("set_user_role");
    // Operator role gates on 2FA; enroll to clear the gate before the
    // rest of the test exercises invite scoping.
    enroll_2fa(&hub, &client, &admin_cookie).await;

    let mine_resp = client
        .get(hub.url("/v1/invites"))
        .header(reqwest::header::COOKIE, &admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(mine_resp.status(), 200);
    let mine: Value = mine_resp.json().await.unwrap();
    let mine_invites = mine["invites"].as_array().unwrap();
    assert_eq!(mine_invites.len(), 1);
    assert_eq!(mine_invites[0]["hostnames"][0], "u.admin.test");

    let all_resp = client
        .get(hub.url("/v1/invites?scope=all"))
        .header(reqwest::header::COOKIE, &admin_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(all_resp.status(), 200);
    let all: Value = all_resp.json().await.unwrap();
    assert_eq!(all["invites"].as_array().unwrap().len(), 2);

    // scope=all from a non-operator must be silently ignored.
    let leaked_resp = client
        .get(hub.url("/v1/invites?scope=all"))
        .header(reqwest::header::COOKIE, &user_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(leaked_resp.status(), 200);
    let leaked: Value = leaked_resp.json().await.unwrap();
    let leaked_invites = leaked["invites"].as_array().unwrap();
    assert_eq!(leaked_invites.len(), 1);
    assert_eq!(leaked_invites[0]["hostnames"][0], "u.regular.test");
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

// DELETE /v1/tenants/{id} (operator tenant remove)

#[tokio::test]
async fn delete_tenant_drops_from_policy_and_records_removal() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // v2: creating the invite registers the tenant immediately.
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    assert!(hub.state.policy.load().is_known_tenant(&tenant.id()));

    let (status, body) = delete_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "removed");

    // In-memory policy evicted.
    assert!(!hub.state.policy.load().is_known_tenant(&tenant.id()));

    // Persistent removal recorded (so a hub restart stays consistent).
    let removals = hub.state.db.list_tenant_removals().await.unwrap();
    assert!(removals.contains(&tenant.id()));
}

#[tokio::test]
async fn delete_tenant_blocks_future_entry_submissions() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

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
async fn tenant_cannot_claim_unapproved_hostname() {
    // v2 equivalent: after invite creation the tenant is pre-registered with
    // exactly the approved hostnames. Claiming anything else must fail.
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

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

// POST /v1/bootstrap (v2: replaces /v1/invites/redeem)

#[tokio::test]
async fn bootstrap_returns_tenant_info_idempotent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let expected_tenant = tenant_from_token(&token);

    let (status1, body1) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status1, 200);
    assert_eq!(body1["tenant_id"], expected_tenant.id().to_string());
    assert_eq!(body1["hostnames"], json!(["app.alice.test"]));

    // Second call must return the same tenant info -- v2 bootstrap is pure
    // metadata lookup, no state transition.
    let (status2, body2) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status2, 200);
    assert_eq!(body2["tenant_id"], body1["tenant_id"]);
    assert_eq!(body2["hostnames"], body1["hostnames"]);
}

/// `iroh_endpoints` must pair the colocated edge's id with its iroh
/// addresses. Other entries in `trusted_edges` MUST NOT receive the
/// colocated edge's addresses — agents would dial them on the wrong
/// endpoint.
#[tokio::test]
async fn bootstrap_iroh_endpoints_only_describe_colocated_edge() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["a.test"]).await;
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status, 200, "bootstrap: {body}");

    let self_edge = hub
        .state
        .identity
        .edge_node_id
        .expect("test hub has edge_node_id")
        .to_string();
    let endpoints = body["iroh_endpoints"]
        .as_array()
        .expect("iroh_endpoints array");
    assert_eq!(endpoints.len(), 1, "exactly the colocated edge");
    assert_eq!(
        endpoints[0]["node_id"].as_str().expect("node_id"),
        self_edge
    );
    let addrs: Vec<String> = endpoints[0]["addresses"]
        .as_array()
        .expect("addresses array")
        .iter()
        .map(|v| v.as_str().expect("addr").to_string())
        .collect();
    assert_eq!(addrs, vec!["127.0.0.1:51820".to_string()]);
}

/// Create an invite with an explicit region + failover regions.
async fn create_invite_with_region(
    hub: &TestHub,
    client: &reqwest::Client,
    name: &str,
    hostnames: &[&str],
    region: Option<&str>,
    failover_regions: &[&str],
) -> InviteToken {
    let (status, body) = post_json(
        client,
        &hub.url("/v1/invites"),
        json!({
            "name": name,
            "hostnames": hostnames,
            "expires_in_secs": 3600,
            "region": region,
            "failover_regions": failover_regions,
        }),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200, "create_invite failed: {body}");
    InviteToken::decode(body["token"].as_str().expect("token field")).expect("decode token")
}

/// Register a live remote edge in a region with one dialable iroh address.
/// Returns its node-id string for endpoint assertions.
fn inject_edge(hub: &TestHub, seed: u8, addr: &str, region: &str) -> String {
    let node_id = iroh::SecretKey::from([seed; 32]).public();
    hub.state.live_edges.upsert(
        *node_id.as_bytes(),
        vec![addr.to_string()],
        towonel_common::edge_link::EdgeCapabilities::default(),
        vec![],
        Some(region.to_string()),
        towonel_common::time::now_ms(),
    );
    node_id.to_string()
}

/// Collect the `node_id`s returned in `iroh_endpoints`.
fn endpoint_node_ids(body: &Value) -> Vec<String> {
    body["iroh_endpoints"]
        .as_array()
        .expect("iroh_endpoints array")
        .iter()
        .map(|e| e["node_id"].as_str().expect("node_id").to_string())
        .collect()
}

async fn bootstrap_endpoints(
    hub: &TestHub,
    client: &reqwest::Client,
    token: &InviteToken,
) -> Vec<String> {
    let (status, body) = post_json(
        client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status, 200, "bootstrap: {body}");
    endpoint_node_ids(&body)
}

// The colocated test edge serves the default region (EU).

#[tokio::test]
async fn bootstrap_region_selects_matching_edges() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let eu = inject_edge(&hub, 2, "10.0.0.2:51820", "EU");
    let ca = inject_edge(&hub, 3, "10.0.0.3:51820", "CA");

    let token = create_invite_with_region(&hub, &client, "a", &["a.test"], Some("EU"), &[]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    assert!(ids.contains(&eu), "EU remote edge included: {ids:?}");
    assert!(!ids.contains(&ca), "CA remote edge excluded: {ids:?}");
}

#[tokio::test]
async fn bootstrap_failover_region_included() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let eu = inject_edge(&hub, 2, "10.0.0.2:51820", "EU");
    let ca = inject_edge(&hub, 3, "10.0.0.3:51820", "CA");

    let token =
        create_invite_with_region(&hub, &client, "a", &["a.test"], Some("EU"), &["CA"]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    assert!(ids.contains(&eu), "EU edge included: {ids:?}");
    assert!(ids.contains(&ca), "CA failover edge included: {ids:?}");
}

#[tokio::test]
async fn bootstrap_default_region_excludes_other_regions() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let ca = inject_edge(&hub, 3, "10.0.0.3:51820", "CA");

    // No region on the invite resolves to the default (EU); the colocated EU
    // edge is returned but the CA edge is not.
    let token = create_invite_with_region(&hub, &client, "a", &["a.test"], None, &[]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    assert!(
        !ids.contains(&ca),
        "CA edge excluded for default EU: {ids:?}"
    );
    assert!(!ids.is_empty(), "colocated EU edge still returned");
}

#[tokio::test]
async fn bootstrap_region_match_is_case_insensitive() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let ca = inject_edge(&hub, 3, "10.0.0.3:51820", "CA");

    // Lowercase `eu` must canonicalize to the `EU` default region, so the
    // colocated EU edge matches and the CA edge is excluded -- NOT the
    // no-strand fallback (which would return CA too).
    let token = create_invite_with_region(&hub, &client, "a", &["a.test"], Some("eu"), &[]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    assert!(!ids.contains(&ca), "CA excluded for lowercase eu: {ids:?}");
    assert!(!ids.is_empty(), "colocated EU edge still returned");
}

#[tokio::test]
async fn bootstrap_in_region_but_undialable_falls_back() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // A CA edge that advertises no dialable iroh address.
    let ca_node = iroh::SecretKey::from([4u8; 32]).public();
    hub.state.live_edges.upsert(
        *ca_node.as_bytes(),
        vec![],
        towonel_common::edge_link::EdgeCapabilities::default(),
        vec![],
        Some("CA".to_string()),
        towonel_common::time::now_ms(),
    );

    // Invite is CA-scoped, but the only CA edge has no addresses, so no
    // dialable edge is in-region -> fall back to all edges, which surfaces
    // the dialable colocated EU edge.
    let token = create_invite_with_region(&hub, &client, "a", &["a.test"], Some("CA"), &[]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    let colocated = hub
        .state
        .identity
        .edge_node_id
        .expect("test hub has edge_node_id")
        .to_string();
    assert!(
        ids.contains(&colocated),
        "fallback surfaces the dialable EU edge: {ids:?}"
    );
}

#[tokio::test]
async fn bootstrap_no_edge_in_region_returns_all() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let ca = inject_edge(&hub, 3, "10.0.0.3:51820", "CA");

    // No edge serves ASIA, so the filter would strand the agent -> fall back
    // to every edge (colocated EU + the CA remote).
    let token = create_invite_with_region(&hub, &client, "a", &["a.test"], Some("ASIA"), &[]).await;
    let ids = bootstrap_endpoints(&hub, &client, &token).await;

    assert!(ids.contains(&ca), "fallback returns the CA edge: {ids:?}");
    assert!(ids.len() >= 2, "fallback returns all edges: {ids:?}");
}

#[tokio::test]
async fn bootstrap_rejects_wrong_secret() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["x.test"]).await;
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode([0x00; 32]),
        }),
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn bootstrap_without_agent_id_omits_edge_cred() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.get("kid").is_none(),
        "kid must be absent for legacy clients"
    );
    assert!(body.get("edge_cred_b64").is_none());
    assert!(body.get("edge_cred_sig_b64").is_none());
}

#[tokio::test]
async fn bootstrap_with_agent_id_returns_signed_edge_cred() {
    use towonel_common::edge_cred::{EdgeCred, verify_edge_cred};
    use towonel_common::identity::AgentKeypair;

    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let expected_tenant = tenant_from_token(&token);
    let agent_kp = AgentKeypair::generate();
    let agent_id_hex = agent_kp.id().to_string();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
            "agent_id": &agent_id_hex,
        }),
        None,
    )
    .await;
    assert_eq!(status, 200, "bootstrap: {body}");

    let kid = body["kid"].as_u64().expect("kid");
    let cred_b64 = body["edge_cred_b64"].as_str().expect("edge_cred_b64");
    let sig_b64 = body["edge_cred_sig_b64"]
        .as_str()
        .expect("edge_cred_sig_b64");
    let cred_bytes = B64.decode(cred_b64).unwrap();
    let sig_bytes: [u8; towonel_common::identity::PQ_SIGNATURE_LEN] =
        B64.decode(sig_b64).unwrap().try_into().expect("sig length");

    let cred = EdgeCred::from_cbor(&cred_bytes).unwrap();
    assert_eq!(u64::from(cred.kid), kid);
    assert_eq!(cred.agent_id, agent_kp.id());
    assert_eq!(cred.tenant_id, expected_tenant.id());
    assert!(cred.not_after_ms > towonel_common::time::now_ms());
    assert!(verify_edge_cred(
        hub.state.signer.public_key(),
        &cred_bytes,
        &sig_bytes
    ));
}

#[tokio::test]
async fn bootstrap_with_garbage_agent_id_400s() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
            "agent_id": "not-hex",
        }),
        None,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn bootstrap_rejects_missing_invite() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode([0xff; INVITE_ID_LEN]),
            "invite_secret": B64.encode([0x00; 32]),
        }),
        None,
    )
    .await;
    // Missing-invite and wrong-secret return the SAME error so a remote
    // attacker can't enumerate which invite IDs exist.
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn session_removed_drops_agent_from_route_table() {
    // Register an agent + hostname via signed entries, mark its session
    // live, verify the route table includes it, then mark the session
    // removed and confirm the next rebuild drops it.
    use super::live_agents::SourceKey;

    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();

    for (seq, op) in [
        (
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.alice.test".into(),
            },
        ),
        (
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ] {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: tenant.id(),
            sequence: seq,
            timestamp: 1_700_000_000_000,
            op,
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
        assert_eq!(resp.status(), 200);
    }

    let source = SourceKey::Remote([0xAB; 32]);
    assert!(
        hub.state
            .live_agents
            .record_added(source, tenant.id(), agent.id())
    );
    super::api::rebuild_and_broadcast_routes(&hub.state)
        .await
        .unwrap();
    assert!(
        hub.state
            .live_agents
            .snapshot()
            .contains(&(tenant.id(), agent.id()))
    );

    assert!(
        hub.state
            .live_agents
            .record_removed(source, tenant.id(), agent.id())
    );
    super::api::rebuild_and_broadcast_routes(&hub.state)
        .await
        .unwrap();
    assert!(
        !hub.state
            .live_agents
            .snapshot()
            .contains(&(tenant.id(), agent.id()))
    );
}

#[tokio::test]
async fn bootstrap_after_revoke_returns_unauthorized_no_oracle() {
    // Revoked invites must return 401 unauthorized (same as wrong-secret) so
    // an attacker holding the secret can't detect the revocation via the
    // error code and verify their secret is correct.
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    delete_json(
        &client,
        &hub.url(&format!("/v1/invites/{}", token.invite_id_b64())),
        Some(OPERATOR_KEY),
    )
    .await;

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/bootstrap"),
        json!({
            "invite_id": B64.encode(token.invite_id),
            "invite_secret": B64.encode(token.invite_secret),
        }),
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "unauthorized");
}

async fn submit_entry(
    client: &reqwest::Client,
    hub: &TestHub,
    tenant: &TenantKeypair,
    sequence: u64,
    op: ConfigOp,
) -> (u16, Value) {
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence,
        timestamp: 1_700_000_000_000,
        op,
    };
    let entry = SignedConfigEntry::sign(&payload, tenant).unwrap();
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body).unwrap();
    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.unwrap_or_default();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        ciborium::from_reader(bytes.as_ref())
            .or_else(|_| serde_json::from_slice(&bytes))
            .unwrap_or(Value::Null)
    };
    (status, body)
}

#[tokio::test]
async fn upsert_tcp_service_accepted() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 200, "got body: {body}");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn upsert_tcp_service_zero_port_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "bad".into(),
            listen_port: 0,
        },
    )
    .await;
    assert_eq!(status, 400);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("must not be 0"),
        "got body: {body}"
    );
}

#[tokio::test]
async fn upsert_tcp_service_privileged_port_rejected_by_default() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "http".into(),
            listen_port: 80,
        },
    )
    .await;
    assert_eq!(status, 400);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("privileged"),
        "got body: {body}"
    );
}

#[tokio::test]
async fn upsert_tcp_service_cross_tenant_port_collision_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let alice_token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let alice = tenant_from_token(&alice_token);
    let bob_token = create_invite(&hub, &client, "bob", &["app.bob.test"]).await;
    let bob = tenant_from_token(&bob_token);

    let (status, _) = submit_entry(
        &client,
        &hub,
        &alice,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &bob,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 400, "got body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already claimed"),
        "got body: {body}"
    );
}

#[tokio::test]
async fn upsert_tcp_service_same_tenant_can_update_port() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, _) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        2,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2223,
        },
    )
    .await;
    assert_eq!(status, 200, "got body: {body}");
}

#[tokio::test]
async fn upsert_tcp_service_same_tenant_different_service_same_port_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, _) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        2,
        ConfigOp::UpsertTcpService {
            service: "metrics".into(),
            listen_port: 2222,
        },
    )
    .await;
    assert_eq!(status, 400, "got body: {body}");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("already bound to service `ssh`"),
        "got body: {body}"
    );
}

#[tokio::test]
async fn require_reservation_blocks_unreserved_tcp_claim() {
    let hub = TestHub::start_with(true).await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 22000,
        },
    )
    .await;
    assert_eq!(status, 403, "got body: {body}");
    assert_eq!(body["error"]["code"], "port_not_reserved");
}

#[tokio::test]
async fn require_reservation_allows_reserved_tcp_claim() {
    let hub = TestHub::start_with(true).await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 22000, "label": "ssh"}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 201, "reserve failed: {body}");

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertTcpService {
            service: "ssh".into(),
            listen_port: 22000,
        },
    )
    .await;
    assert_eq!(status, 200, "got body: {body}");
}

#[tokio::test]
async fn require_reservation_is_per_protocol() {
    // A TCP reservation on port N must NOT unlock a UDP claim on the same N.
    let hub = TestHub::start_with(true).await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, _) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 5353}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = submit_entry(
        &client,
        &hub,
        &tenant,
        1,
        ConfigOp::UpsertUdpService {
            service: "dns".into(),
            listen_port: 5353,
        },
    )
    .await;
    assert_eq!(status, 403, "got body: {body}");
    assert_eq!(body["error"]["code"], "port_not_reserved");
}

#[tokio::test]
async fn unknown_op_variant_returns_unsupported_op() {
    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum FutureOp {
        SomethingNew { foo: String },
    }
    #[derive(Serialize)]
    struct FuturePayload {
        version: u16,
        tenant_id: TenantId,
        sequence: u64,
        timestamp: u64,
        op: FutureOp,
    }

    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let payload = FuturePayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: FutureOp::SomethingNew { foo: "bar".into() },
    };
    let mut payload_cbor = Vec::new();
    ciborium::into_writer(&payload, &mut payload_cbor).unwrap();
    let signature = Box::new(tenant.sign(&payload_cbor));
    let entry = SignedConfigEntry {
        payload_cbor,
        signature,
        tenant_id: tenant.id(),
    };
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body).unwrap();

    let resp = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, 400, "got body: {body}");
    assert_eq!(body["error"]["code"], "unsupported_op", "got body: {body}");
}

// POST /v1/agent/refresh

#[derive(Serialize)]
struct RefreshBody {
    tenant_id: TenantId,
    agent_id: towonel_common::identity::AgentId,
}

fn encode_refresh(tenant_id: TenantId, agent_id: towonel_common::identity::AgentId) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(
        &RefreshBody {
            tenant_id,
            agent_id,
        },
        &mut buf,
    )
    .unwrap();
    buf
}

async fn register_agent_for_refresh(
    hub: &TestHub,
    client: &reqwest::Client,
    tenant: &TenantKeypair,
    agent: &AgentKeypair,
) {
    for (seq, op) in [
        (
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.alice.test".into(),
            },
        ),
        (
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ] {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: tenant.id(),
            sequence: seq,
            timestamp: 1_700_000_000_000,
            op,
        };
        let entry = SignedConfigEntry::sign(&payload, tenant).unwrap();
        let mut body = Vec::new();
        ciborium::into_writer(&entry, &mut body).unwrap();
        let resp = client
            .post(hub.url("/v1/entries"))
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "registering agent for refresh test");
    }
}

async fn post_refresh_signed(
    hub: &TestHub,
    client: &reqwest::Client,
    tenant_id: TenantId,
    agent: &AgentKeypair,
) -> (reqwest::StatusCode, Value) {
    let body_bytes = encode_refresh(tenant_id, agent.id());
    let auth = towonel_common::auth::sign_auth_header(
        agent.signing_key(),
        "towonel/agent-refresh/v1",
        towonel_common::time::now_ms(),
        &body_bytes,
    );
    let resp = client
        .post(hub.url("/v1/agent/refresh"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body_bytes)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let value = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn refresh_returns_fresh_edge_cred_for_signed_agent() {
    use towonel_common::edge_cred::{EdgeCred, verify_edge_cred};

    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();
    register_agent_for_refresh(&hub, &client, &tenant, &agent).await;

    let (status, body) = post_refresh_signed(&hub, &client, tenant.id(), &agent).await;
    assert_eq!(status, 200, "{body}");

    let cred_bytes = B64.decode(body["edge_cred_b64"].as_str().unwrap()).unwrap();
    let sig_bytes: [u8; towonel_common::identity::PQ_SIGNATURE_LEN] = B64
        .decode(body["edge_cred_sig_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let cred = EdgeCred::from_cbor(&cred_bytes).unwrap();
    assert_eq!(cred.agent_id, agent.id());
    assert_eq!(cred.tenant_id, tenant.id());
    assert_eq!(u64::from(cred.kid), body["kid"].as_u64().unwrap(),);
    assert!(verify_edge_cred(
        hub.state.signer.public_key(),
        &cred_bytes,
        &sig_bytes,
    ));
}

#[tokio::test]
async fn refresh_rejects_agent_not_in_signed_agents() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();
    // Deliberately skip register_agent_for_refresh.

    let (status, body) = post_refresh_signed(&hub, &client, tenant.id(), &agent).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn refresh_rejects_revoked_agent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();
    register_agent_for_refresh(&hub, &client, &tenant, &agent).await;

    // Submit RevokeAgent at next sequence; the rebuild must drop it from
    // signed_agents and the next refresh must reject.
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 3,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::RevokeAgent {
            agent_id: agent.id(),
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
    assert_eq!(resp.status(), 200, "submitting RevokeAgent");

    let (status, body) = post_refresh_signed(&hub, &client, tenant.id(), &agent).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn refresh_rejects_mismatched_agent_id() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();
    let attacker = AgentKeypair::generate();
    register_agent_for_refresh(&hub, &client, &tenant, &agent).await;

    // Body claims `agent`, but the signature is from `attacker`.
    let body_bytes = encode_refresh(tenant.id(), agent.id());
    let auth = towonel_common::auth::sign_auth_header(
        attacker.signing_key(),
        "towonel/agent-refresh/v1",
        towonel_common::time::now_ms(),
        &body_bytes,
    );
    let resp = client
        .post(hub.url("/v1/agent/refresh"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn refresh_rate_limits_per_agent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();
    register_agent_for_refresh(&hub, &client, &tenant, &agent).await;

    // Each refresh must use a unique ts_ms so the nonce cache doesn't reject
    // it as a replay before the per-agent limiter even fires.
    let base_ts = towonel_common::time::now_ms();
    let body_bytes = encode_refresh(tenant.id(), agent.id());
    for i in 0..super::api::AGENT_REFRESH_MAX_PER_MIN {
        let auth = towonel_common::auth::sign_auth_header(
            agent.signing_key(),
            "towonel/agent-refresh/v1",
            base_ts + u64::from(i),
            &body_bytes,
        );
        let resp = client
            .post(hub.url("/v1/agent/refresh"))
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(body_bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "call #{i} should succeed");
    }

    let auth = towonel_common::auth::sign_auth_header(
        agent.signing_key(),
        "towonel/agent-refresh/v1",
        base_ts + u64::from(super::api::AGENT_REFRESH_MAX_PER_MIN),
        &body_bytes,
    );
    let resp = client
        .post(hub.url("/v1/agent/refresh"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn upsert_agent_is_idempotent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let token = create_invite(&hub, &client, "alice", &["app.alice.test"]).await;
    let tenant = tenant_from_token(&token);
    let agent = AgentKeypair::generate();

    // First registration with sequence 1
    let payload = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 1,
        timestamp: 1_700_000_000_000,
        op: ConfigOp::UpsertAgent {
            agent_id: agent.id(),
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
    assert_eq!(resp.status(), 200, "first UpsertAgent should succeed");

    // Second registration with SAME agent_id but different sequence (simulating retry)
    let payload2 = ConfigPayload {
        version: 1,
        tenant_id: tenant.id(),
        sequence: 2,
        timestamp: 1_700_000_000_001,
        op: ConfigOp::UpsertAgent {
            agent_id: agent.id(),
        },
    };
    let entry2 = SignedConfigEntry::sign(&payload2, &tenant).unwrap();
    let mut body2 = Vec::new();
    ciborium::into_writer(&entry2, &mut body2).unwrap();

    let resp2 = client
        .post(hub.url("/v1/entries"))
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body2)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        200,
        "second UpsertAgent with same agent_id should succeed (idempotent)"
    );

    // Verify only one UpsertAgent entry was inserted
    let entries_url = format!("{}/v1/tenants/{}/entries", hub.base_url, tenant.id());
    let resp = client.get(&entries_url).send().await.unwrap();
    let entries: Vec<SignedConfigEntry> =
        ciborium::from_reader(resp.bytes().await.unwrap().as_ref()).unwrap();

    let upsert_agent_count = entries
        .iter()
        .filter(|e| {
            e.verify(tenant.public_key())
                .is_ok_and(|p| matches!(p.op, ConfigOp::UpsertAgent { .. }))
        })
        .count();

    assert_eq!(
        upsert_agent_count, 1,
        "only one UpsertAgent entry should be in the database"
    );
}

// --- email verification + password reset + signup-invite mailing ---

/// Mint a signup invite via the hub's operator API and return its code.
async fn mint_signup_invite(hub: &TestHub, client: &reqwest::Client) -> String {
    let (status, body) = post_json(
        client,
        &hub.url("/v1/signup-invites"),
        json!({"role": "user"}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200, "mint_signup_invite: {body}");
    body["code"].as_str().expect("code").to_string()
}

/// Drain any background pending mail-sends so the next assertion is stable.
/// In practice the API handler awaits the mailer inline, but the helper is
/// here so future async batching doesn't require touching every test.
async fn snapshot_mails(hub: &TestHub) -> Vec<super::test_helpers::TestMail> {
    hub.mailer.sent.lock().await.clone()
}

#[tokio::test]
async fn signup_sends_verification_and_returns_no_session() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let code = mint_signup_invite(&hub, &client).await;
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": "alice@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    assert_eq!(status, 200, "signup: {body}");
    assert_eq!(body["verification_required"], true);
    assert_eq!(body["email"], "alice@example.test");
    // Critical: signup must not authenticate the caller.
    assert_eq!(
        body.get("user").map(Value::is_object),
        None,
        "signup must not return an authed user before verification"
    );

    let mails = snapshot_mails(&hub).await;
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].kind, TestMailKind::Verification);
    assert_eq!(mails[0].to, "alice@example.test");
}

#[tokio::test]
async fn login_blocked_until_email_verified() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let code = mint_signup_invite(&hub, &client).await;
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": "bob@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    assert_eq!(s, 200);

    // First login attempt: correct password but unverified → 403.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/login"),
        json!({"email": "bob@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"]["code"], "email_unverified");

    // Verify by consuming the token captured by the TestMailer.
    let token = snapshot_mails(&hub).await[0].token.clone();
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/verify"),
        json!({"token": token}),
        None,
    )
    .await;
    assert_eq!(s, 200);

    // Now login must succeed.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/login"),
        json!({"email": "bob@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    assert_eq!(status, 200, "post-verify login failed: {body}");
    assert_eq!(body["user"]["email"], "bob@example.test");
}

#[tokio::test]
async fn verify_token_is_single_use() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let code = mint_signup_invite(&hub, &client).await;
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": "carol@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    assert_eq!(s, 200);
    let token = snapshot_mails(&hub).await[0].token.clone();

    let (s1, _) = post_json(
        &client,
        &hub.url("/v1/auth/verify"),
        json!({"token": token.clone()}),
        None,
    )
    .await;
    assert_eq!(s1, 200);

    // Second use must fail. A retry-replay window would let a leaked email
    // link be consumed twice; we want exactly-once.
    let (s2, body) = post_json(
        &client,
        &hub.url("/v1/auth/verify"),
        json!({"token": token}),
        None,
    )
    .await;
    assert_eq!(s2, 400);
    assert_eq!(body["error"]["code"], "token_invalid");
}

#[tokio::test]
async fn verify_resend_does_not_enumerate() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Unknown email — must still return 200 with the same generic message.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/verify/resend"),
        json!({"email": "nobody@example.test"}),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
    assert!(
        snapshot_mails(&hub).await.is_empty(),
        "no mail for unknown user"
    );

    // Real, already-verified user — also 200, also no mail.
    let code = mint_signup_invite(&hub, &client).await;
    let _ = post_json(
        &client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": "dave@example.test", "password": "hunter22!"}),
        None,
    )
    .await;
    let token = snapshot_mails(&hub).await[0].token.clone();
    let _ = post_json(
        &client,
        &hub.url("/v1/auth/verify"),
        json!({"token": token}),
        None,
    )
    .await;
    let before = snapshot_mails(&hub).await.len();
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/verify/resend"),
        json!({"email": "dave@example.test"}),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
    assert_eq!(
        snapshot_mails(&hub).await.len(),
        before,
        "no resend for already-verified user"
    );
}

#[tokio::test]
async fn password_reset_does_not_enumerate_and_invalidates_sessions() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Unknown email path: still 200, still no mail.
    let (status, _) = post_json(
        &client,
        &hub.url("/v1/auth/password/reset"),
        json!({"email": "ghost@example.test"}),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        snapshot_mails(&hub)
            .await
            .iter()
            .all(|m| m.kind != TestMailKind::PasswordReset),
    );

    // Set up an existing verified user.
    let code = mint_signup_invite(&hub, &client).await;
    let _ = post_json(
        &client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": "eve@example.test", "password": "old-pass!"}),
        None,
    )
    .await;
    let verify_token = snapshot_mails(&hub).await[0].token.clone();
    let _ = post_json(
        &client,
        &hub.url("/v1/auth/verify"),
        json!({"token": verify_token}),
        None,
    )
    .await;

    // Log in to mint a session — we'll prove it gets invalidated.
    let login_resp = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "eve@example.test", "password": "old-pass!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), 200);
    let session_cookie = login_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("towonel_session="))
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Sanity: /v1/auth/me succeeds with the cookie.
    let me = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 200);

    // Request reset → captures a token via TestMailer.
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/password/reset"),
        json!({"email": "eve@example.test"}),
        None,
    )
    .await;
    assert_eq!(s, 200);
    let reset_token = snapshot_mails(&hub)
        .await
        .iter()
        .rev()
        .find(|m| m.kind == TestMailKind::PasswordReset)
        .expect("reset mail")
        .token
        .clone();

    // Confirm with a new password.
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/password/reset/confirm"),
        json!({"token": reset_token, "new_password": "new-pass!"}),
        None,
    )
    .await;
    assert_eq!(s, 200);

    // The old cookie must no longer authenticate — sessions are wiped on reset.
    let me = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 401);

    // And the new password must work.
    let (s, _) = post_json(
        &client,
        &hub.url("/v1/auth/login"),
        json!({"email": "eve@example.test", "password": "new-pass!"}),
        None,
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn signup_invite_with_recipient_sends_mail() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/signup-invites"),
        json!({"role": "user", "recipient_email": "newjoiner@example.test"}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    let code = body["code"].as_str().unwrap().to_string();

    let mails = snapshot_mails(&hub).await;
    let sent = mails
        .iter()
        .find(|m| m.kind == TestMailKind::SignupInvite)
        .expect("signup invite mail");
    assert_eq!(sent.to, "newjoiner@example.test");
    assert_eq!(
        sent.token, code,
        "invite mail carries the same code returned to operator"
    );
}

#[tokio::test]
async fn signup_invite_rejects_malformed_recipient_email() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(
        &client,
        &hub.url("/v1/signup-invites"),
        json!({"role": "user", "recipient_email": "not-an-email"}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 400, "should reject malformed: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");
}

/// Sign up + verify + log in; returns the session cookie header value.
async fn signup_and_login_user(
    hub: &TestHub,
    client: &reqwest::Client,
    email: &str,
    password: &str,
) -> String {
    let code = mint_signup_invite(hub, client).await;
    let (s, _) = post_json(
        client,
        &hub.url("/v1/auth/signup"),
        json!({"code": code, "email": email, "password": password}),
        None,
    )
    .await;
    assert_eq!(s, 200);
    let mails = snapshot_mails(hub).await;
    let verify_token = mails
        .iter()
        .rev()
        .find(|m| m.kind == TestMailKind::Verification && m.to == email)
        .expect("verification mail")
        .token
        .clone();
    let (s, _) = post_json(
        client,
        &hub.url("/v1/auth/verify"),
        json!({"token": verify_token}),
        None,
    )
    .await;
    assert_eq!(s, 200);

    let resp = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("towonel_session="))
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn list_identities_returns_user_own_identities_only() {
    use super::db::user_oauth_identities::NewOauthIdentity;
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let alice_cookie =
        signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let bob_cookie = signup_and_login_user(&hub, &client, "bob@example.test", "hunter22!").await;

    let user_id_for = async |cookie: &str| -> String {
        let body: Value = client
            .get(hub.url("/v1/auth/me"))
            .header(reqwest::header::COOKIE, cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["id"].as_str().unwrap().to_string()
    };
    let alice_id = user_id_for(&alice_cookie).await;
    let bob_id = user_id_for(&bob_cookie).await;

    hub.state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "alice-subject",
            user_id: &alice_id,
            email: Some("alice@example.test"),
            now_ms: 1_700_000_000_000,
        })
        .await
        .unwrap();
    hub.state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "bob-subject",
            user_id: &bob_id,
            email: Some("bob@example.test"),
            now_ms: 1_700_000_000_000,
        })
        .await
        .unwrap();

    let body: Value = client
        .get(hub.url("/v1/auth/oidc/identities"))
        .header(reqwest::header::COOKIE, &alice_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let identities = body["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1, "alice must see only her own identity");
    assert_eq!(identities[0]["provider"], "codeberg");
    assert_eq!(identities[0]["email"], "alice@example.test");
    assert_ne!(
        identities[0]["email"], "bob@example.test",
        "bob's identity must not leak"
    );
}

#[tokio::test]
async fn list_identities_requires_authentication() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(hub.url("/v1/auth/oidc/identities"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn unlink_removes_identity_for_caller() {
    use super::db::user_oauth_identities::NewOauthIdentity;
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let me_body: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me_body["id"].as_str().unwrap().to_string();

    hub.state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "codeberg-subject-9999",
            user_id: &user_id,
            email: Some("alice@example.test"),
            now_ms: 1_700_000_000_000,
        })
        .await
        .unwrap();

    let resp = client
        .post(hub.url("/v1/auth/oidc/codeberg/unlink"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The identity must be gone from the DB after a successful unlink.
    let still = hub
        .state
        .db
        .find_oauth_identity("codeberg", "codeberg-subject-9999")
        .await
        .unwrap();
    assert!(still.is_none());
}

#[tokio::test]
async fn unlink_unknown_provider_returns_not_found() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;

    let resp = client
        .post(hub.url("/v1/auth/oidc/codeberg/unlink"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn unlink_blocks_self_lockout_when_no_password_and_no_other_identity() {
    use super::db::user_oauth_identities::NewOauthIdentity;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let me_body: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me_body["id"].as_str().unwrap().to_string();

    // OIDC-only account (no password) with exactly one identity —
    // unlinking it would lock the user out.
    hub.state
        .db
        .insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "codeberg-subject-9999",
            user_id: &user_id,
            email: Some("alice@example.test"),
            now_ms: 1_700_000_000_000,
        })
        .await
        .unwrap();
    super::db::entities::users::Entity::update_many()
        .col_expr(
            super::db::entities::users::Column::PasswordHash,
            sea_orm::sea_query::Expr::value(""),
        )
        .filter(super::db::entities::users::Column::Id.eq(&user_id))
        .exec(&hub.state.db.conn)
        .await
        .unwrap();

    let resp = client
        .post(hub.url("/v1/auth/oidc/codeberg/unlink"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "would_lock_out");
}

async fn user_id_by_email(hub: &TestHub, email: &str) -> String {
    hub.state
        .db
        .find_user_by_email(email)
        .await
        .expect("find_user_by_email")
        .expect("user exists after signup")
        .id
}

#[tokio::test]
async fn non_owner_user_gets_403_on_port_reserve() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let cookie = signup_and_login_user(&hub, &client, "noone@example.test", "hunter22!").await;

    let token = create_invite(&hub, &client, "tenant-a", &["a.alice.test"]).await;
    let tenant = tenant_from_token(&token);

    let resp = client
        .post(hub.url(&format!("/v1/tenants/{}/ports", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"protocol": "tcp", "preferred": 22100}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn owner_user_can_reserve_port() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let cookie = signup_and_login_user(&hub, &client, "owner@example.test", "hunter22!").await;
    let user_id = user_id_by_email(&hub, "owner@example.test").await;

    let token = create_invite(&hub, &client, "tenant-owner", &["a.owner.test"]).await;
    let tenant = tenant_from_token(&token);

    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &[0u8; 16],
            display_name: "test",
            now_ms: 1,
        })
        .await
        .expect("insert_tenant_ownership");

    let resp = client
        .post(hub.url(&format!("/v1/tenants/{}/ports", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"protocol": "tcp", "preferred": 22200}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "expected 201, got {status}: {body}");
    assert_eq!(body["port"], 22200);
}

#[tokio::test]
async fn user_port_quota_enforced() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    hub.state
        .db
        .set_setting_int(super::db::app_settings::USER_PORT_QUOTA_KEY, 2, 1)
        .await
        .unwrap();

    let cookie = signup_and_login_user(&hub, &client, "quota@example.test", "hunter22!").await;
    let user_id = user_id_by_email(&hub, "quota@example.test").await;

    let token = create_invite(&hub, &client, "tenant-quota", &["a.quota.test"]).await;
    let tenant = tenant_from_token(&token);

    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &[1u8; 16],
            display_name: "test",
            now_ms: 1,
        })
        .await
        .unwrap();

    for port in [22300u16, 22301] {
        let resp = client
            .post(hub.url(&format!("/v1/tenants/{}/ports", tenant.id())))
            .header(reqwest::header::COOKIE, &cookie)
            .json(&json!({"protocol": "tcp", "preferred": port}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "port {port} should succeed");
    }

    let resp = client
        .post(hub.url(&format!("/v1/tenants/{}/ports", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"protocol": "tcp", "preferred": 22302}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "port_quota_exceeded");
}

#[tokio::test]
async fn operator_bearer_bypasses_quota() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    hub.state
        .db
        .set_setting_int(super::db::app_settings::USER_PORT_QUOTA_KEY, 0, 1)
        .await
        .unwrap();

    let token = create_invite(&hub, &client, "op-tenant", &["a.op.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 22400}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 201, "operator should bypass quota: {body}");
}

#[tokio::test]
async fn chosen_port_auto_assigns_concrete_ip() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "ip-tenant", &["a.ip.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 22600}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["ip"], "127.0.0.1",
        "chosen port should get a concrete IP"
    );
}

#[tokio::test]
async fn chosen_port_fails_when_no_edge_ip() {
    let hub = TestHub::start_without_edge_ips().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "noip-tenant", &["a.noip.test"]).await;
    let tenant = tenant_from_token(&token);

    let (status, body) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 22700}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["error"]["code"], "no_assignable_ip");
}

#[tokio::test]
async fn available_ports_skips_reserved() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let token = create_invite(&hub, &client, "avail-tenant", &["a.avail.test"]).await;
    let tenant = tenant_from_token(&token);
    let _ = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/ports", tenant.id())),
        json!({"protocol": "tcp", "preferred": 10_000}),
        Some(OPERATOR_KEY),
    )
    .await;

    let (status, body) = get_json(
        &client,
        &hub.url("/v1/ports/available?protocol=tcp&count=5"),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    let ports: Vec<u16> = body["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
        .collect();
    assert_eq!(ports.len(), 5);
    assert!(
        !ports.contains(&10_000),
        "reserved port leaked into available list"
    );
    assert!(ports.iter().all(|p| (10_000..=32_767).contains(p)));
}

#[tokio::test]
async fn operator_can_read_and_update_quota_setting() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = get_json(
        &client,
        &hub.url("/v1/settings/user-port-quota"),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["value"], 10);

    let resp = client
        .put(hub.url("/v1/settings/user-port-quota"))
        .bearer_auth(OPERATOR_KEY)
        .json(&json!({"value": 25}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["value"], 25);

    let (_status, body) = get_json(
        &client,
        &hub.url("/v1/settings/user-port-quota"),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(body["value"], 25);
}

#[tokio::test]
async fn non_owner_user_gets_403_on_list_ports() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let cookie = signup_and_login_user(&hub, &client, "lister@example.test", "hunter22!").await;

    let token = create_invite(&hub, &client, "tenant-list", &["a.list.test"]).await;
    let tenant = tenant_from_token(&token);

    let resp = client
        .get(hub.url(&format!("/v1/tenants/{}/ports", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn non_owner_user_gets_403_on_delete_port() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let cookie = signup_and_login_user(&hub, &client, "deleter@example.test", "hunter22!").await;

    let token = create_invite(&hub, &client, "tenant-del", &["a.del.test"]).await;
    let tenant = tenant_from_token(&token);

    let resp = client
        .delete(hub.url(&format!("/v1/tenants/{}/ports/tcp/22500", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn concurrent_reserves_respect_quota() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    hub.state
        .db
        .set_setting_int(super::db::app_settings::USER_PORT_QUOTA_KEY, 3, 1)
        .await
        .unwrap();

    let cookie = signup_and_login_user(&hub, &client, "race@example.test", "hunter22!").await;
    let user_id = user_id_by_email(&hub, "race@example.test").await;

    let token = create_invite(&hub, &client, "tenant-race", &["a.race.test"]).await;
    let tenant = tenant_from_token(&token);

    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &[3u8; 16],
            display_name: "test",
            now_ms: 1,
        })
        .await
        .unwrap();

    // Mix of tcp and udp to cover the cross-protocol race the locks now guard against.
    let url = hub.url(&format!("/v1/tenants/{}/ports", tenant.id()));
    let mut handles = Vec::new();
    for (i, proto) in ["tcp", "tcp", "tcp", "udp", "udp", "udp", "tcp", "udp"]
        .iter()
        .enumerate()
    {
        let client = client.clone();
        let url = url.clone();
        let cookie = cookie.clone();
        let proto = (*proto).to_string();
        let port = 22_600u16 + u16::try_from(i).unwrap();
        handles.push(tokio::spawn(async move {
            client
                .post(&url)
                .header(reqwest::header::COOKIE, &cookie)
                .json(&json!({"protocol": proto, "preferred": port}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut created = 0;
    let mut quota_exceeded = 0;
    let mut other = 0;
    for h in handles {
        match h.await.unwrap() {
            201 => created += 1,
            403 => quota_exceeded += 1,
            _ => other += 1,
        }
    }
    assert_eq!(created, 3, "exactly quota=3 should succeed");
    assert_eq!(quota_exceeded, 5, "the remaining 5 should be quota-blocked");
    assert_eq!(other, 0);

    let count = hub
        .state
        .db
        .count_port_reservations_for_user(&user_id)
        .await
        .unwrap();
    assert_eq!(count, 3, "DB count must match the quota — no slip-through");
}

async fn current_totp(state: &super::api::AppState, user_id: &str) -> String {
    let row = state.db.find_user_totp(user_id).await.unwrap().unwrap();
    let secret = super::auth::totp::unseal(&row.secret_encrypted, &state.kek).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    super::auth::totp::generate_at(&secret, now)
}

async fn enroll_2fa(hub: &TestHub, client: &reqwest::Client, cookie: &str) -> Vec<String> {
    let setup: Value = client
        .post(hub.url("/v1/auth/2fa/setup"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(setup["secret_base32"].is_string(), "setup: {setup}");
    assert!(setup["otpauth_url"].is_string(), "setup: {setup}");

    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap().to_string();
    let code = current_totp(&hub.state, &user_id).await;

    let confirm: Value = client
        .post(hub.url("/v1/auth/2fa/confirm"))
        .header(reqwest::header::COOKIE, cookie)
        .json(&json!({"code": code}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    confirm["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn twofa_setup_then_confirm_marks_enabled() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let backups = enroll_2fa(&hub, &client, &cookie).await;
    assert_eq!(backups.len(), 10, "must issue exactly ten backup codes");

    let status: Value = client
        .get(hub.url("/v1/auth/2fa/status"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["enabled"], true);
    assert_eq!(status["pending"], false);
    assert_eq!(status["backup_codes_remaining"], 10);
}

#[tokio::test]
async fn login_without_twofa_returns_session_directly() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let _cookie = signup_and_login_user(&hub, &client, "carol@example.test", "hunter22!").await;
    let resp = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "carol@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let has_session = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|s| s.starts_with("towonel_session="));
    assert!(has_session, "session cookie must be set when no 2FA");
}

#[tokio::test]
async fn login_with_twofa_returns_challenge_not_session() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "dave@example.test", "hunter22!").await;
    enroll_2fa(&hub, &client, &cookie).await;

    let resp = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "dave@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let has_session = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|s| s.starts_with("towonel_session="));
    assert!(
        !has_session,
        "session cookie must NOT be set when 2FA required"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["twofa_required"], true);
    assert!(body["challenge_token"].is_string());
}

#[tokio::test]
async fn twofa_verify_with_correct_code_issues_session() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "eve@example.test", "hunter22!").await;
    enroll_2fa(&hub, &client, &cookie).await;

    let login_body: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "eve@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = login_body["challenge_token"].as_str().unwrap();

    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap();
    let code = current_totp(&hub.state, user_id).await;

    let resp = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": challenge, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let session = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("towonel_session="));
    assert!(session.is_some(), "2FA verify must set session cookie");
}

#[tokio::test]
async fn twofa_verify_replay_within_window_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "frank@example.test", "hunter22!").await;
    enroll_2fa(&hub, &client, &cookie).await;

    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap().to_string();

    // First login completes with the current code.
    let login1: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "frank@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal1 = login1["challenge_token"].as_str().unwrap().to_string();
    let code = current_totp(&hub.state, &user_id).await;
    let r1 = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": chal1, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    // Second login with the SAME code must be rejected (replay guard).
    let login2: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "frank@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal2 = login2["challenge_token"].as_str().unwrap().to_string();
    let r2 = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": chal2, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 401, "replayed code must be rejected");
}

#[tokio::test]
async fn twofa_challenge_burned_after_max_failed_attempts() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "ivy@example.test", "hunter22!").await;
    enroll_2fa(&hub, &client, &cookie).await;

    let login: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "ivy@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = login["challenge_token"].as_str().unwrap().to_string();

    // Burn the challenge by submitting wrong codes up to the bound.
    for _ in 0..super::api::TWOFA_MAX_ATTEMPTS_PER_CHALLENGE {
        let r = client
            .post(hub.url("/v1/auth/2fa/verify"))
            .json(&json!({"challenge_token": challenge, "code": "000000"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    // Even a correct code on the same challenge must now fail.
    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap();
    let code = current_totp(&hub.state, user_id).await;
    let r = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": challenge, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        401,
        "challenge must be invalid after exceeding attempt cap"
    );
}

#[tokio::test]
async fn twofa_backup_code_works_once() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "grace@example.test", "hunter22!").await;
    let backups = enroll_2fa(&hub, &client, &cookie).await;
    let backup = backups.into_iter().next().unwrap();

    // First use: succeed.
    let login1: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "grace@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal1 = login1["challenge_token"].as_str().unwrap().to_string();
    let r1 = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": chal1, "code": backup}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    // Second use: same backup code is now consumed -> 401.
    let login2: Value = client
        .post(hub.url("/v1/auth/login"))
        .json(&json!({"email": "grace@example.test", "password": "hunter22!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chal2 = login2["challenge_token"].as_str().unwrap().to_string();
    let r2 = client
        .post(hub.url("/v1/auth/2fa/verify"))
        .json(&json!({"challenge_token": chal2, "code": backup}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 401, "consumed backup code must not work again");
}

#[tokio::test]
async fn twofa_disable_requires_password_and_code() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "henry@example.test", "hunter22!").await;
    let backups = enroll_2fa(&hub, &client, &cookie).await;
    // Use a backup code as the second factor — sidesteps the TOTP replay
    // window so the test is deterministic regardless of which 30s step we
    // land in.
    let backup_code = backups
        .into_iter()
        .next()
        .expect("at least one backup code");

    let r1 = client
        .post(hub.url("/v1/auth/2fa/disable"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"password": "wrong", "code": backup_code.clone()}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 401);

    let r2 = client
        .post(hub.url("/v1/auth/2fa/disable"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"password": "hunter22!", "code": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 401);

    let r3 = client
        .post(hub.url("/v1/auth/2fa/disable"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"password": "hunter22!", "code": backup_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), 200, "disable with backup code must succeed");

    let status: Value = client
        .get(hub.url("/v1/auth/2fa/status"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["enabled"], false);
    assert_eq!(status["pending"], false);
    assert_eq!(status["backup_codes_remaining"], 0);
}

#[tokio::test]
async fn operator_without_twofa_blocked_from_privileged_routes() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let cookie = signup_and_login_user(&hub, &client, "op@example.test", "hunter22!").await;
    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap().to_string();
    let now = i64::try_from(towonel_common::time::now_ms()).unwrap();
    hub.state
        .db
        .set_user_role(&user_id, "operator", now)
        .await
        .unwrap();

    let resp = client
        .get(hub.url("/v1/edges"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "twofa_setup_required");

    // The enrollment surface must stay reachable so the UI has a way out.
    let r2 = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);

    let r3 = client
        .post(hub.url("/v1/auth/2fa/setup"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), 200);

    let code = current_totp(&hub.state, &user_id).await;
    let r4 = client
        .post(hub.url("/v1/auth/2fa/confirm"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r4.status(), 200);

    let r5 = client
        .get(hub.url("/v1/edges"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r5.status(), 200);
}

// POST/GET/DELETE /v1/auth/api-keys (personal API keys)

async fn create_api_key(
    hub: &TestHub,
    client: &reqwest::Client,
    cookie: &str,
    body: Value,
) -> (reqwest::StatusCode, Value) {
    let resp = client
        .post(hub.url("/v1/auth/api-keys"))
        .header(reqwest::header::COOKIE, cookie)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let json: Value = resp.json().await.unwrap();
    (status, json)
}

#[tokio::test]
async fn api_key_authenticates_as_owning_user() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;

    let me_via_cookie = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let user_id = me_via_cookie["id"].as_str().unwrap().to_string();

    let (status, body) = create_api_key(&hub, &client, &cookie, json!({"name": "ci"})).await;
    assert_eq!(status, 201);
    let token = body["token"].as_str().unwrap();
    assert!(token.starts_with("twk_"), "token shape: {token}");

    // The minted key authenticates as the same user via Bearer.
    let (status, me_via_key) = get_json(&client, &hub.url("/v1/auth/me"), Some(token)).await;
    assert_eq!(status, 200);
    assert_eq!(me_via_key["id"].as_str().unwrap(), user_id);
    assert_eq!(me_via_key["email"].as_str().unwrap(), "alice@example.test");
}

#[tokio::test]
async fn api_key_create_rejected_for_operator_key() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    // Operator-key principal is not a user account.
    let (status, body) = post_json(
        &client,
        &hub.url("/v1/auth/api-keys"),
        json!({"name": "nope"}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"]["code"].as_str().unwrap(), "user_required");
}

#[tokio::test]
async fn api_key_listed_then_revoked_stops_working() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;

    let (status, created) = create_api_key(&hub, &client, &cookie, json!({"name": "laptop"})).await;
    assert_eq!(status, 201);
    let token = created["token"].as_str().unwrap().to_string();
    let key_id = created["id"].as_str().unwrap().to_string();

    // Listing exposes metadata but never the secret.
    let (status, listed) = get_json(&client, &hub.url("/v1/auth/api-keys"), Some(&token)).await;
    assert_eq!(status, 200);
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"].as_str().unwrap(), key_id);
    assert_eq!(keys[0]["name"].as_str().unwrap(), "laptop");
    assert!(keys[0].get("token").is_none(), "secret must not be listed");

    // Revoke, then the same token is rejected.
    let (status, _) = delete_json(
        &client,
        &hub.url(&format!("/v1/auth/api-keys/{key_id}")),
        Some(&token),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = get_json(&client, &hub.url("/v1/auth/me"), Some(&token)).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn api_key_unknown_token_unauthorized() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (status, _) = get_json(
        &client,
        &hub.url("/v1/auth/me"),
        Some("twk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn api_key_revoke_scoped_to_owner() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let alice = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let bob = signup_and_login_user(&hub, &client, "bob@example.test", "hunter22!").await;

    let (_, alice_created) =
        create_api_key(&hub, &client, &alice, json!({"name": "alice-key"})).await;
    let alice_key_id = alice_created["id"].as_str().unwrap();

    let (_, bob_created) = create_api_key(&hub, &client, &bob, json!({"name": "bob-key"})).await;
    let bob_token = bob_created["token"].as_str().unwrap();

    // Bob cannot delete Alice's key — it's invisible to him.
    let (status, _) = delete_json(
        &client,
        &hub.url(&format!("/v1/auth/api-keys/{alice_key_id}")),
        Some(bob_token),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn api_key_with_expiry_is_accepted_and_set() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;

    let (status, created) = create_api_key(
        &hub,
        &client,
        &cookie,
        json!({"name": "ci", "expires_in_days": 30}),
    )
    .await;
    assert_eq!(status, 201);
    assert!(
        created["expires_at_ms"].as_i64().is_some(),
        "expiry should be set"
    );
    let token = created["token"].as_str().unwrap();
    let (status, _) = get_json(&client, &hub.url("/v1/auth/me"), Some(token)).await;
    assert_eq!(status, 200);

    // Out-of-range lifetimes are rejected.
    let (status, _) = create_api_key(
        &hub,
        &client,
        &cookie,
        json!({"name": "bad", "expires_in_days": 9999}),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn api_key_expired_is_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap().to_string();

    // Insert a key whose expiry is already in the past — it must not authenticate.
    let expired = crate::hub::auth::api_key::mint();
    hub.state
        .db
        .insert_api_key(crate::hub::db::api_keys::NewApiKey {
            id: "expired-key",
            user_id: &user_id,
            key_hash: &expired.key_hash,
            name: "expired",
            expires_at_ms: Some(1),
            now_ms: 1,
        })
        .await
        .unwrap();

    let (status, _) = get_json(&client, &hub.url("/v1/auth/me"), Some(&expired.token)).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn api_key_rejected_after_user_disabled() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "alice@example.test", "hunter22!").await;
    let me: Value = client
        .get(hub.url("/v1/auth/me"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["id"].as_str().unwrap().to_string();
    let (_, created) = create_api_key(&hub, &client, &cookie, json!({"name": "ci"})).await;
    let token = created["token"].as_str().unwrap().to_string();

    // Operator disables the account; the key must stop working.
    let (status, _) = post_json(
        &client,
        &hub.url(&format!("/v1/users/{user_id}/disable")),
        json!({}),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = get_json(&client, &hub.url("/v1/auth/me"), Some(&token)).await;
    assert_eq!(status, 401);
}
