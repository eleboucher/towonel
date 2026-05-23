use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use serde_json::{Value, json};
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::{AgentKeypair, TenantId, TenantKeypair};
use towonel_common::invite::{INVITE_ID_LEN, InviteToken};

use super::test_helpers::{
    OPERATOR_KEY, TestHub, create_invite, delete_json, get_json, post_json, tenant_from_token,
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
async fn prune_stale_liveness_drops_agent_from_route_table() {
    // Seed an agent as live, submit its UpsertAgent + UpsertHostname, verify
    // the route table includes it, then age its liveness row past the cutoff
    // and confirm a liveness-aware rebuild drops it.
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

    let now = towonel_common::time::now_ms();
    hub.state
        .liveness
        .bump(&tenant.id(), &agent.id(), now)
        .await
        .unwrap();
    super::api::rebuild_and_broadcast_routes(&hub.state)
        .await
        .unwrap();

    let live = hub.state.liveness.live_agents(0).await.unwrap();
    assert!(live.contains(&(tenant.id(), agent.id())));

    let ancient = now.saturating_sub(10 * 60 * 1_000);
    hub.state
        .liveness
        .bump(&tenant.id(), &agent.id(), ancient)
        .await
        .unwrap();
    let pruned = hub
        .state
        .liveness
        .prune(now.saturating_sub(5 * 60 * 1_000))
        .await
        .unwrap();
    assert_eq!(pruned, 1);

    let live_after = hub.state.liveness.live_agents(0).await.unwrap();
    assert!(!live_after.contains(&(tenant.id(), agent.id())));
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
