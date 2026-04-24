#![allow(clippy::redundant_closure_for_method_calls, clippy::similar_names)]

use super::*;
use crate::config_entry::ConfigPayload;
use crate::identity::{AgentKeypair, TenantKeypair};

/// Build a policy that allows the given tenant all specified hostnames.
fn policy_for(kp: &TenantKeypair, hostnames: &[&str]) -> OwnershipPolicy {
    let mut policy = OwnershipPolicy::new();
    policy.register_tenant(
        &kp.id(),
        kp.public_key().clone(),
        hostnames.iter().map(|s| s.to_string()),
    );
    policy
}

fn register(policy: &mut OwnershipPolicy, kp: &TenantKeypair, hostnames: &[&str]) {
    policy.register_tenant(
        &kp.id(),
        kp.public_key().clone(),
        hostnames.iter().map(|s| s.to_string()),
    );
}

fn sign_entry(kp: &TenantKeypair, seq: u64, op: ConfigOp) -> SignedConfigEntry {
    let payload = ConfigPayload {
        version: 1,
        tenant_id: kp.id(),
        sequence: seq,
        timestamp: 1_700_000_000 + seq,
        op,
    };
    SignedConfigEntry::sign(&payload, kp).unwrap()
}

#[test]
fn empty_entries_produce_empty_table() {
    let policy = OwnershipPolicy::new();
    let table = RouteTable::from_entries(&[], &policy);
    assert!(table.is_empty());
}

#[test]
fn hostname_without_agent_produces_no_route() {
    let kp = TenantKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![sign_entry(
        &kp,
        1,
        ConfigOp::UpsertHostname {
            hostname: "app.example.eu".into(),
        },
    )];
    let table = RouteTable::from_entries(&entries, &policy);
    assert!(table.is_empty());
}

#[test]
fn hostname_plus_agent_produces_route() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert_eq!(table.len(), 1);
    let agents = table.lookup("app.example.eu").unwrap();
    assert!(agents.contains(&agent.id()));
}

#[test]
fn wildcard_lookup() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["*.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "*.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert!(table.lookup("app.example.eu").is_some());
    assert!(table.lookup("other.example.eu").is_some());
    assert!(table.lookup("example.eu").is_none());
}

#[test]
fn delete_hostname_removes_route() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::DeleteHostname {
                hostname: "app.example.eu".into(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert!(table.is_empty());
}

#[test]
fn live_agents_filter_hides_offline_agents() {
    let kp = TenantKeypair::generate();
    let live_agent = AgentKeypair::generate();
    let offline_agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);

    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: live_agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::UpsertAgent {
                agent_id: offline_agent.id(),
            },
        ),
    ];

    let mut live = HashSet::new();
    live.insert((kp.id(), live_agent.id()));

    let table = RouteTable::from_entries_with_liveness(&entries, &policy, Some(&live));
    let agents = table.lookup("app.example.eu").unwrap();
    assert!(agents.contains(&live_agent.id()));
    assert!(
        !agents.contains(&offline_agent.id()),
        "offline agent must be filtered out"
    );
    assert_eq!(agents.len(), 1);
}

#[test]
fn live_agents_empty_hides_all_routes() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];

    let empty = HashSet::new();
    let table = RouteTable::from_entries_with_liveness(&entries, &policy, Some(&empty));
    assert!(table.is_empty());
}

#[test]
fn live_agents_none_preserves_legacy_behavior() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];

    let table = RouteTable::from_entries_with_liveness(&entries, &policy, None);
    assert!(table.lookup("app.example.eu").is_some());
}

#[test]
fn revoke_agent_removes_from_routes() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::RevokeAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    // Hostname exists but no agents -> no route
    assert!(table.is_empty());
}

#[test]
fn multiple_tenants_isolated() {
    let kp1 = TenantKeypair::generate();
    let kp2 = TenantKeypair::generate();
    let agent1 = AgentKeypair::generate();
    let agent2 = AgentKeypair::generate();

    let mut policy = OwnershipPolicy::new();
    register(&mut policy, &kp1, &["alice.example.eu"]);
    register(&mut policy, &kp2, &["bob.example.eu"]);

    let entries = vec![
        sign_entry(
            &kp1,
            1,
            ConfigOp::UpsertHostname {
                hostname: "alice.example.eu".into(),
            },
        ),
        sign_entry(
            &kp1,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent1.id(),
            },
        ),
        sign_entry(
            &kp2,
            1,
            ConfigOp::UpsertHostname {
                hostname: "bob.example.eu".into(),
            },
        ),
        sign_entry(
            &kp2,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent2.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    let alice_agents = table.lookup("alice.example.eu").unwrap();
    assert!(alice_agents.contains(&agent1.id()));
    assert!(!alice_agents.contains(&agent2.id()));

    let bob_agents = table.lookup("bob.example.eu").unwrap();
    assert!(bob_agents.contains(&agent2.id()));
    assert!(!bob_agents.contains(&agent1.id()));
}

#[test]
fn two_tenants_same_hostname_second_rejected() {
    let kp1 = TenantKeypair::generate();
    let kp2 = TenantKeypair::generate();
    let agent1 = AgentKeypair::generate();
    let agent2 = AgentKeypair::generate();

    // Only kp1 is allowed to claim "shared.example.eu"
    let mut policy = OwnershipPolicy::new();
    register(&mut policy, &kp1, &["shared.example.eu"]);
    register(&mut policy, &kp2, &["bob.example.eu"]);

    let entries = vec![
        sign_entry(
            &kp1,
            1,
            ConfigOp::UpsertHostname {
                hostname: "shared.example.eu".into(),
            },
        ),
        sign_entry(
            &kp1,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent1.id(),
            },
        ),
        // kp2 tries to hijack the same hostname
        sign_entry(
            &kp2,
            1,
            ConfigOp::UpsertHostname {
                hostname: "shared.example.eu".into(),
            },
        ),
        sign_entry(
            &kp2,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent2.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    // kp1's route should be intact
    let agents = table.lookup("shared.example.eu").unwrap();
    assert!(agents.contains(&agent1.id()));
    // kp2's agent must NOT be serving this hostname
    assert!(!agents.contains(&agent2.id()));
}

#[test]
fn unknown_tenant_entries_skipped() {
    let known = TenantKeypair::generate();
    let unknown = TenantKeypair::generate();
    let agent_k = AgentKeypair::generate();
    let agent_u = AgentKeypair::generate();

    // Only `known` is in the policy
    let policy = policy_for(&known, &["app.example.eu"]);

    let entries = vec![
        sign_entry(
            &known,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &known,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent_k.id(),
            },
        ),
        sign_entry(
            &unknown,
            1,
            ConfigOp::UpsertHostname {
                hostname: "evil.example.eu".into(),
            },
        ),
        sign_entry(
            &unknown,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent_u.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    assert!(table.lookup("app.example.eu").is_some());
    assert!(table.lookup("evil.example.eu").is_none());
}

#[test]
fn hostname_outside_policy_rejected() {
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();

    // Tenant is only allowed "allowed.example.eu"
    let policy = policy_for(&kp, &["allowed.example.eu"]);

    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "allowed.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertHostname {
                hostname: "sneaky.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    assert!(table.lookup("allowed.example.eu").is_some());
    assert!(table.lookup("sneaky.example.eu").is_none());
}

#[test]
fn wildcard_is_single_level() {
    // *.example.eu matches app.example.eu but NOT deep.app.example.eu
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["*.example.eu"]);

    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "*.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    assert!(table.lookup("app.example.eu").is_some());
    assert!(
        table.lookup("deep.app.example.eu").is_none(),
        "wildcards are single-level"
    );
}

#[test]
fn lookup_with_tls_matches_lookup_plus_tls_mode() {
    use crate::tls_policy::TlsMode;

    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu", "*.bob.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertHostname {
                hostname: "*.bob.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            4,
            ConfigOp::SetHostnameTls {
                hostname: "*.bob.example.eu".into(),
                mode: TlsMode::Terminate,
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    let (agents, tls) = table.lookup_with_tls("APP.example.eu").unwrap();
    assert_eq!(agents, table.lookup("app.example.eu").unwrap());
    assert_eq!(tls, TlsMode::Passthrough);

    let (wagents, wtls) = table.lookup_with_tls("foo.bob.example.eu").unwrap();
    assert_eq!(wagents, table.lookup("foo.bob.example.eu").unwrap());
    assert_eq!(wtls, TlsMode::Terminate);

    assert!(table.lookup_with_tls("missing.example.eu").is_none());
}

#[test]
fn set_hostname_tls_populates_policy() {
    use crate::tls_policy::TlsMode;

    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["*.bob.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "*.bob.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::SetHostnameTls {
                hostname: "*.bob.example.eu".into(),
                mode: TlsMode::Terminate,
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert!(matches!(
        table.tls_mode("foo.bob.example.eu"),
        TlsMode::Terminate
    ));
    // Routes remain intact.
    assert!(table.lookup("foo.bob.example.eu").is_some());
}

#[test]
fn set_hostname_tls_rejected_for_unowned_hostname() {
    use crate::tls_policy::TlsMode;

    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["allowed.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "allowed.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::SetHostnameTls {
                hostname: "not-mine.example.eu".into(),
                mode: TlsMode::Terminate,
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert_eq!(
        table.tls_mode("not-mine.example.eu"),
        TlsMode::Passthrough,
        "TLS policy for unowned hostname must be ignored"
    );
}

#[test]
fn delete_hostname_clears_tls_policy() {
    use crate::tls_policy::TlsMode;

    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["app.example.eu"]);
    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "app.example.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
        sign_entry(
            &kp,
            3,
            ConfigOp::SetHostnameTls {
                hostname: "app.example.eu".into(),
                mode: TlsMode::Terminate,
            },
        ),
        sign_entry(
            &kp,
            4,
            ConfigOp::DeleteHostname {
                hostname: "app.example.eu".into(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);
    assert!(table.is_empty());
    assert_eq!(table.tls_mode("app.example.eu"), TlsMode::Passthrough);
}

#[test]
fn lookup_bare_tld_does_not_match_wildcard() {
    // A hostname with no dots (e.g. "eu") should not match any wildcard.
    let kp = TenantKeypair::generate();
    let agent = AgentKeypair::generate();
    let policy = policy_for(&kp, &["*.eu"]);

    let entries = vec![
        sign_entry(
            &kp,
            1,
            ConfigOp::UpsertHostname {
                hostname: "*.eu".into(),
            },
        ),
        sign_entry(
            &kp,
            2,
            ConfigOp::UpsertAgent {
                agent_id: agent.id(),
            },
        ),
    ];
    let table = RouteTable::from_entries(&entries, &policy);

    assert!(table.lookup("example.eu").is_some());
    assert!(
        table.lookup("eu").is_none(),
        "bare TLD with no dots must not match any wildcard"
    );
}
