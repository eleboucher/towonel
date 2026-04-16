use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config_entry::{ConfigOp, SignedConfigEntry};
use crate::identity::AgentId;
use crate::ownership::OwnershipPolicy;

/// A materialized routing table: hostname -> set of agent IDs that serve it.
///
/// This is the domain-level route table. Adapters (iroh, etc.) convert
/// `AgentId` to their transport-specific peer identifiers.
///
/// Serializes as canonical CBOR on the hub's `/v1/routes/subscribe` SSE
/// stream, so an edge-only node can apply snapshots pushed by a remote hub.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteTable {
    routes: HashMap<String, HashSet<AgentId>>,
}

impl RouteTable {
    /// Materialize a route table by replaying signed config entries in order.
    ///
    /// Entries must be pre-sorted by (tenant_id, sequence). Each entry is
    /// verified before being applied -- entries with invalid signatures are
    /// logged and skipped. The `policy` enforces which tenants and hostnames
    /// are allowed.
    pub fn from_entries(entries: &[SignedConfigEntry], policy: &OwnershipPolicy) -> Self {
        let mut tenant_state: HashMap<String, TenantState> = HashMap::new();

        for entry in entries {
            let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
                tracing::debug!(
                    tenant = %entry.tenant_id,
                    "skipping entry for tenant not in ownership policy"
                );
                continue;
            };

            let payload = match entry.verify(pq_pubkey) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        tenant = %entry.tenant_id,
                        error = %e,
                        "skipping entry with invalid signature"
                    );
                    continue;
                }
            };

            let key = payload.tenant_id.to_string();
            let state = tenant_state.entry(key).or_default();

            match &payload.op {
                ConfigOp::UpsertHostname { hostname } => {
                    if policy.is_hostname_allowed(&payload.tenant_id, hostname) {
                        state.hostnames.insert(hostname.to_lowercase());
                    } else {
                        tracing::warn!(
                            tenant = %payload.tenant_id,
                            %hostname,
                            "skipping unauthorized hostname claim"
                        );
                    }
                }
                ConfigOp::DeleteHostname { hostname } => {
                    state.hostnames.remove(&hostname.to_lowercase());
                }
                ConfigOp::UpsertAgent { agent_id } => {
                    state.agents.insert(agent_id.clone());
                }
                ConfigOp::RevokeAgent { agent_id } => {
                    state.agents.remove(agent_id);
                }
            }
        }

        let mut routes: HashMap<String, HashSet<AgentId>> = HashMap::new();
        for state in tenant_state.values() {
            if state.agents.is_empty() {
                continue;
            }
            for hostname in &state.hostnames {
                routes.insert(hostname.clone(), state.agents.clone());
            }
        }

        Self { routes }
    }

    /// Look up which agents serve a hostname.
    ///
    /// Tries exact match first, then a single-level wildcard: `*.example.eu`
    /// matches `app.example.eu` but **not** `deep.app.example.eu`. Only the
    /// first label (before the first dot) is replaced by `*`.
    pub fn lookup(&self, hostname: &str) -> Option<&HashSet<AgentId>> {
        let lower = hostname.to_lowercase();

        if let Some(agents) = self.routes.get(&lower).filter(|a| !a.is_empty()) {
            return Some(agents);
        }

        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            if let Some(agents) = self.routes.get(&wildcard).filter(|a| !a.is_empty()) {
                return Some(agents);
            }
        }

        None
    }

    /// Build a route table from a pre-computed map (e.g. from TOML config).
    ///
    /// Use this when you already have the final hostname->agents mapping and
    /// don't need to replay signed config entries. Ownership is already
    /// enforced by the TOML structure itself.
    pub fn from_raw(routes: HashMap<String, HashSet<AgentId>>) -> Self {
        Self { routes }
    }

    /// Check if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Number of hostname entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// All hostnames with at least one agent.
    pub fn hostnames(&self) -> HashSet<String> {
        self.routes
            .iter()
            .filter(|(_, agents)| !agents.is_empty())
            .map(|(h, _)| h.clone())
            .collect()
    }
}

/// Per-tenant state accumulated while replaying config entries.
#[derive(Default)]
struct TenantState {
    hostnames: HashSet<String>,
    agents: HashSet<AgentId>,
}

#[cfg(test)]
mod tests {
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

    // --- Security tests ---

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
}
