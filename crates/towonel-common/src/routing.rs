use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config_entry::{ConfigOp, SignedConfigEntry};
use crate::hostname::{ascii_lowercase_cow, wildcard_lookup_ascii_lower};
use crate::identity::{AgentId, TenantId};
use crate::ownership::OwnershipPolicy;
use crate::tls_policy::{TlsMode, TlsPolicyTable};

/// A materialized routing table: hostname -> set of agent IDs that serve it,
/// plus a parallel TLS policy table so edges can look up termination mode
/// on the hot path.
///
/// Serializes as canonical CBOR on the hub's `/v1/routes/subscribe` SSE
/// stream, so an edge-only node can apply snapshots pushed by a remote hub.
/// `tls_policies` is `#[serde(default)]` for wire compatibility with older
/// hubs/edges that predate per-hostname TLS config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteTable {
    routes: HashMap<String, HashSet<AgentId>>,
    #[serde(default, skip_serializing_if = "TlsPolicyTable::is_empty")]
    tls_policies: TlsPolicyTable,
    /// `#[serde(default)]` keeps the wire format compatible with edges and
    /// hubs that predate TCP service forwarding.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    tcp_routes: HashMap<TcpRouteKey, HashSet<AgentId>>,
    /// `BTreeMap` so the edge reconciler iterates in deterministic port order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tcp_listeners: BTreeMap<u16, TcpListenerBinding>,
}

/// Struct rather than a `(TenantId, String)` tuple so the CBOR wire form has
/// stable named fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpRouteKey {
    pub tenant: TenantId,
    pub service: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpListenerBinding {
    pub tenant: TenantId,
    pub service: String,
}

impl RouteTable {
    /// Materialize a route table by replaying signed config entries in order.
    ///
    /// Entries must be pre-sorted by (`tenant_id`, sequence). Each entry is
    /// verified before being applied -- entries with invalid signatures are
    /// logged and skipped. The `policy` enforces which tenants and hostnames
    /// are allowed.
    #[must_use]
    pub fn from_entries(entries: &[SignedConfigEntry], policy: &OwnershipPolicy) -> Self {
        Self::from_entries_with_liveness(entries, policy, None)
    }

    /// Same as [`Self::from_entries`] but intersects each tenant's agent set
    /// with `live_agents` before materialization. Agents missing from
    /// `live_agents` are treated as unreachable and their routes suppressed.
    /// Pass `None` to disable liveness filtering.
    #[must_use]
    pub fn from_entries_with_liveness(
        entries: &[SignedConfigEntry],
        policy: &OwnershipPolicy,
        live_agents: Option<&HashSet<(TenantId, AgentId)>>,
    ) -> Self {
        let mut tenant_state: HashMap<TenantId, TenantState> = HashMap::new();

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

            let state = tenant_state.entry(payload.tenant_id).or_default();

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
                    let key = hostname.to_lowercase();
                    state.hostnames.remove(&key);
                    state.tls.remove(&key);
                }
                ConfigOp::UpsertAgent { agent_id } => {
                    state.agents.insert(agent_id.clone());
                }
                ConfigOp::RevokeAgent { agent_id } => {
                    state.agents.remove(agent_id);
                }
                ConfigOp::SetHostnameTls { hostname, mode } => {
                    if policy.is_hostname_allowed(&payload.tenant_id, hostname) {
                        state.tls.insert(hostname.to_lowercase(), *mode);
                    } else {
                        tracing::warn!(
                            tenant = %payload.tenant_id,
                            %hostname,
                            "skipping unauthorized TLS policy"
                        );
                    }
                }
                ConfigOp::UpsertTcpService {
                    service,
                    listen_port,
                } => {
                    state.tcp_services.insert(service.clone(), *listen_port);
                }
                ConfigOp::DeleteTcpService { service } => {
                    state.tcp_services.remove(service);
                }
            }
        }

        let mut routes: HashMap<String, HashSet<AgentId>> = HashMap::new();
        let mut tls_policies = TlsPolicyTable::new();
        let mut tcp_routes: HashMap<TcpRouteKey, HashSet<AgentId>> = HashMap::new();
        let mut tcp_listeners: BTreeMap<u16, TcpListenerBinding> = BTreeMap::new();

        // Sort tenants so cross-tenant port collisions resolve deterministically
        // (lowest `tenant_id` wins). HashMap iteration is randomized.
        let mut sorted_tenants: Vec<&TenantId> = tenant_state.keys().collect();
        sorted_tenants.sort_by_key(|t| *t.as_bytes());

        for tenant_id in sorted_tenants {
            let state = &tenant_state[tenant_id];
            materialize_tenant(
                tenant_id,
                state,
                live_agents,
                &mut routes,
                &mut tls_policies,
                &mut tcp_routes,
                &mut tcp_listeners,
            );
        }

        Self {
            routes,
            tls_policies,
            tcp_routes,
            tcp_listeners,
        }
    }

    /// Borrow the TLS policy table for in-process lookups on the edge.
    #[must_use]
    pub const fn tls_policies(&self) -> &TlsPolicyTable {
        &self.tls_policies
    }

    /// Look up the TLS mode for a hostname (exact or wildcard); missing
    /// entries default to `Passthrough`.
    #[must_use]
    pub fn tls_mode(&self, hostname: &str) -> TlsMode {
        self.tls_policies.lookup(hostname)
    }

    /// Look up which agents serve a hostname.
    ///
    /// Tries exact match first, then a single-level wildcard: `*.example.eu`
    /// matches `app.example.eu` but **not** `deep.app.example.eu`. Only the
    /// first label (before the first dot) is replaced by `*`.
    #[must_use]
    pub fn lookup(&self, hostname: &str) -> Option<&HashSet<AgentId>> {
        crate::hostname::wildcard_lookup(hostname, |key| {
            self.routes.get(key).filter(|a| !a.is_empty())
        })
    }

    /// Combined `lookup` + TLS-mode resolution that shares a single
    /// ASCII-lowercase allocation across both hot-path probes. Preserves the
    /// independent wildcard semantics (each table is probed with its own
    /// exact-then-wildcard order).
    #[must_use]
    pub fn lookup_with_tls(&self, hostname: &str) -> Option<(&HashSet<AgentId>, TlsMode)> {
        let lower = ascii_lowercase_cow(hostname);
        let agents = wildcard_lookup_ascii_lower(&lower, |key| {
            self.routes.get(key).filter(|a| !a.is_empty())
        })?;
        let tls = self.tls_policies.lookup_ascii_lower(&lower);
        Some((agents, tls))
    }

    /// Build a route table from a pre-computed map (e.g. from TOML config).
    ///
    /// Use this when you already have the final hostname->agents mapping and
    /// don't need to replay signed config entries. Ownership is already
    /// enforced by the TOML structure itself.
    #[must_use]
    pub fn from_raw(routes: HashMap<String, HashSet<AgentId>>) -> Self {
        Self {
            routes,
            tls_policies: TlsPolicyTable::new(),
            tcp_routes: HashMap::new(),
            tcp_listeners: BTreeMap::new(),
        }
    }

    /// Service names are exact-match — no wildcards (unlike `lookup`).
    #[must_use]
    pub fn lookup_tcp_service(
        &self,
        tenant: &TenantId,
        service: &str,
    ) -> Option<&HashSet<AgentId>> {
        let key = TcpRouteKey {
            tenant: *tenant,
            service: service.to_string(),
        };
        self.tcp_routes.get(&key).filter(|a| !a.is_empty())
    }

    #[must_use]
    pub const fn tcp_listeners(&self) -> &BTreeMap<u16, TcpListenerBinding> {
        &self.tcp_listeners
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
    #[must_use]
    pub fn hostnames(&self) -> HashSet<String> {
        self.routes
            .iter()
            .filter(|(_, agents)| !agents.is_empty())
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Every unique agent that serves at least one hostname or TCP service.
    #[must_use]
    pub fn unique_agents(&self) -> HashSet<&AgentId> {
        self.routes
            .values()
            .flatten()
            .chain(self.tcp_routes.values().flatten())
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn materialize_tenant(
    tenant_id: &TenantId,
    state: &TenantState,
    live_agents: Option<&HashSet<(TenantId, AgentId)>>,
    routes: &mut HashMap<String, HashSet<AgentId>>,
    tls_policies: &mut TlsPolicyTable,
    tcp_routes: &mut HashMap<TcpRouteKey, HashSet<AgentId>>,
    tcp_listeners: &mut BTreeMap<u16, TcpListenerBinding>,
) {
    // Only allocate a new set when filtering; the `None` path reuses the
    // existing set by reference. `agents_ref` points at whichever.
    let filtered: Option<HashSet<AgentId>> = live_agents.map(|live| {
        state
            .agents
            .iter()
            .filter(|a| live.contains(&(*tenant_id, (*a).clone())))
            .cloned()
            .collect()
    });
    let agents_ref: &HashSet<AgentId> = filtered.as_ref().unwrap_or(&state.agents);

    if agents_ref.is_empty() {
        return;
    }
    for hostname in &state.hostnames {
        routes.insert(hostname.clone(), agents_ref.clone());
        if let Some(mode) = state.tls.get(hostname) {
            tls_policies.insert(hostname.clone(), *mode);
        }
    }
    for (service, listen_port) in &state.tcp_services {
        tcp_routes.insert(
            TcpRouteKey {
                tenant: *tenant_id,
                service: service.clone(),
            },
            agents_ref.clone(),
        );
        // First-claim-wins is a backstop: the hub already enforces port
        // uniqueness at insert time.
        tcp_listeners
            .entry(*listen_port)
            .or_insert_with(|| TcpListenerBinding {
                tenant: *tenant_id,
                service: service.clone(),
            });
    }
}

/// Per-tenant state accumulated while replaying config entries.
#[derive(Default)]
struct TenantState {
    hostnames: HashSet<String>,
    agents: HashSet<AgentId>,
    tls: HashMap<String, TlsMode>,
    /// `service_name -> listen_port`, last-write-wins per service.
    tcp_services: HashMap<String, u16>,
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
