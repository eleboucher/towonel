use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use iroh::{EndpointAddr, EndpointId};
use tracing::warn;

use towonel_common::identity::AgentId;
use towonel_common::routing::RouteTable;
use towonel_common::tls_policy::TlsMode;

use crate::config::TenantEntry;

/// Thin adapter around [`RouteTable`] that provides lock-free reads on the
/// hot path and converts between domain types ([`AgentId`]) and transport
/// types ([`EndpointId`]).
pub struct Router {
    /// The materialized routing table plus its TLS policies. Swapped atomically
    /// on config reload; hot-path reads are wait-free.
    table: ArcSwap<RouteTable>,
    /// Optional direct socket addresses per agent `EndpointId`, used when relay
    /// discovery is unavailable (e.g. Docker e2e tests). Populated at startup
    /// from TOML config and never changed at runtime.
    direct_addrs: HashMap<AgentId, Vec<SocketAddr>>,
}

impl Router {
    /// Build a routing table from the TOML tenant config.
    ///
    /// For each tenant, parses the hex-encoded agent `EndpointIds` and maps every
    /// hostname pattern to those agents. Produces a [`RouteTable`] internally.
    /// Also parses optional `direct_addresses` for Docker/e2e environments.
    pub fn load_from_config(tenants: &[TenantEntry]) -> anyhow::Result<Self> {
        let mut routes: HashMap<String, HashSet<AgentId>> = HashMap::new();
        let mut direct_addrs: HashMap<AgentId, Vec<SocketAddr>> = HashMap::new();

        for tenant in tenants {
            let mut agent_ids = Vec::with_capacity(tenant.agent_node_ids.len());
            for hex_id in &tenant.agent_node_ids {
                let agent_id: AgentId = hex_id
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid agent_node_id {hex_id}: {e}"))?;
                agent_ids.push(agent_id);
            }

            if agent_ids.is_empty() {
                warn!(tenant = %tenant.name, "tenant has no agent_node_ids configured, skipping");
                continue;
            }

            let parsed_addrs: Vec<SocketAddr> = tenant
                .direct_addresses
                .iter()
                .filter_map(|s| match s.parse::<SocketAddr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        warn!(addr = %s, error = %e, "invalid direct_address, skipping");
                        None
                    }
                })
                .collect();

            if !parsed_addrs.is_empty() {
                for agent_id in &agent_ids {
                    direct_addrs
                        .entry(agent_id.clone())
                        .or_default()
                        .extend(parsed_addrs.iter().copied());
                }
            }

            for hostname in &tenant.hostnames {
                let key = hostname.to_lowercase();
                routes
                    .entry(key)
                    .or_default()
                    .extend(agent_ids.iter().cloned());
            }
        }

        let table = RouteTable::from_raw(routes);
        Ok(Self {
            table: ArcSwap::from_pointee(table),
            direct_addrs,
        })
    }

    /// Replace the entire routing table (and its derived TLS policies).
    ///
    /// Used by the dynamic config sync: the hub builds a [`RouteTable`] from
    /// signed config entries (including `SetHostnameTls` ops) and broadcasts
    /// it to the edge. Hot-path readers see the swap atomically without
    /// blocking.
    pub fn replace(&self, new_table: RouteTable) {
        self.table.store(Arc::new(new_table));
    }

    /// Look up agents and TLS mode for a hostname in a single pass. Missing
    /// TLS entries default to `Passthrough`. Returns `None` when no route
    /// matches the hostname.
    #[must_use]
    pub fn route(&self, hostname: &str) -> Option<(Vec<EndpointAddr>, TlsMode)> {
        let table = self.table.load();
        let agents = table.lookup(hostname)?;
        let addrs = self.agents_to_addrs(agents)?;
        Some((addrs, table.tls_mode(hostname)))
    }

    fn agents_to_addrs(&self, agents: &HashSet<AgentId>) -> Option<Vec<EndpointAddr>> {
        let addrs: Vec<EndpointAddr> = agents
            .iter()
            .filter_map(|aid| {
                let eid = EndpointId::from_bytes(aid.as_bytes()).ok()?;
                let mut addr = EndpointAddr::new(eid);
                if let Some(sockets) = self.direct_addrs.get(aid) {
                    for sock in sockets {
                        addr = addr.with_ip_addr(*sock);
                    }
                }
                Some(addr)
            })
            .collect();
        (!addrs.is_empty()).then_some(addrs)
    }
}

#[cfg(test)]
#[allow(clippy::doc_markdown)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    /// Derive a valid hex-encoded EndpointId from a seed byte.
    /// Different seeds produce different valid Ed25519 public keys.
    fn agent_hex_from_seed(seed: u8) -> String {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        let secret = SecretKey::from(key_bytes);
        hex::encode(secret.public().as_bytes())
    }

    fn make_tenant(name: &str, hostnames: Vec<&str>, agent_hex: Vec<&str>) -> TenantEntry {
        TenantEntry {
            id: agent_hex_from_seed(1), // doesn't matter, just needs to be present
            // Edge-only code path: the edge routes by agent_node_ids, not by
            // cryptographic identity, so the pq_public_key field is not
            // consulted here. Leave empty.
            pq_public_key: String::new(),
            name: name.to_string(),
            hostnames: hostnames.into_iter().map(String::from).collect(),
            agent_node_ids: agent_hex.into_iter().map(String::from).collect(),
            direct_addresses: Vec::new(),
        }
    }

    #[tokio::test]
    async fn exact_match() {
        let hex_id = agent_hex_from_seed(1);
        let tenant = make_tenant("test", vec!["app.example.com"], vec![&hex_id]);
        let router = Router::load_from_config(&[tenant]).unwrap();

        let result = router.route("app.example.com").map(|(addrs, _)| addrs);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn wildcard_match() {
        let hex_id = agent_hex_from_seed(1);
        let tenant = make_tenant("test", vec!["*.example.com"], vec![&hex_id]);
        let router = Router::load_from_config(&[tenant]).unwrap();

        let result = router.route("app.example.com").map(|(addrs, _)| addrs);
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn no_match_returns_none() {
        let hex_id = agent_hex_from_seed(1);
        let tenant = make_tenant("test", vec!["other.com"], vec![&hex_id]);
        let router = Router::load_from_config(&[tenant]).unwrap();

        let result = router.route("app.example.com").map(|(addrs, _)| addrs);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn case_insensitive_lookup() {
        let hex_id = agent_hex_from_seed(1);
        let tenant = make_tenant("test", vec!["App.Example.COM"], vec![&hex_id]);
        let router = Router::load_from_config(&[tenant]).unwrap();

        let result = router.route("app.example.com").map(|(addrs, _)| addrs);
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn tenant_without_agents_is_skipped() {
        let tenant = make_tenant("empty", vec!["app.example.com"], vec![]);
        let router = Router::load_from_config(&[tenant]).unwrap();

        let result = router.route("app.example.com").map(|(addrs, _)| addrs);
        assert!(result.is_none());
    }
}
