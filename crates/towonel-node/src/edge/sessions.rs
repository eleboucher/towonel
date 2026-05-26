use std::sync::Arc;

use iroh::EndpointId;
use iroh::endpoint::Connection;
use tracing::{debug, info};

use towonel_common::identity::TenantId;

use super::health::EdgeMetrics;

pub struct AgentSession {
    pub agent_id: EndpointId,
    conn: Connection,
}

impl AgentSession {
    #[must_use]
    pub const fn new(agent_id: EndpointId, conn: Connection) -> Self {
        Self { agent_id, conn }
    }

    pub async fn open_stream(
        &self,
    ) -> Result<
        (iroh::endpoint::SendStream, iroh::endpoint::RecvStream),
        iroh::endpoint::ConnectionError,
    > {
        self.conn.open_bi().await
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    pub fn conn_stable_id(&self) -> usize {
        self.conn.stable_id()
    }
}

pub struct SessionRegistry {
    by_id: papaya::HashMap<EndpointId, Arc<AgentSession>>,
    /// Populated after the hub verifies the agent's `EdgeCred`.
    tenants: papaya::HashMap<EndpointId, TenantId>,
    metrics: EdgeMetrics,
}

impl SessionRegistry {
    #[must_use]
    pub fn new(metrics: EdgeMetrics) -> Self {
        Self {
            by_id: papaya::HashMap::new(),
            tenants: papaya::HashMap::new(),
            metrics,
        }
    }

    pub fn record_tenant(&self, agent_id: EndpointId, tenant_id: TenantId) {
        self.tenants.pin().insert(agent_id, tenant_id);
    }

    #[must_use]
    pub fn tenant_for(&self, agent_id: &EndpointId) -> Option<TenantId> {
        self.tenants.pin().get(agent_id).copied()
    }

    pub fn register(&self, session: &Arc<AgentSession>) {
        let agent_id = session.agent_id;
        // pin() returns a guard that must outlive the value insert() returns.
        let map = self.by_id.pin();
        let previous = map.insert(agent_id, Arc::clone(session));
        match previous {
            Some(old) => {
                debug!(agent = %agent_id.fmt_short(), "superseding previous session");
                old.close(0, b"superseded");
                // active_sessions stays flat on supersede: -1 + 1.
            }
            None => {
                self.metrics.active_sessions.inc();
            }
        }
        self.metrics.sessions_total.inc();
        info!(agent = %agent_id.fmt_short(), "agent session registered");
    }

    /// Only remove if the registered entry's `stable_id` still matches; a
    /// stale handler task must not evict a fresh reconnection.
    pub fn remove_if_current(&self, session: &AgentSession) {
        let agent_id = session.agent_id;
        let stable_id = session.conn_stable_id();
        let map = self.by_id.pin();
        let result = map.remove_if(&agent_id, |_, current| {
            current.conn_stable_id() == stable_id
        });
        match result {
            Ok(Some(_)) => {
                self.metrics.active_sessions.dec();
                self.tenants.pin().remove(&agent_id);
                info!(agent = %agent_id.fmt_short(), "agent session removed");
            }
            Ok(None) | Err(_) => {
                debug!(agent = %agent_id.fmt_short(), "session already replaced; not removing");
            }
        }
    }

    #[must_use]
    pub fn get(&self, agent_id: &EndpointId) -> Option<Arc<AgentSession>> {
        self.by_id.pin().get(agent_id).cloned()
    }

    /// Pairs each registered agent with its verified tenant; agents whose
    /// `EdgeCred` exchange hasn't completed are skipped.
    #[must_use]
    pub fn active_with_tenant(&self) -> Vec<(EndpointId, TenantId)> {
        let tenants = self.tenants.pin();
        self.by_id
            .pin()
            .iter()
            .filter_map(|(agent_id, _)| tenants.get(agent_id).map(|t| (*agent_id, *t)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::EndpointAddr;
    use iroh::endpoint::{Endpoint, presets::N0DisableRelay};
    use towonel_common::protocol::ALPN_TUNNEL;

    use super::*;

    async fn make_endpoints() -> (Endpoint, Endpoint, EndpointAddr) {
        let edge_ep = Endpoint::builder(N0DisableRelay)
            .alpns(vec![ALPN_TUNNEL.to_vec()])
            .bind()
            .await
            .expect("edge bind");
        let agent_ep = Endpoint::builder(N0DisableRelay)
            .bind()
            .await
            .expect("agent bind");

        let mut edge_addr = EndpointAddr::new(edge_ep.id());
        for sock in &edge_ep.bound_sockets() {
            let reachable = if sock.ip().is_unspecified() {
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), sock.port())
            } else {
                *sock
            };
            edge_addr = edge_addr.with_ip_addr(reachable);
        }
        (edge_ep, agent_ep, edge_addr)
    }

    fn spawn_accept_loop(edge_ep: Endpoint, registry: Arc<SessionRegistry>) {
        tokio::spawn(async move {
            while let Some(incoming) = edge_ep.accept().await {
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let agent_id = conn.remote_id();
                    let session = Arc::new(AgentSession::new(agent_id, conn.clone()));
                    registry.register(&session);
                    let _ = conn.closed().await;
                    registry.remove_if_current(&session);
                });
            }
        });
    }

    #[tokio::test]
    async fn register_then_remove_on_close() {
        let registry = Arc::new(SessionRegistry::new(EdgeMetrics::new()));
        let (edge_ep, agent_ep, edge_addr) = make_endpoints().await;
        let agent_id = agent_ep.id();

        spawn_accept_loop(edge_ep.clone(), Arc::clone(&registry));

        let conn = agent_ep
            .connect(edge_addr, ALPN_TUNNEL)
            .await
            .expect("agent connect to edge");

        // Wait for registration to propagate.
        for _ in 0..100 {
            if registry.get(&agent_id).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            registry.get(&agent_id).is_some(),
            "agent did not register within timeout"
        );

        conn.close(0u32.into(), b"bye");
        agent_ep.close().await;

        for _ in 0..100 {
            if registry.get(&agent_id).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            registry.get(&agent_id).is_none(),
            "session was not removed after connection close"
        );

        edge_ep.close().await;
    }

    #[tokio::test]
    async fn duplicate_register_supersedes_previous() {
        let registry = Arc::new(SessionRegistry::new(EdgeMetrics::new()));
        let (edge_ep, agent_ep, edge_addr) = make_endpoints().await;
        let agent_id = agent_ep.id();

        spawn_accept_loop(edge_ep.clone(), Arc::clone(&registry));

        let conn1 = agent_ep
            .connect(edge_addr.clone(), ALPN_TUNNEL)
            .await
            .expect("first connect");

        // Wait for the first session to appear.
        for _ in 0..100 {
            if registry.get(&agent_id).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let first = registry.get(&agent_id).expect("first session registered");
        let first_id = first.conn_stable_id();
        drop(first);

        let conn2 = agent_ep
            .connect(edge_addr, ALPN_TUNNEL)
            .await
            .expect("second connect");

        for _ in 0..100 {
            if let Some(s) = registry.get(&agent_id)
                && s.conn_stable_id() != first_id
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let second = registry.get(&agent_id).expect("second session registered");
        assert_ne!(
            second.conn_stable_id(),
            first_id,
            "registry should hold the new connection after supersede"
        );

        conn2.close(0u32.into(), b"bye");
        // conn1 was already closed by the supersede.
        drop(conn1);
        agent_ep.close().await;
        edge_ep.close().await;
    }

    #[tokio::test]
    async fn remove_if_current_no_op_when_superseded() {
        let registry = Arc::new(SessionRegistry::new(EdgeMetrics::new()));
        let (edge_ep, agent_ep, edge_addr) = make_endpoints().await;
        let agent_id = agent_ep.id();

        spawn_accept_loop(edge_ep.clone(), Arc::clone(&registry));

        let conn1 = agent_ep
            .connect(edge_addr.clone(), ALPN_TUNNEL)
            .await
            .expect("first connect");
        for _ in 0..100 {
            if registry.get(&agent_id).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stale = registry.get(&agent_id).expect("first session");

        let conn2 = agent_ep
            .connect(edge_addr, ALPN_TUNNEL)
            .await
            .expect("second connect");
        for _ in 0..100 {
            if let Some(s) = registry.get(&agent_id)
                && s.conn_stable_id() != stale.conn_stable_id()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let fresh_id = registry
            .get(&agent_id)
            .expect("second session")
            .conn_stable_id();

        // Old handler running remove_if_current on its stale session must
        // not evict the fresh entry.
        registry.remove_if_current(&stale);

        let after = registry
            .get(&agent_id)
            .expect("fresh session should still be registered");
        assert_eq!(after.conn_stable_id(), fresh_id);

        conn2.close(0u32.into(), b"bye");
        drop(conn1);
        drop(stale);
        agent_ep.close().await;
        edge_ep.close().await;
    }
}
