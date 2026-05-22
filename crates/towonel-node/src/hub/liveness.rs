use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

use async_trait::async_trait;
use towonel_common::identity::{AgentId, TenantId};

#[async_trait]
pub trait LivenessStore: Send + Sync {
    async fn bump(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        now_ms: u64,
    ) -> anyhow::Result<()>;

    async fn live_agents(&self, cutoff_ms: u64) -> anyhow::Result<HashSet<(TenantId, AgentId)>>;

    async fn prune(&self, older_than_ms: u64) -> anyhow::Result<u64>;
}

#[derive(Default)]
pub struct InMemoryLivenessStore {
    inner: RwLock<HashMap<(TenantId, AgentId), u64>>,
}

impl InMemoryLivenessStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LivenessStore for InMemoryLivenessStore {
    async fn bump(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        {
            let mut guard = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.insert((*tenant_id, agent_id.clone()), now_ms);
        }
        Ok(())
    }

    async fn live_agents(&self, cutoff_ms: u64) -> anyhow::Result<HashSet<(TenantId, AgentId)>> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(guard
            .iter()
            .filter(|(_, last)| **last >= cutoff_ms)
            .map(|((t, a), _)| (*t, a.clone()))
            .collect())
    }

    async fn prune(&self, older_than_ms: u64) -> anyhow::Result<u64> {
        let removed = {
            let mut guard = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = guard.len();
            guard.retain(|_, last| *last >= older_than_ms);
            before.saturating_sub(guard.len())
        };
        Ok(u64::try_from(removed).unwrap_or(0))
    }
}

pub type SharedLivenessStore = Arc<dyn LivenessStore>;

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::identity::AgentKeypair;

    fn make_tenant() -> TenantId {
        TenantId::from_bytes(&[1u8; 32])
    }

    #[tokio::test]
    async fn bump_then_live_agents_respects_cutoff() {
        let store = InMemoryLivenessStore::new();
        let tenant = make_tenant();
        let a1 = AgentKeypair::generate().id();
        let a2 = AgentKeypair::generate().id();
        store.bump(&tenant, &a1, 100).await.unwrap();
        store.bump(&tenant, &a2, 500).await.unwrap();
        let live_recent = store.live_agents(400).await.unwrap();
        assert_eq!(live_recent.len(), 1);
        assert!(live_recent.contains(&(tenant, a2.clone())));
        let live_all = store.live_agents(0).await.unwrap();
        assert_eq!(live_all.len(), 2);
    }

    #[tokio::test]
    async fn prune_drops_stale_rows() {
        let store = InMemoryLivenessStore::new();
        let tenant = make_tenant();
        let a1 = AgentKeypair::generate().id();
        let a2 = AgentKeypair::generate().id();
        store.bump(&tenant, &a1, 100).await.unwrap();
        store.bump(&tenant, &a2, 500).await.unwrap();
        let pruned = store.prune(300).await.unwrap();
        assert_eq!(pruned, 1);
        let live = store.live_agents(0).await.unwrap();
        assert_eq!(live.len(), 1);
        assert!(live.contains(&(tenant, a2)));
    }
}
