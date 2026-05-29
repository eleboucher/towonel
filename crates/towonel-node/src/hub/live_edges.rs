use std::collections::HashMap;
use std::sync::RwLock;
use towonel_common::edge_link::EdgeCapabilities;

pub type EdgeId = [u8; 32];

/// One entry from [`LiveEdges::snapshot`]: edge id, iroh endpoints,
/// capabilities, public IPs, and the region it serves.
pub type EdgeSnapshot = (
    EdgeId,
    Vec<String>,
    EdgeCapabilities,
    Vec<String>,
    Option<String>,
);

#[derive(Clone, Debug)]
pub struct LiveEdge {
    pub iroh_endpoints: Vec<String>,
    pub capabilities: EdgeCapabilities,
    pub public_ips: Vec<String>,
    /// Region this edge serves. `None` from a pre-v5 edge.
    pub region: Option<String>,
    #[expect(dead_code, reason = "janitor sweep lands with the durable store")]
    pub last_seen_ms: u64,
}

#[derive(Default)]
pub struct LiveEdges {
    inner: RwLock<HashMap<EdgeId, LiveEdge>>,
}

impl LiveEdges {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(
        &self,
        id: EdgeId,
        iroh_endpoints: Vec<String>,
        capabilities: EdgeCapabilities,
        public_ips: Vec<String>,
        region: Option<String>,
        now_ms: u64,
    ) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(
            id,
            LiveEdge {
                iroh_endpoints,
                capabilities,
                public_ips,
                region,
                last_seen_ms: now_ms,
            },
        );
    }

    pub fn remove(&self, id: &EdgeId) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(id);
    }

    pub fn snapshot(&self) -> Vec<EdgeSnapshot> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .iter()
            .map(|(id, edge)| {
                (
                    *id,
                    edge.iroh_endpoints.clone(),
                    edge.capabilities.clone(),
                    edge.public_ips.clone(),
                    edge.region.clone(),
                )
            })
            .collect()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_then_snapshot() {
        let live = LiveEdges::new();
        live.upsert(
            [1u8; 32],
            vec!["1.2.3.4:51820".into()],
            EdgeCapabilities::default(),
            vec!["1.2.3.4".into()],
            Some("EU".into()),
            100,
        );
        live.upsert(
            [2u8; 32],
            vec!["5.6.7.8:51820".into()],
            EdgeCapabilities::default(),
            vec!["5.6.7.8".into()],
            Some("CA".into()),
            200,
        );
        let mut snap = live.snapshot();
        snap.sort_by_key(|(id, _, _, _, _)| *id);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].0, [1u8; 32]);
        assert_eq!(snap[1].0, [2u8; 32]);
    }

    #[test]
    fn remove_takes_edge_offline() {
        let live = LiveEdges::new();
        live.upsert(
            [3u8; 32],
            vec!["x:1".into()],
            EdgeCapabilities::default(),
            vec![],
            None,
            1,
        );
        assert!(!live.is_empty());
        live.remove(&[3u8; 32]);
        assert!(live.is_empty());
    }
}
