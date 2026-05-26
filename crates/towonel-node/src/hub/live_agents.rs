//! Presence-based agent liveness keyed per source edge. An agent is live
//! iff at least one edge currently reports an active QUIC session for it.
//! Per-source keying refcounts multi-edge same-agent and lets us drop an
//! edge's whole set in one call when its `edge_link` disappears.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use towonel_common::identity::{AgentId, TenantId};

use super::live_edges::EdgeId;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceKey {
    Local,
    Remote(EdgeId),
}

type LiveSet = HashSet<(TenantId, AgentId)>;

#[derive(Default)]
pub struct LiveAgents {
    by_source: RwLock<HashMap<SourceKey, LiveSet>>,
}

impl LiveAgents {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` iff this is the first source to hold the key — i.e.
    /// the global live set just gained it. Callers gate rebuilds on this.
    pub fn record_added(&self, src: SourceKey, tenant: TenantId, agent: AgentId) -> bool {
        let key = (tenant, agent);
        let mut guard = self
            .by_source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_live = guard.iter().any(|(k, set)| *k != src && set.contains(&key));
        let inserted = guard.entry(src).or_default().insert(key);
        drop(guard);
        inserted && !already_live
    }

    /// Returns `true` iff this drops the key from the global live set
    /// (no other source still holds it).
    pub fn record_removed(&self, src: SourceKey, tenant: TenantId, agent: AgentId) -> bool {
        let key = (tenant, agent);
        let mut guard = self
            .by_source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = guard.get_mut(&src).is_some_and(|set| set.remove(&key));
        let any_other = removed && guard.iter().any(|(k, set)| *k != src && set.contains(&key));
        drop(guard);
        removed && !any_other
    }

    /// Atomically replaces `src`'s set. Returns `true` iff the global live
    /// set changed. Driven by `SessionsSnapshot` on edge (re)connect.
    pub fn replace(
        &self,
        src: SourceKey,
        sessions: impl IntoIterator<Item = (TenantId, AgentId)>,
    ) -> bool {
        let new_set: LiveSet = sessions.into_iter().collect();
        let mut guard = self
            .by_source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = guard.insert(src, new_set.clone()).unwrap_or_default();
        let added_globally = new_set
            .difference(&prev)
            .any(|key| !guard.iter().any(|(k, set)| *k != src && set.contains(key)));
        let removed_globally = !added_globally
            && prev
                .difference(&new_set)
                .any(|key| !guard.iter().any(|(k, set)| *k != src && set.contains(key)));
        drop(guard);
        added_globally || removed_globally
    }

    /// Drops `src`'s entire set. Returns `true` iff anything left the global
    /// live set (an entry not also held by another source).
    pub fn drop_source(&self, src: SourceKey) -> bool {
        let mut guard = self
            .by_source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(removed) = guard.remove(&src) else {
            return false;
        };
        let changed = removed
            .into_iter()
            .any(|key| !guard.iter().any(|(_, set)| set.contains(&key)));
        drop(guard);
        changed
    }

    /// `SessionRemoved` only carries the agent id on the wire; recover the
    /// tenant from the source's set populated by prior `SessionAdded`s.
    #[must_use]
    pub fn tenant_of(&self, src: SourceKey, agent: &AgentId) -> Option<TenantId> {
        let guard = self
            .by_source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let found = guard
            .get(&src)?
            .iter()
            .find(|(_, a)| a == agent)
            .map(|(t, _)| *t);
        drop(guard);
        found
    }

    /// Union across every source. Consumed by route-table rebuilds.
    #[must_use]
    pub fn snapshot(&self) -> LiveSet {
        let guard = self
            .by_source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = LiveSet::new();
        for set in guard.values() {
            out.extend(set.iter().cloned());
        }
        drop(guard);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::identity::AgentKeypair;

    fn tenant(seed: u8) -> TenantId {
        TenantId::from_bytes(&[seed; 32])
    }

    fn agent() -> AgentId {
        AgentKeypair::generate().id()
    }

    fn edge(seed: u8) -> SourceKey {
        SourceKey::Remote([seed; 32])
    }

    #[test]
    fn record_added_only_returns_true_on_first_source() {
        let live = LiveAgents::new();
        let (t, a) = (tenant(1), agent());
        assert!(live.record_added(edge(1), t, a.clone()));
        // Same source re-adds (idempotent): not a global transition.
        assert!(!live.record_added(edge(1), t, a.clone()));
        // Different source sees the same key: already-live, not a transition.
        assert!(!live.record_added(edge(2), t, a));
    }

    #[test]
    fn record_removed_holds_while_another_source_has_it() {
        let live = LiveAgents::new();
        let (t, a) = (tenant(1), agent());
        live.record_added(edge(1), t, a.clone());
        live.record_added(edge(2), t, a.clone());
        // edge(1) drops it: edge(2) still has it → not a global removal.
        assert!(!live.record_removed(edge(1), t, a.clone()));
        // edge(2) drops it: now globally gone.
        assert!(live.record_removed(edge(2), t, a));
    }

    #[test]
    fn record_removed_for_unknown_key_is_false() {
        let live = LiveAgents::new();
        assert!(!live.record_removed(edge(1), tenant(1), agent()));
    }

    #[test]
    fn replace_swaps_an_edge_set_atomically() {
        let live = LiveAgents::new();
        let (t, a1, a2) = (tenant(1), agent(), agent());
        live.record_added(edge(1), t, a1.clone());
        // Replace with a different agent — both an add and a remove.
        assert!(live.replace(edge(1), [(t, a2.clone())]));
        let snap = live.snapshot();
        assert!(!snap.contains(&(t, a1)));
        assert!(snap.contains(&(t, a2)));
    }

    #[test]
    fn replace_no_op_returns_false() {
        let live = LiveAgents::new();
        let (t, a) = (tenant(1), agent());
        live.record_added(edge(1), t, a.clone());
        assert!(!live.replace(edge(1), [(t, a)]));
    }

    #[test]
    fn drop_source_keeps_entries_held_elsewhere() {
        let live = LiveAgents::new();
        let (t, shared, only_on_1) = (tenant(1), agent(), agent());
        live.record_added(edge(1), t, shared.clone());
        live.record_added(edge(1), t, only_on_1.clone());
        live.record_added(edge(2), t, shared.clone());
        // edge(1) goes away: `shared` survives (edge 2), `only_on_1` doesn't.
        assert!(live.drop_source(edge(1)));
        let snap = live.snapshot();
        assert!(snap.contains(&(t, shared)));
        assert!(!snap.contains(&(t, only_on_1)));
    }

    #[test]
    fn drop_source_no_op_when_unknown() {
        let live = LiveAgents::new();
        assert!(!live.drop_source(edge(1)));
    }

    #[test]
    fn snapshot_unions_local_and_remote() {
        let live = LiveAgents::new();
        let (t, a1, a2) = (tenant(1), agent(), agent());
        live.record_added(SourceKey::Local, t, a1.clone());
        live.record_added(edge(1), t, a2.clone());
        let snap = live.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&(t, a1)));
        assert!(snap.contains(&(t, a2)));
    }
}
