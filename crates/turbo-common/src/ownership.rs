use std::collections::{HashMap, HashSet};

use crate::identity::{PqPublicKey, TenantId};

/// Operator-configured hostname ownership plus the tenant's ML-DSA-65
/// public key. `OwnershipPolicy` is both the allowlist and the
/// verification oracle — `SignedConfigEntry::verify` looks up the PQ
/// pubkey here.
#[derive(Clone, Debug, Default)]
pub struct OwnershipPolicy {
    allowed: HashMap<TenantId, HashSet<String>>,
    pq_keys: HashMap<TenantId, PqPublicKey>,
}

impl OwnershipPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tenant with their ML-DSA-65 public key and hostname
    /// patterns. Re-registering merges new patterns into the existing set
    /// and overwrites the PQ pubkey.
    pub fn register_tenant(
        &mut self,
        tenant_id: &TenantId,
        pq_public_key: PqPublicKey,
        patterns: impl IntoIterator<Item = String>,
    ) {
        let entry = self.allowed.entry(*tenant_id).or_default();
        for p in patterns {
            entry.insert(p.to_lowercase());
        }
        self.pq_keys.insert(*tenant_id, pq_public_key);
    }

    pub fn pq_public_key(&self, tenant_id: &TenantId) -> Option<&PqPublicKey> {
        self.pq_keys.get(tenant_id)
    }

    pub fn is_known_tenant(&self, tenant_id: &TenantId) -> bool {
        self.allowed.contains_key(tenant_id)
    }

    /// Drop a tenant. Their existing signed entries stay in the DB, but
    /// the route table stops materializing routes for them.
    pub fn remove(&mut self, tenant_id: &TenantId) {
        self.allowed.remove(tenant_id);
        self.pq_keys.remove(tenant_id);
    }

    /// Iterate over `(tenant_id, hostname_patterns)` pairs. Used by the
    /// hub to detect hostname conflicts across tenants.
    pub fn iter_patterns(&self) -> impl Iterator<Item = (&TenantId, &HashSet<String>)> {
        self.allowed.iter()
    }

    /// Check if a tenant is allowed to claim a specific hostname.
    pub fn is_hostname_allowed(&self, tenant_id: &TenantId, hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        let patterns = match self.allowed.get(tenant_id) {
            Some(p) => p,
            None => return false,
        };

        for pattern in patterns {
            if pattern == &lower {
                return true; // exact match
            }
            if let Some(suffix) = pattern.strip_prefix("*.")
                && lower.ends_with(suffix)
                && lower.len() > suffix.len() + 1
            {
                let prefix = &lower[..lower.len() - suffix.len() - 1];
                if !prefix.is_empty() {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TenantKeypair;

    fn register(policy: &mut OwnershipPolicy, kp: &TenantKeypair, patterns: &[&str]) {
        policy.register_tenant(
            &kp.id(),
            kp.public_key().clone(),
            patterns.iter().map(|s| s.to_string()),
        );
    }

    #[test]
    fn exact_match_allowed() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["app.example.eu"]);

        assert!(policy.is_hostname_allowed(&kp.id(), "app.example.eu"));
        assert!(!policy.is_hostname_allowed(&kp.id(), "other.example.eu"));
    }

    #[test]
    fn wildcard_match_allowed() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["*.example.eu"]);

        assert!(policy.is_hostname_allowed(&kp.id(), "app.example.eu"));
        assert!(policy.is_hostname_allowed(&kp.id(), "other.example.eu"));
        // bare domain should not match wildcard
        assert!(!policy.is_hostname_allowed(&kp.id(), "example.eu"));
    }

    #[test]
    fn case_insensitive() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["App.Example.EU"]);

        assert!(policy.is_hostname_allowed(&kp.id(), "app.example.eu"));
    }

    #[test]
    fn unknown_tenant_rejected() {
        let known = TenantKeypair::generate();
        let unknown = TenantKeypair::generate();

        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &known, &["app.example.eu"]);

        assert!(policy.is_known_tenant(&known.id()));
        assert!(!policy.is_known_tenant(&unknown.id()));
        assert!(!policy.is_hostname_allowed(&unknown.id(), "app.example.eu"));
    }

    #[test]
    fn hostname_outside_policy_rejected() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["allowed.example.eu"]);

        assert!(!policy.is_hostname_allowed(&kp.id(), "evil.example.eu"));
    }

    #[test]
    fn pq_public_key_round_trip() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["app.example.eu"]);

        assert_eq!(policy.pq_public_key(&kp.id()), Some(kp.public_key()));
    }

    #[test]
    fn remove_drops_patterns_and_pq_key() {
        let kp = TenantKeypair::generate();
        let mut policy = OwnershipPolicy::new();
        register(&mut policy, &kp, &["app.example.eu"]);

        policy.remove(&kp.id());

        assert!(!policy.is_known_tenant(&kp.id()));
        assert!(policy.pq_public_key(&kp.id()).is_none());
    }

    #[test]
    fn register_twice_merges_patterns_and_overwrites_key() {
        let kp1 = TenantKeypair::from_seed([1u8; 32]);
        let kp2 = TenantKeypair::from_seed([2u8; 32]);
        // Same tenant_id would require same pubkey -- we simulate the
        // operator-intent semantics by re-registering with a different
        // pubkey under the *same* tenant_id. In practice tenant_id always
        // matches the pubkey, so this only happens on operator policy
        // reload with an updated [[tenants]] block.
        let tenant_id = kp1.id();
        let mut policy = OwnershipPolicy::new();
        policy.register_tenant(&tenant_id, kp1.public_key().clone(), ["a.test".to_string()]);
        policy.register_tenant(&tenant_id, kp2.public_key().clone(), ["b.test".to_string()]);

        assert!(policy.is_hostname_allowed(&tenant_id, "a.test"));
        assert!(policy.is_hostname_allowed(&tenant_id, "b.test"));
        assert_eq!(policy.pq_public_key(&tenant_id), Some(kp2.public_key()));
    }
}
