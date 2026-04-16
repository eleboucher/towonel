use crate::hostname::wildcard_lookup;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TlsMode {
    #[default]
    Passthrough,
    Terminate,
}

impl TlsMode {
    /// Human-readable label for logging/metrics.
    #[must_use] 
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Terminate => "terminate",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TlsPolicyTable {
    policies: HashMap<String, TlsMode>,
}

impl TlsPolicyTable {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn from_raw(policies: HashMap<String, TlsMode>) -> Self {
        Self { policies }
    }

    pub fn insert(&mut self, hostname: impl Into<String>, mode: TlsMode) {
        self.policies.insert(hostname.into().to_lowercase(), mode);
    }

    #[must_use] 
    pub fn lookup(&self, hostname: &str) -> TlsMode {
        wildcard_lookup(hostname, |key| self.policies.get(key))
            .cloned()
            .unwrap_or(TlsMode::Passthrough)
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    #[must_use] 
    pub fn terminate_hostnames(&self) -> Vec<String> {
        self.policies
            .iter()
            .filter(|(_, m)| matches!(m, TlsMode::Terminate))
            .map(|(h, _)| h.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_entry_defaults_passthrough() {
        let table = TlsPolicyTable::new();
        assert_eq!(table.lookup("anything.example.com"), TlsMode::Passthrough);
    }

    #[test]
    fn exact_match() {
        let mut table = TlsPolicyTable::new();
        table.insert("app.example.com", TlsMode::Terminate);
        assert!(matches!(
            table.lookup("app.example.com"),
            TlsMode::Terminate
        ));
    }

    #[test]
    fn wildcard_match() {
        let mut table = TlsPolicyTable::new();
        table.insert("*.bob.example", TlsMode::Terminate);
        assert!(matches!(table.lookup("foo.bob.example"), TlsMode::Terminate));
        assert_eq!(table.lookup("bob.example"), TlsMode::Passthrough);
    }

    #[test]
    fn case_insensitive() {
        let mut table = TlsPolicyTable::new();
        table.insert("APP.Example.COM", TlsMode::Passthrough);
        assert_eq!(table.lookup("app.example.com"), TlsMode::Passthrough);
    }

    #[test]
    fn terminate_hostnames_lists_only_terminate_entries() {
        let mut table = TlsPolicyTable::new();
        table.insert("a.example.com", TlsMode::Passthrough);
        table.insert("b.example.com", TlsMode::Terminate);
        let hosts = table.terminate_hostnames();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "b.example.com");
    }
}
