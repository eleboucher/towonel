use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum TlsMode {
    #[default]
    Passthrough,
    Terminate,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TlsPolicyTable {
    policies: HashMap<String, TlsMode>,
}

impl TlsPolicyTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_raw(policies: HashMap<String, TlsMode>) -> Self {
        Self { policies }
    }

    pub fn insert(&mut self, hostname: impl Into<String>, mode: TlsMode) {
        self.policies.insert(hostname.into().to_lowercase(), mode);
    }

    pub fn lookup(&self, hostname: &str) -> TlsMode {
        let lower = hostname.to_lowercase();
        if let Some(mode) = self.policies.get(&lower) {
            return mode.clone();
        }
        if let Some(dot_pos) = lower.find('.')
            && let Some(mode) = self.policies.get(&format!("*.{}", &lower[dot_pos + 1..]))
        {
            return mode.clone();
        }
        TlsMode::Passthrough
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

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
