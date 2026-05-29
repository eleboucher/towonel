#![expect(
    clippy::zero_sized_map_values,
    reason = "TlsMode is single-variant today; future variants would re-expand the table"
)]

use crate::hostname::{wildcard_lookup, wildcard_lookup_ascii_lower};

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMode {
    #[default]
    Passthrough,
}

impl TlsMode {
    /// Human-readable label for logging/metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
        }
    }
}

impl Serialize for TlsMode {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "snake_case", tag = "mode")]
        enum Wire {
            Passthrough,
        }
        match self {
            Self::Passthrough => Wire::Passthrough.serialize(ser),
        }
    }
}

impl<'de> Deserialize<'de> for TlsMode {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            mode: String,
        }
        let wire = Wire::deserialize(de)?;
        match wire.mode.as_str() {
            "passthrough" => Ok(Self::Passthrough),
            "terminate" => {
                tracing::warn!(
                    "tls_mode=terminate is no longer supported; treating as passthrough"
                );
                Ok(Self::Passthrough)
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown tls_mode {other:?}"
            ))),
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

    pub fn insert(&mut self, hostname: impl Into<String>, mode: TlsMode) {
        self.policies.insert(hostname.into().to_lowercase(), mode);
    }

    #[must_use]
    pub fn lookup(&self, hostname: &str) -> TlsMode {
        wildcard_lookup(hostname, |key| self.policies.get(key))
            .copied()
            .unwrap_or(TlsMode::Passthrough)
    }

    /// Same as [`Self::lookup`] but the caller has already ASCII-lowercased
    /// the hostname; avoids a redundant allocation on the edge hot path.
    #[must_use]
    pub fn lookup_ascii_lower(&self, lower: &str) -> TlsMode {
        wildcard_lookup_ascii_lower(lower, |key| self.policies.get(key))
            .copied()
            .unwrap_or(TlsMode::Passthrough)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
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
    fn legacy_terminate_value_maps_to_passthrough() {
        let table: TlsPolicyTable =
            serde_json::from_str(r#"{"policies":{"app.test":{"mode":"terminate"}}}"#).unwrap();
        assert_eq!(table.lookup("app.test"), TlsMode::Passthrough);
    }
}
