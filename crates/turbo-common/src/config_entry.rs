use ciborium::value::{Integer, Value as CborValue};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::identity::{
    AgentId, PQ_SIGNATURE_LEN, PqPublicKey, TenantId, TenantKeypair, verify_pq_signature,
};
use crate::tls_policy::TlsMode;

/// Operations that can be performed on the config state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOp {
    /// Claim a hostname for this tenant. Edge will route SNI matches to this tenant's agents.
    UpsertHostname {
        hostname: String,
    },
    /// Release a hostname.
    DeleteHostname {
        hostname: String,
    },
    /// Authorize an agent to connect on behalf of this tenant.
    UpsertAgent {
        agent_id: AgentId,
    },
    /// Revoke an agent's authorization.
    RevokeAgent {
        agent_id: AgentId,
    },
    SetHostnameTls {
        hostname: String,
        mode: TlsMode,
    },
}

/// The payload of a config entry, before signing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigPayload {
    /// Protocol version. Currently `1`.
    pub version: u16,
    pub tenant_id: TenantId,
    pub sequence: u64,
    pub timestamp: u64,
    pub op: ConfigOp,
}

/// A signed config entry.
#[derive(Clone)]
pub struct SignedConfigEntry {
    /// Canonical CBOR-encoded payload bytes (the signed material).
    pub payload_cbor: Vec<u8>,
    /// ML-DSA-65 signature over `payload_cbor`.
    /// Boxed so moves of `SignedConfigEntry` don't copy 3.3 KiB on the stack.
    pub signature: Box<[u8; PQ_SIGNATURE_LEN]>,
    /// The tenant who signed this entry, i.e. `sha256(pq_public_key)`.
    pub tenant_id: TenantId,
}

impl std::fmt::Debug for SignedConfigEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedConfigEntry")
            .field("payload_cbor.len", &self.payload_cbor.len())
            .field("signature.len", &PQ_SIGNATURE_LEN)
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

impl Serialize for SignedConfigEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(3))?;
        map.serialize_entry("payload", serde_bytes::Bytes::new(&self.payload_cbor))?;
        map.serialize_entry(
            "signature",
            serde_bytes::Bytes::new(self.signature.as_slice()),
        )?;
        map.serialize_entry("tenant_id", &self.tenant_id)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for SignedConfigEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "payload")]
            payload: serde_bytes::ByteBuf,
            signature: serde_bytes::ByteBuf,
            tenant_id: TenantId,
        }
        let w = Wire::deserialize(d)?;
        let sig_arr: [u8; PQ_SIGNATURE_LEN] = w.signature.as_ref().try_into().map_err(|_| {
            D::Error::custom(format!(
                "signature must be exactly {PQ_SIGNATURE_LEN} bytes (ml-dsa-65), got {}",
                w.signature.len()
            ))
        })?;
        Ok(Self {
            payload_cbor: w.payload.into_vec(),
            signature: Box::new(sig_arr),
            tenant_id: w.tenant_id,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigEntryError {
    #[error("CBOR encoding error: {0}")]
    Encode(String),
    #[error("CBOR decoding error: {0}")]
    Decode(String),
    #[error("ml-dsa-65 signature verification failed")]
    InvalidSignature,
    #[error("tenant_id in payload does not match outer tenant_id")]
    TenantMismatch,
    #[error("unsupported payload version: {0}")]
    UnsupportedVersion(u16),
}

impl SignedConfigEntry {
    /// Canonicalise `payload` to CBOR, sign with `keypair`'s ML-DSA-65 key.
    pub fn sign(
        payload: &ConfigPayload,
        keypair: &TenantKeypair,
    ) -> Result<Self, ConfigEntryError> {
        let cbor_bytes = to_canonical_cbor(payload)?;
        let signature = Box::new(keypair.sign(&cbor_bytes));
        Ok(Self {
            payload_cbor: cbor_bytes,
            signature,
            tenant_id: keypair.id(),
        })
    }

    /// Canonicalise + sign with the deterministic (all-zero seed) path.
    /// For snapshot / wire-format tests that need byte-stable signatures.
    /// **Production code must use [`sign`] (randomized).**
    #[doc(hidden)]
    pub fn sign_deterministic(
        payload: &ConfigPayload,
        keypair: &TenantKeypair,
    ) -> Result<Self, ConfigEntryError> {
        let cbor_bytes = to_canonical_cbor(payload)?;
        let signature = Box::new(keypair.sign_deterministic(&cbor_bytes));
        Ok(Self {
            payload_cbor: cbor_bytes,
            signature,
            tenant_id: keypair.id(),
        })
    }

    /// Verify the signature against `pq_pubkey` and decode the payload.
    /// The caller supplies `pq_pubkey` via a lookup in the hub's
    /// `OwnershipPolicy` (keyed by `self.tenant_id`).
    pub fn verify(&self, pq_pubkey: &PqPublicKey) -> Result<ConfigPayload, ConfigEntryError> {
        if !verify_pq_signature(pq_pubkey, &self.payload_cbor, &self.signature) {
            return Err(ConfigEntryError::InvalidSignature);
        }
        let payload = from_canonical_cbor(&self.payload_cbor)?;
        if payload.version != 1 {
            return Err(ConfigEntryError::UnsupportedVersion(payload.version));
        }
        if payload.tenant_id != self.tenant_id {
            return Err(ConfigEntryError::TenantMismatch);
        }
        Ok(payload)
    }
}

/// Encode a `ConfigPayload` as canonical CBOR per protocol §3.4.
///
/// Map keys in RFC 8949 §4.2.1 length-first order:
/// `op (2) < version (7) < sequence (8) < tenant_id (9) < timestamp (9)`.
/// Identifiers are 32-byte CBOR byte strings (§2.3). `op` variant tags are
/// snake_case (§3.2). Integers use ciborium's smallest-form encoding.
fn to_canonical_cbor(payload: &ConfigPayload) -> Result<Vec<u8>, ConfigEntryError> {
    let op_value = match &payload.op {
        ConfigOp::UpsertHostname { hostname } => op_with(
            "upsert_hostname",
            "hostname",
            CborValue::Text(hostname.clone()),
        ),
        ConfigOp::DeleteHostname { hostname } => op_with(
            "delete_hostname",
            "hostname",
            CborValue::Text(hostname.clone()),
        ),
        ConfigOp::UpsertAgent { agent_id } => op_with(
            "upsert_agent",
            "agent_id",
            CborValue::Bytes(agent_id.as_bytes().to_vec()),
        ),
        ConfigOp::RevokeAgent { agent_id } => op_with(
            "revoke_agent",
            "agent_id",
            CborValue::Bytes(agent_id.as_bytes().to_vec()),
        ),
        ConfigOp::SetHostnameTls { hostname, mode } => {
            let mode_cbor = tls_mode_to_cbor(mode);
            CborValue::Map(vec![(
                CborValue::Text("set_hostname_tls".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("hostname".into()),
                        CborValue::Text(hostname.clone()),
                    ),
                    (CborValue::Text("mode".into()), mode_cbor),
                ]),
            )])
        }
    };

    let outer = CborValue::Map(vec![
        (CborValue::Text("op".into()), op_value),
        (
            CborValue::Text("version".into()),
            CborValue::Integer(Integer::from(payload.version)),
        ),
        (
            CborValue::Text("sequence".into()),
            CborValue::Integer(Integer::from(payload.sequence)),
        ),
        (
            CborValue::Text("tenant_id".into()),
            CborValue::Bytes(payload.tenant_id.as_bytes().to_vec()),
        ),
        (
            CborValue::Text("timestamp".into()),
            CborValue::Integer(Integer::from(payload.timestamp)),
        ),
    ]);

    let mut out = Vec::new();
    ciborium::into_writer(&outer, &mut out).map_err(|e| ConfigEntryError::Encode(e.to_string()))?;
    Ok(out)
}

fn op_with(variant: &str, field: &str, value: CborValue) -> CborValue {
    CborValue::Map(vec![(
        CborValue::Text(variant.into()),
        CborValue::Map(vec![(CborValue::Text(field.into()), value)]),
    )])
}

/// Canonical CBOR encoding of a `TlsMode`. Mirrors the `serde`
/// internally-tagged representation (`{ mode = "passthrough" | "terminate" }`)
/// so signatures are deterministic.
fn tls_mode_to_cbor(mode: &TlsMode) -> CborValue {
    let tag = match mode {
        TlsMode::Passthrough => "passthrough",
        TlsMode::Terminate => "terminate",
    };
    CborValue::Map(vec![(
        CborValue::Text("mode".into()),
        CborValue::Text(tag.into()),
    )])
}

/// Decode canonical CBOR bytes back into a `ConfigPayload`. Order-independent
/// (fields looked up by name via serde); encode is the only canonical path.
fn from_canonical_cbor(bytes: &[u8]) -> Result<ConfigPayload, ConfigEntryError> {
    ciborium::from_reader(bytes).map_err(|e| ConfigEntryError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry() -> (TenantKeypair, ConfigPayload) {
        let kp = TenantKeypair::generate();
        let payload = ConfigPayload {
            version: 1,
            tenant_id: kp.id(),
            sequence: 1,
            timestamp: 1_700_000_000_000,
            op: ConfigOp::UpsertHostname {
                hostname: "app.erwan.example.eu".to_string(),
            },
        };
        (kp, payload)
    }

    #[test]
    fn sign_and_verify() {
        let (kp, payload) = make_entry();
        let entry = SignedConfigEntry::sign(&payload, &kp).unwrap();
        let verified = entry.verify(kp.public_key()).unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (kp, payload) = make_entry();
        let mut entry = SignedConfigEntry::sign(&payload, &kp).unwrap();
        if let Some(byte) = entry.payload_cbor.last_mut() {
            *byte ^= 0xff;
        }
        let err = entry.verify(kp.public_key()).unwrap_err();
        assert!(matches!(err, ConfigEntryError::InvalidSignature));
    }

    #[test]
    fn wrong_tenant_id_rejected() {
        let (kp, payload) = make_entry();
        let mut entry = SignedConfigEntry::sign(&payload, &kp).unwrap();
        let other = TenantKeypair::generate();
        entry.tenant_id = other.id();

        // Verifying against the real signer's pubkey still passes ML-DSA
        // (the sig is over the same bytes), but the inner-vs-outer
        // tenant_id check fires.
        let err = entry.verify(kp.public_key()).unwrap_err();
        assert!(
            matches!(err, ConfigEntryError::TenantMismatch),
            "expected TenantMismatch, got {err:?}"
        );
    }

    #[test]
    fn unsupported_version_rejected() {
        let kp = TenantKeypair::generate();
        let payload = ConfigPayload {
            version: 2, // future version
            tenant_id: kp.id(),
            sequence: 1,
            timestamp: 1,
            op: ConfigOp::UpsertHostname {
                hostname: "x.test".into(),
            },
        };
        let entry = SignedConfigEntry::sign(&payload, &kp).unwrap();
        let err = entry.verify(kp.public_key()).unwrap_err();
        assert!(matches!(err, ConfigEntryError::UnsupportedVersion(2)));
    }

    #[test]
    fn all_config_ops_sign_verify() {
        let kp = TenantKeypair::generate();
        let agent_kp = crate::identity::AgentKeypair::generate();

        let ops = vec![
            ConfigOp::UpsertHostname {
                hostname: "test.example.eu".into(),
            },
            ConfigOp::DeleteHostname {
                hostname: "test.example.eu".into(),
            },
            ConfigOp::UpsertAgent {
                agent_id: agent_kp.id(),
            },
            ConfigOp::RevokeAgent {
                agent_id: agent_kp.id(),
            },
            ConfigOp::SetHostnameTls {
                hostname: "test.example.eu".into(),
                mode: TlsMode::Passthrough,
            },
            ConfigOp::SetHostnameTls {
                hostname: "test.example.eu".into(),
                mode: TlsMode::Terminate,
            },
        ];

        for (i, op) in ops.into_iter().enumerate() {
            let payload = ConfigPayload {
                version: 1,
                tenant_id: kp.id(),
                sequence: i as u64 + 1,
                timestamp: 1_700_000_000_000,
                op,
            };
            let entry = SignedConfigEntry::sign(&payload, &kp).unwrap();
            let verified = entry.verify(kp.public_key()).unwrap();
            assert_eq!(verified, payload);
        }
    }

    #[test]
    fn wire_format_canonical_and_stable() {
        let kp = TenantKeypair::from_seed([42u8; 32]);
        let payload = ConfigPayload {
            version: 1,
            tenant_id: kp.id(),
            sequence: 1,
            timestamp: 1_700_000_000_000,
            op: ConfigOp::UpsertHostname {
                hostname: "app.example.eu".to_string(),
            },
        };

        // CBOR encoding must be deterministic even though signatures are randomized.
        let entry1 = SignedConfigEntry::sign(&payload, &kp).unwrap();
        let entry2 = SignedConfigEntry::sign(&payload, &kp).unwrap();

        assert_eq!(
            entry1.payload_cbor, entry2.payload_cbor,
            "CBOR encoding must be deterministic"
        );

        // Signatures are randomized — both must verify but need not be equal.
        assert!(entry1.verify(kp.public_key()).is_ok());
        assert!(entry2.verify(kp.public_key()).is_ok());

        let value: CborValue = ciborium::from_reader(entry1.payload_cbor.as_slice())
            .expect("canonical bytes must parse as CBOR");
        let map = match value {
            CborValue::Map(m) => m,
            _ => panic!("top-level must be a CBOR map"),
        };
        let keys: Vec<&str> = map
            .iter()
            .map(|(k, _)| match k {
                CborValue::Text(t) => t.as_str(),
                other => panic!("map key is not a text string: {other:?}"),
            })
            .collect();
        assert_eq!(
            keys,
            ["op", "version", "sequence", "tenant_id", "timestamp"],
            "CBOR keys must be in length-first canonical order"
        );

        let (_, tenant_val) = map
            .iter()
            .find(|(k, _)| matches!(k, CborValue::Text(t) if t == "tenant_id"))
            .unwrap();
        match tenant_val {
            CborValue::Bytes(b) => assert_eq!(b.len(), 32, "tenant_id must be 32 bytes"),
            other => panic!("tenant_id must be a byte string, got {other:?}"),
        }

        let (_, op_val) = map
            .iter()
            .find(|(k, _)| matches!(k, CborValue::Text(t) if t == "op"))
            .unwrap();
        let op_map = match op_val {
            CborValue::Map(m) => m,
            other => panic!("op must be a map, got {other:?}"),
        };
        assert_eq!(op_map.len(), 1, "op must contain exactly one variant");
        let tag = match &op_map[0].0 {
            CborValue::Text(t) => t.as_str(),
            other => panic!("op variant tag must be text, got {other:?}"),
        };
        assert!(
            [
                "upsert_hostname",
                "delete_hostname",
                "upsert_agent",
                "revoke_agent",
                "set_hostname_tls",
            ]
            .contains(&tag),
            "op variant tag must be snake_case, got {tag}"
        );

        // ML-DSA signature is always exactly PQ_SIGNATURE_LEN bytes.
        assert_eq!(entry1.signature.len(), PQ_SIGNATURE_LEN);
    }

    #[test]
    fn set_hostname_tls_canonical_cbor_stable_and_ordered() {
        // SetHostnameTls produces a nested `mode` map whose key order and
        // values must be deterministic so signatures are byte-stable.
        let kp = TenantKeypair::from_seed([7u8; 32]);
        for mode in [TlsMode::Passthrough, TlsMode::Terminate] {
            let payload = ConfigPayload {
                version: 1,
                tenant_id: kp.id(),
                sequence: 1,
                timestamp: 1_700_000_000_000,
                op: ConfigOp::SetHostnameTls {
                    hostname: "app.example.eu".into(),
                    mode: mode.clone(),
                },
            };
            let a = SignedConfigEntry::sign(&payload, &kp).unwrap();
            let b = SignedConfigEntry::sign(&payload, &kp).unwrap();
            assert_eq!(
                a.payload_cbor, b.payload_cbor,
                "SetHostnameTls CBOR must be deterministic for mode {mode:?}"
            );
            let parsed: CborValue = ciborium::from_reader(a.payload_cbor.as_slice()).unwrap();
            let map = match parsed {
                CborValue::Map(m) => m,
                _ => panic!("top-level must be a map"),
            };
            let (_, op_val) = map
                .iter()
                .find(|(k, _)| matches!(k, CborValue::Text(t) if t == "op"))
                .unwrap();
            let op_map = match op_val {
                CborValue::Map(m) => m,
                _ => panic!("op must be a map"),
            };
            let tag = match &op_map[0].0 {
                CborValue::Text(t) => t.as_str(),
                _ => panic!("op variant tag must be text"),
            };
            assert_eq!(tag, "set_hostname_tls");
            let inner = match &op_map[0].1 {
                CborValue::Map(m) => m,
                _ => panic!("set_hostname_tls payload must be a map"),
            };
            let inner_keys: Vec<&str> = inner
                .iter()
                .map(|(k, _)| match k {
                    CborValue::Text(t) => t.as_str(),
                    _ => panic!("key must be text"),
                })
                .collect();
            assert_eq!(
                inner_keys,
                ["hostname", "mode"],
                "set_hostname_tls keys must be in a fixed order"
            );
            let mode_cbor = &inner[1].1;
            let mode_map = match mode_cbor {
                CborValue::Map(m) => m,
                _ => panic!("mode must be a map"),
            };
            let expected_tag = match mode {
                TlsMode::Passthrough => "passthrough",
                TlsMode::Terminate => "terminate",
            };
            assert_eq!(mode_map.len(), 1, "mode map has a single `mode` key");
            assert!(
                matches!(&mode_map[0].0, CborValue::Text(t) if t == "mode"),
                "mode map key must be `mode`"
            );
            assert!(
                matches!(&mode_map[0].1, CborValue::Text(t) if t == expected_tag),
                "mode tag must match the variant"
            );
        }
    }

    #[test]
    fn sign_verify_across_many_calls() {
        // Randomized signing: each signature differs but all must verify.
        let kp = TenantKeypair::from_seed([50u8; 32]);
        let payload = ConfigPayload {
            version: 1,
            tenant_id: kp.id(),
            sequence: 1,
            timestamp: 1,
            op: ConfigOp::UpsertHostname {
                hostname: "h".into(),
            },
        };
        // CBOR encoding is still deterministic.
        let first = SignedConfigEntry::sign(&payload, &kp).unwrap();
        for _ in 0..9 {
            let next = SignedConfigEntry::sign(&payload, &kp).unwrap();
            assert_eq!(next.payload_cbor, first.payload_cbor);
            assert!(next.verify(kp.public_key()).is_ok());
        }
    }

    #[test]
    fn cbor_wire_roundtrip_preserves_signature() {
        let (kp, payload) = make_entry();
        let entry = SignedConfigEntry::sign(&payload, &kp).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&entry, &mut buf).unwrap();
        let decoded: SignedConfigEntry = ciborium::from_reader(&buf[..]).unwrap();

        assert_eq!(decoded.payload_cbor, entry.payload_cbor);
        assert_eq!(decoded.signature, entry.signature);
        assert_eq!(decoded.tenant_id, entry.tenant_id);

        let verified = decoded
            .verify(kp.public_key())
            .expect("signature must verify after wire roundtrip");
        assert_eq!(verified, payload);
    }

    #[test]
    fn cbor_wire_rejects_truncated_signature() {
        // Hand-craft a bogus envelope with a 100-byte "signature" -- the
        // deserializer must refuse rather than silently pass the truncated
        // sig down to verify().
        let fake_payload: &[u8] = b"\xa0"; // empty CBOR map
        let fake_sig = vec![0u8; 100];
        let fake_tenant = [0u8; 32];

        let envelope = CborValue::Map(vec![
            (
                CborValue::Text("payload".into()),
                CborValue::Bytes(fake_payload.to_vec()),
            ),
            (
                CborValue::Text("signature".into()),
                CborValue::Bytes(fake_sig),
            ),
            (
                CborValue::Text("tenant_id".into()),
                CborValue::Bytes(fake_tenant.to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&envelope, &mut buf).unwrap();

        let err = ciborium::from_reader::<SignedConfigEntry, _>(&buf[..]).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "expected signature-size error, got {err}"
        );
    }

    #[test]
    fn inner_tenant_mismatch_rejected() {
        // Bob signs a payload that *claims* to be from Alice. After signing,
        // the outer tenant_id becomes Bob's (SignedConfigEntry::sign uses
        // keypair.id()), but the inner payload carries Alice's id. verify
        // must reject because payload.tenant_id != outer tenant_id.
        let alice = TenantKeypair::generate();
        let bob = TenantKeypair::generate();

        let payload_claiming_alice = ConfigPayload {
            version: 1,
            tenant_id: alice.id(),
            sequence: 1,
            timestamp: 1,
            op: ConfigOp::UpsertHostname {
                hostname: "alice.example.eu".into(),
            },
        };

        let bob_signed = SignedConfigEntry::sign(&payload_claiming_alice, &bob).unwrap();
        let err = bob_signed.verify(bob.public_key()).unwrap_err();
        assert!(
            matches!(err, ConfigEntryError::TenantMismatch),
            "expected TenantMismatch, got {err:?}"
        );
    }
}
