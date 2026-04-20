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
            .finish_non_exhaustive()
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

/// CBOR-encode a `ConfigPayload`. Byte-stable given a fixed struct layout,
/// which is what the signature needs.
fn to_canonical_cbor(payload: &ConfigPayload) -> Result<Vec<u8>, ConfigEntryError> {
    let mut out = Vec::new();
    ciborium::into_writer(payload, &mut out)
        .map_err(|e| ConfigEntryError::Encode(e.to_string()))?;
    Ok(out)
}

fn from_canonical_cbor(bytes: &[u8]) -> Result<ConfigPayload, ConfigEntryError> {
    ciborium::from_reader(bytes).map_err(|e| ConfigEntryError::Decode(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::manual_let_else)]
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
    fn wire_format_deterministic() {
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

        let entry1 = SignedConfigEntry::sign(&payload, &kp).unwrap();
        let entry2 = SignedConfigEntry::sign(&payload, &kp).unwrap();

        assert_eq!(
            entry1.payload_cbor, entry2.payload_cbor,
            "CBOR encoding must be deterministic"
        );
        assert!(entry1.verify(kp.public_key()).is_ok());
        assert!(entry2.verify(kp.public_key()).is_ok());
        assert_eq!(entry1.signature.len(), PQ_SIGNATURE_LEN);
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
        // Hand-craft a bogus envelope with a 100-byte "signature" — the
        // deserializer must refuse rather than silently pass the truncated
        // sig down to verify().
        #[derive(Serialize)]
        struct BadEnvelope<'a> {
            payload: &'a serde_bytes::Bytes,
            signature: &'a serde_bytes::Bytes,
            tenant_id: TenantId,
        }
        let env = BadEnvelope {
            payload: serde_bytes::Bytes::new(b"\xa0"),
            signature: serde_bytes::Bytes::new(&[0u8; 100]),
            tenant_id: TenantId::from_bytes(&[0u8; 32]),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&env, &mut buf).unwrap();

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
