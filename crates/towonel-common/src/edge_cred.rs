#![expect(
    clippy::map_err_ignore,
    reason = "TryInto length-mismatch errors carry no information beyond our message"
)]

use serde::{Deserialize, Serialize};

use crate::identity::{AgentId, PQ_SIGNATURE_LEN, PqPublicKey, TenantId, verify_pq_signature};

pub const EDGE_CRED_VERSION: u16 = 1;
pub const EDGE_CRED_NONCE_LEN: usize = 16;
pub type Kid = u32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeCred {
    pub version: u16,
    pub kid: Kid,
    pub agent_id: AgentId,
    #[serde(with = "serde_tenant_id_bytes")]
    pub tenant_id: TenantId,
    pub not_after_ms: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; EDGE_CRED_NONCE_LEN],
}

impl EdgeCred {
    pub fn to_cbor(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(128);
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> anyhow::Result<Self> {
        ciborium::from_reader(bytes).map_err(Into::into)
    }
}

/// Detached ML-DSA-65 signature over `cred.to_cbor()`.
pub type EdgeCredSig = [u8; PQ_SIGNATURE_LEN];

#[must_use]
pub fn verify_edge_cred(pq_pubkey: &PqPublicKey, cred_cbor: &[u8], sig: &EdgeCredSig) -> bool {
    verify_pq_signature(pq_pubkey, cred_cbor, sig)
}

mod serde_tenant_id_bytes {
    use super::TenantId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(id: &TenantId, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(id.as_bytes()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<TenantId, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        let arr: [u8; 32] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| serde::de::Error::custom("tenant_id must be 32 bytes"))?;
        Ok(TenantId::from_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TenantKeypair;

    fn sample_cred() -> EdgeCred {
        let mut nonce = [0u8; EDGE_CRED_NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let kp = TenantKeypair::generate();
        let agent_kp = crate::identity::AgentKeypair::generate();
        EdgeCred {
            version: EDGE_CRED_VERSION,
            kid: 1,
            agent_id: agent_kp.id(),
            tenant_id: kp.id(),
            not_after_ms: 1_700_000_000_000,
            nonce,
        }
    }

    #[test]
    fn cbor_round_trip() {
        let cred = sample_cred();
        let bytes = cred.to_cbor().unwrap();
        let decoded = EdgeCred::from_cbor(&bytes).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    fn sign_verify_round_trip() {
        let cred = sample_cred();
        let kp = TenantKeypair::generate();
        let bytes = cred.to_cbor().unwrap();
        let sig = kp.sign(&bytes);
        assert!(verify_edge_cred(kp.public_key(), &bytes, &sig));
    }

    #[test]
    fn rejects_tampered_bytes() {
        let cred = sample_cred();
        let kp = TenantKeypair::generate();
        let mut tampered = cred.to_cbor().unwrap();
        // Sign the *original* bytes, then flip a byte and verify must fail.
        // Order matters — moving the sign() call below the XOR would silently
        // turn this into a tautology.
        let sig = kp.sign(&tampered);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!verify_edge_cred(kp.public_key(), &tampered, &sig));
    }
}
