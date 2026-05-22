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

pub const CONTROL_OPCODE_AUTHENTICATE: u8 = 0x01;

/// Wire shape after `CONTROL_PREFIX`:
/// `opcode:u8 || kid:u32_BE || cred_len:u32_BE || cred || sig_len:u32_BE || sig`.
#[derive(Debug)]
pub struct AuthFrame {
    pub kid: Kid,
    pub cred_cbor: Vec<u8>,
    pub sig: EdgeCredSig,
}

impl AuthFrame {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + 4 + self.cred_cbor.len() + 4 + PQ_SIGNATURE_LEN);
        buf.push(CONTROL_OPCODE_AUTHENTICATE);
        buf.extend_from_slice(&self.kid.to_be_bytes());
        buf.extend_from_slice(&u32_be(self.cred_cbor.len()));
        buf.extend_from_slice(&self.cred_cbor);
        buf.extend_from_slice(&u32_be(self.sig.len()));
        buf.extend_from_slice(&self.sig);
        buf
    }

    pub fn decode(frame: &[u8]) -> anyhow::Result<Self> {
        let mut cur = Cursor::new(frame);
        let opcode = cur.read_u8()?;
        if opcode != CONTROL_OPCODE_AUTHENTICATE {
            anyhow::bail!("expected Authenticate opcode, got {opcode:#x}");
        }
        let kid = cur.read_u32_be()?;
        let cred_len = cur.read_u32_be()? as usize;
        let cred_cbor = cur.read_bytes(cred_len)?.to_vec();
        let sig_len = cur.read_u32_be()? as usize;
        if sig_len != PQ_SIGNATURE_LEN {
            anyhow::bail!("sig_len {sig_len} != {PQ_SIGNATURE_LEN}");
        }
        let sig_bytes = cur.read_bytes(sig_len)?;
        let sig: EdgeCredSig = sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("sig length mismatch"))?;
        if !cur.is_at_end() {
            anyhow::bail!("trailing bytes after auth frame");
        }
        Ok(Self {
            kid,
            cred_cbor,
            sig,
        })
    }
}

fn u32_be(n: usize) -> [u8; 4] {
    // Edge caps the whole frame at 64 KiB long before u32::MAX matters.
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> anyhow::Result<u8> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("auth frame: unexpected end at u8"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u32_be(&mut self) -> anyhow::Result<u32> {
        let bytes = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| anyhow::anyhow!("auth frame: unexpected end at u32"))?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("auth frame: u32 slice"))?;
        self.pos += 4;
        Ok(u32::from_be_bytes(arr))
    }

    fn read_bytes(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("auth frame: length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| anyhow::anyhow!("auth frame: unexpected end at {n}-byte payload"))?;
        self.pos = end;
        Ok(slice)
    }

    const fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
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
    fn auth_frame_round_trip() {
        let cred = sample_cred();
        let cred_cbor = cred.to_cbor().unwrap();
        let sig = [9u8; PQ_SIGNATURE_LEN];
        let original = AuthFrame {
            kid: 7,
            cred_cbor: cred_cbor.clone(),
            sig,
        };
        let bytes = original.encode();
        let decoded = AuthFrame::decode(&bytes).unwrap();
        assert_eq!(decoded.kid, 7);
        assert_eq!(decoded.cred_cbor, cred_cbor);
        assert_eq!(decoded.sig, sig);
    }

    #[test]
    fn auth_frame_rejects_wrong_opcode() {
        let mut buf = AuthFrame {
            kid: 1,
            cred_cbor: vec![0; 10],
            sig: [0u8; PQ_SIGNATURE_LEN],
        }
        .encode();
        buf[0] = 0x99;
        AuthFrame::decode(&buf).unwrap_err();
    }

    #[test]
    fn auth_frame_rejects_truncated() {
        let buf = AuthFrame {
            kid: 1,
            cred_cbor: vec![0; 10],
            sig: [0u8; PQ_SIGNATURE_LEN],
        }
        .encode();
        AuthFrame::decode(&buf[..buf.len() - 1]).unwrap_err();
    }

    #[test]
    fn auth_frame_rejects_trailing_bytes() {
        let mut buf = AuthFrame {
            kid: 1,
            cred_cbor: vec![0; 10],
            sig: [0u8; PQ_SIGNATURE_LEN],
        }
        .encode();
        buf.push(0xAA);
        AuthFrame::decode(&buf).unwrap_err();
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
