#![expect(
    clippy::map_err_ignore,
    reason = "TryInto length-mismatch + AEAD decrypt errors must not leak detail"
)]

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use zeroize::Zeroizing;

pub const KEK_LEN: usize = 32;
pub const KEK_NONCE_LEN: usize = 12;

pub struct HubKek(Zeroizing<[u8; KEK_LEN]>);

impl HubKek {
    pub fn from_hex(hex_str: &str) -> anyhow::Result<Self> {
        let bytes = Zeroizing::new(
            hex::decode(hex_str.trim())
                .map_err(|e| anyhow::anyhow!("KEK is not valid hex: {e}"))?,
        );
        let arr: [u8; KEK_LEN] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "KEK must be exactly {KEK_LEN} bytes ({} hex chars)",
                KEK_LEN * 2
            )
        })?;
        Ok(Self(Zeroizing::new(arr)))
    }

    #[must_use]
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; KEK_LEN]);
        #[expect(
            clippy::expect_used,
            reason = "OS RNG failure is unrecoverable at this layer"
        )]
        getrandom::fill(k.as_mut_slice()).expect("OS RNG failed");
        Self(k)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    /// AES-256-GCM seal. Output layout: `nonce(12) || ciphertext+tag`.
    pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; KEK_NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_slice())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {e}"))?;
        let ciphertext = cipher
            .encrypt((&nonce_bytes).into(), plaintext)
            .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
        let mut out = Vec::with_capacity(KEK_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn unseal(&self, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (nonce_bytes, ciphertext) = sealed
            .split_first_chunk::<KEK_NONCE_LEN>()
            .ok_or_else(|| anyhow::anyhow!("sealed blob too short"))?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_slice())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {e}"))?;
        cipher
            .decrypt(nonce_bytes.into(), ciphertext)
            .map_err(|_| anyhow::anyhow!("unseal failed — wrong KEK or corrupted blob"))
    }
}

impl std::fmt::Debug for HubKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubKek(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kek = HubKek::generate();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let sealed = kek.seal(plaintext).unwrap();
        let unsealed = kek.unseal(&sealed).unwrap();
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek_a = HubKek::generate();
        let kek_b = HubKek::generate();
        let sealed = kek_a.seal(b"secret").unwrap();
        kek_b.unseal(&sealed).unwrap_err();
    }

    #[test]
    fn nonce_varies_per_seal() {
        let kek = HubKek::generate();
        let a = kek.seal(b"same").unwrap();
        let b = kek.seal(b"same").unwrap();
        assert_ne!(a, b, "nonce must be random");
    }

    #[test]
    fn from_hex_round_trip() {
        let kek = HubKek::generate();
        let hex = kek.to_hex();
        let kek2 = HubKek::from_hex(&hex).unwrap();
        let sealed = kek.seal(b"x").unwrap();
        let unsealed = kek2.unseal(&sealed).unwrap();
        assert_eq!(unsealed, b"x");
    }

    #[test]
    fn rejects_short_blob() {
        let kek = HubKek::generate();
        kek.unseal(&[0u8; 5]).unwrap_err();
    }
}
