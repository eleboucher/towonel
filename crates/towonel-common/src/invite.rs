use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use zeroize::{Zeroize, Zeroizing};

/// Length of `invite_id` in bytes.
pub const INVITE_ID_LEN: usize = 16;
/// Length of `invite_secret` in bytes.
pub const INVITE_SECRET_LEN: usize = 32;
/// Length of the embedded tenant ML-DSA-65 seed in bytes.
pub const TENANT_SEED_LEN: usize = 32;
/// Length of the embedded edge ed25519 seed in bytes.
pub const EDGE_SEED_LEN: usize = 32;

const TENANT_TOKEN_PREFIX: &str = "tt_inv_2_";
const EDGE_TOKEN_PREFIX: &str = "tt_edge_2_";

#[derive(Debug, thiserror::Error)]
pub enum InviteTokenError {
    #[error("invite token has the wrong prefix (expected `{expected}`)")]
    WrongPrefix { expected: &'static str },
    #[error("invite token must contain {expected} dot-separated segments, got {got}")]
    WrongSegmentCount { expected: usize, got: usize },
    #[error("invite token segment is not valid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invite token hub_url is not valid UTF-8: {0}")]
    HubUrlEncoding(#[from] std::string::FromUtf8Error),
    #[error("invite_id must be exactly {INVITE_ID_LEN} bytes, got {0}")]
    BadInviteIdLen(usize),
    #[error("invite_secret must be exactly {INVITE_SECRET_LEN} bytes, got {0}")]
    BadInviteSecretLen(usize),
    #[error("tenant_seed must be exactly {TENANT_SEED_LEN} bytes, got {0}")]
    BadTenantSeedLen(usize),
    #[error("node_seed must be exactly {EDGE_SEED_LEN} bytes, got {0}")]
    BadNodeSeedLen(usize),
}

/// A parsed tenant invite token.
///
/// v2 format: `tt_inv_2_<b64(hub_url)>.<b64(invite_id)>.<b64(invite_secret)>.<b64(tenant_seed)>`.
/// The tenant ML-DSA-65 seed is embedded directly so pods can derive the
/// tenant signing key locally and run statelessly (no disk, no redemption
/// dance) -- the hub pre-registers the tenant at invite creation time.
///
/// `invite_secret` and `tenant_seed` are zeroed on drop (see [`Drop`]) and
/// redacted by the [`fmt::Debug`] impl so logs / panic messages never leak
/// them. Not `Clone` -- duplicating a token would leave two live copies of
/// the secret material, defeating the zeroize-on-drop guarantee.
/// Do not add a `Serialize` derive: the only legitimate serialization goes
/// through [`Self::encode`].
#[derive(PartialEq, Eq)]
pub struct InviteToken {
    pub hub_url: String,
    pub invite_id: [u8; INVITE_ID_LEN],
    pub invite_secret: [u8; INVITE_SECRET_LEN],
    pub tenant_seed: [u8; TENANT_SEED_LEN],
}

impl fmt::Debug for InviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteToken")
            .field("hub_url", &self.hub_url)
            .field("invite_id", &hex::encode(self.invite_id))
            .field("invite_secret", &"<redacted>")
            .field("tenant_seed", &"<redacted>")
            .finish()
    }
}

impl Drop for InviteToken {
    fn drop(&mut self) {
        self.invite_secret.zeroize();
        self.tenant_seed.zeroize();
    }
}

impl InviteToken {
    #[must_use]
    pub fn new(
        hub_url: impl Into<String>,
        invite_id: [u8; INVITE_ID_LEN],
        invite_secret: [u8; INVITE_SECRET_LEN],
        tenant_seed: [u8; TENANT_SEED_LEN],
    ) -> Self {
        Self {
            hub_url: hub_url.into(),
            invite_id,
            invite_secret,
            tenant_seed,
        }
    }

    #[must_use]
    pub fn generate(hub_url: impl Into<String>) -> Self {
        let invite_id = fresh_bytes::<INVITE_ID_LEN>();
        let invite_secret = fresh_bytes::<INVITE_SECRET_LEN>();
        let tenant_seed = fresh_bytes::<TENANT_SEED_LEN>();
        Self::new(hub_url, invite_id, invite_secret, tenant_seed)
    }

    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{TENANT_TOKEN_PREFIX}{}.{}.{}.{}",
            B64.encode(self.hub_url.as_bytes()),
            B64.encode(self.invite_id),
            B64.encode(self.invite_secret),
            B64.encode(self.tenant_seed),
        )
    }

    pub fn decode(s: &str) -> Result<Self, InviteTokenError> {
        let body = s
            .strip_prefix(TENANT_TOKEN_PREFIX)
            .ok_or(InviteTokenError::WrongPrefix {
                expected: TENANT_TOKEN_PREFIX,
            })?;
        let parts: Vec<&str> = body.split('.').collect();
        if parts.len() != 4 {
            return Err(InviteTokenError::WrongSegmentCount {
                expected: 4,
                got: parts.len(),
            });
        }

        let hub_url = String::from_utf8(B64.decode(parts[0])?)?;

        let id_bytes = B64.decode(parts[1])?;
        let invite_id: [u8; INVITE_ID_LEN] = id_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteIdLen(id_bytes.len()))?;

        let secret_bytes = Zeroizing::new(B64.decode(parts[2])?);
        let invite_secret: [u8; INVITE_SECRET_LEN] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteSecretLen(secret_bytes.len()))?;

        let seed_bytes = Zeroizing::new(B64.decode(parts[3])?);
        let tenant_seed: [u8; TENANT_SEED_LEN] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadTenantSeedLen(seed_bytes.len()))?;

        Ok(Self {
            hub_url,
            invite_id,
            invite_secret,
            tenant_seed,
        })
    }

    #[must_use]
    pub fn invite_id_b64(&self) -> String {
        B64.encode(self.invite_id)
    }
}

/// A parsed edge invite token.
///
/// v2 format: `tt_edge_2_<b64(hub_url)>.<b64(invite_id)>.<b64(invite_secret)>.<b64(node_seed)>`.
/// The ed25519 node seed is embedded directly so a fresh VPS pod can derive
/// its iroh identity locally and start running without a separate redemption
/// step -- the hub pre-registers the edge's `node_id` at invite creation time.
///
/// Edge invites are non-expiring by design; operators revoke an invite to
/// cut off access (revocation takes effect on the next reconnect).
///
/// `invite_secret` and `node_seed` are zeroed on drop and redacted by the
/// [`fmt::Debug`] impl. Not `Clone` -- see [`InviteToken`] for the rationale.
#[derive(PartialEq, Eq)]
pub struct EdgeInviteToken {
    pub hub_url: String,
    pub invite_id: [u8; INVITE_ID_LEN],
    pub invite_secret: [u8; INVITE_SECRET_LEN],
    pub node_seed: [u8; EDGE_SEED_LEN],
}

impl fmt::Debug for EdgeInviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdgeInviteToken")
            .field("hub_url", &self.hub_url)
            .field("invite_id", &hex::encode(self.invite_id))
            .field("invite_secret", &"<redacted>")
            .field("node_seed", &"<redacted>")
            .finish()
    }
}

impl Drop for EdgeInviteToken {
    fn drop(&mut self) {
        self.invite_secret.zeroize();
        self.node_seed.zeroize();
    }
}

impl EdgeInviteToken {
    #[must_use]
    pub fn new(
        hub_url: impl Into<String>,
        invite_id: [u8; INVITE_ID_LEN],
        invite_secret: [u8; INVITE_SECRET_LEN],
        node_seed: [u8; EDGE_SEED_LEN],
    ) -> Self {
        Self {
            hub_url: hub_url.into(),
            invite_id,
            invite_secret,
            node_seed,
        }
    }

    #[must_use]
    pub fn generate(hub_url: impl Into<String>) -> Self {
        let invite_id = fresh_bytes::<INVITE_ID_LEN>();
        let invite_secret = fresh_bytes::<INVITE_SECRET_LEN>();
        let node_seed = fresh_bytes::<EDGE_SEED_LEN>();
        Self::new(hub_url, invite_id, invite_secret, node_seed)
    }

    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{EDGE_TOKEN_PREFIX}{}.{}.{}.{}",
            B64.encode(self.hub_url.as_bytes()),
            B64.encode(self.invite_id),
            B64.encode(self.invite_secret),
            B64.encode(self.node_seed),
        )
    }

    pub fn decode(s: &str) -> Result<Self, InviteTokenError> {
        let body = s
            .strip_prefix(EDGE_TOKEN_PREFIX)
            .ok_or(InviteTokenError::WrongPrefix {
                expected: EDGE_TOKEN_PREFIX,
            })?;
        let parts: Vec<&str> = body.split('.').collect();
        if parts.len() != 4 {
            return Err(InviteTokenError::WrongSegmentCount {
                expected: 4,
                got: parts.len(),
            });
        }

        let hub_url = String::from_utf8(B64.decode(parts[0])?)?;

        let id_bytes = B64.decode(parts[1])?;
        let invite_id: [u8; INVITE_ID_LEN] = id_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteIdLen(id_bytes.len()))?;

        let secret_bytes = Zeroizing::new(B64.decode(parts[2])?);
        let invite_secret: [u8; INVITE_SECRET_LEN] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteSecretLen(secret_bytes.len()))?;

        let seed_bytes = Zeroizing::new(B64.decode(parts[3])?);
        let node_seed: [u8; EDGE_SEED_LEN] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadNodeSeedLen(seed_bytes.len()))?;

        Ok(Self {
            hub_url,
            invite_id,
            invite_secret,
            node_seed,
        })
    }

    #[must_use]
    pub fn invite_id_b64(&self) -> String {
        B64.encode(self.invite_id)
    }
}

/// Operator secret for keyed hashing of invite secrets before DB storage.
/// Rotating invalidates every outstanding invite hash; treat as long-lived.
///
/// Not `Clone` — duplicating would leave two live copies of the secret
/// material. Wrap in `Arc<InviteHashKey>` at call sites that need sharing.
/// Zeroized on drop via [`Zeroizing`].
pub struct InviteHashKey(Zeroizing<[u8; 32]>);

impl InviteHashKey {
    pub fn from_hex(hex_str: &str) -> anyhow::Result<Self> {
        let bytes = Zeroizing::new(
            hex::decode(hex_str.trim())
                .map_err(|e| anyhow::anyhow!("invite hash key is not valid hex: {e}"))?,
        );
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("invite hash key must be exactly 32 bytes (64 hex chars)")
        })?;
        Ok(Self(Zeroizing::new(arr)))
    }

    #[must_use]
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        #[allow(clippy::expect_used)]
        getrandom::fill(k.as_mut_slice()).expect("OS RNG failed");
        Self(k)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for InviteHashKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteHashKey(***)")
    }
}

#[must_use]
pub fn hash_invite_secret(key: &InviteHashKey, secret: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key.as_bytes(), secret).as_bytes()
}

fn fresh_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    // OS RNG failure is unrecoverable at this layer.
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut buf).expect("OS RNG failed");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_v2_encode_decode_roundtrip() {
        let token = InviteToken::new(
            "https://node.towonel.example.eu:8443",
            [1u8; INVITE_ID_LEN],
            [2u8; INVITE_SECRET_LEN],
            [3u8; TENANT_SEED_LEN],
        );
        let encoded = token.encode();
        assert!(encoded.starts_with(TENANT_TOKEN_PREFIX));
        assert_eq!(InviteToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn edge_v2_encode_decode_roundtrip() {
        let token = EdgeInviteToken::new(
            "https://node.towonel.example.eu:8443",
            [3u8; INVITE_ID_LEN],
            [4u8; INVITE_SECRET_LEN],
            [5u8; EDGE_SEED_LEN],
        );
        let encoded = token.encode();
        assert!(encoded.starts_with(EDGE_TOKEN_PREFIX));
        assert_eq!(EdgeInviteToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn edge_v1_tokens_rejected() {
        assert!(matches!(
            EdgeInviteToken::decode("tt_edge_1_aaa.bbb.ccc"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
    }

    #[test]
    fn edge_rejects_bad_node_seed_len() {
        let encoded = format!(
            "{EDGE_TOKEN_PREFIX}{}.{}.{}.{}",
            B64.encode(b"https://hub"),
            B64.encode([1u8; INVITE_ID_LEN]),
            B64.encode([2u8; INVITE_SECRET_LEN]),
            B64.encode([3u8; 16]),
        );
        assert!(matches!(
            EdgeInviteToken::decode(&encoded),
            Err(InviteTokenError::BadNodeSeedLen(16))
        ));
    }

    #[test]
    fn tenant_and_edge_tokens_dont_cross_decode() {
        let tenant = InviteToken::new(
            "https://h",
            [1u8; INVITE_ID_LEN],
            [2u8; INVITE_SECRET_LEN],
            [5u8; TENANT_SEED_LEN],
        );
        let edge = EdgeInviteToken::new(
            "https://h",
            [1u8; INVITE_ID_LEN],
            [2u8; INVITE_SECRET_LEN],
            [6u8; EDGE_SEED_LEN],
        );

        assert!(matches!(
            EdgeInviteToken::decode(&tenant.encode()),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
        assert!(matches!(
            InviteToken::decode(&edge.encode()),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
    }

    #[test]
    fn tenant_v1_tokens_rejected() {
        assert!(matches!(
            InviteToken::decode("tt_inv_1_aaa.bbb.ccc"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(matches!(
            InviteToken::decode("tt_inv_0_aaa.bbb.ccc.ddd"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
        assert!(matches!(
            InviteToken::decode("not-a-token"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
    }

    #[test]
    fn tenant_rejects_three_segments() {
        let body = format!(
            "{TENANT_TOKEN_PREFIX}{}.{}.{}",
            B64.encode(b"https://hub"),
            B64.encode([1u8; INVITE_ID_LEN]),
            B64.encode([2u8; INVITE_SECRET_LEN]),
        );
        assert!(matches!(
            InviteToken::decode(&body),
            Err(InviteTokenError::WrongSegmentCount {
                expected: 4,
                got: 3
            })
        ));
    }

    #[test]
    fn tenant_rejects_bad_lengths() {
        let encoded = format!(
            "{TENANT_TOKEN_PREFIX}{}.{}.{}.{}",
            B64.encode(b"https://hub"),
            B64.encode([1u8; 8]),
            B64.encode([2u8; INVITE_SECRET_LEN]),
            B64.encode([3u8; TENANT_SEED_LEN]),
        );
        assert!(matches!(
            InviteToken::decode(&encoded),
            Err(InviteTokenError::BadInviteIdLen(8))
        ));
    }

    #[test]
    fn tenant_rejects_bad_tenant_seed_len() {
        let encoded = format!(
            "{TENANT_TOKEN_PREFIX}{}.{}.{}.{}",
            B64.encode(b"https://hub"),
            B64.encode([1u8; INVITE_ID_LEN]),
            B64.encode([2u8; INVITE_SECRET_LEN]),
            B64.encode([3u8; 16]),
        );
        assert!(matches!(
            InviteToken::decode(&encoded),
            Err(InviteTokenError::BadTenantSeedLen(16))
        ));
    }

    #[test]
    fn generate_produces_distinct_tokens() {
        let a = InviteToken::generate("https://hub");
        let b = InviteToken::generate("https://hub");
        assert_ne!(a.invite_id, b.invite_id);
        assert_ne!(a.invite_secret, b.invite_secret);
        assert_ne!(a.tenant_seed, b.tenant_seed);

        let c = EdgeInviteToken::generate("https://hub");
        let d = EdgeInviteToken::generate("https://hub");
        assert_ne!(c.invite_id, d.invite_id);
        assert_ne!(c.node_seed, d.node_seed);
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let key = InviteHashKey::generate();
        let h1 = hash_invite_secret(&key, &[1u8; 32]);
        let h2 = hash_invite_secret(&key, &[1u8; 32]);
        let h3 = hash_invite_secret(&key, &[2u8; 32]);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn hash_depends_on_key() {
        let k1 = InviteHashKey::generate();
        let k2 = InviteHashKey::generate();
        let secret = [7u8; 32];
        assert_ne!(
            hash_invite_secret(&k1, &secret),
            hash_invite_secret(&k2, &secret),
            "same secret under two keys must produce different hashes"
        );
    }

    #[test]
    fn hash_key_hex_roundtrip() {
        let k = InviteHashKey::generate();
        let hex_str = k.to_hex();
        let parsed = InviteHashKey::from_hex(&hex_str).unwrap();
        assert_eq!(k.as_bytes(), parsed.as_bytes());
    }
}
