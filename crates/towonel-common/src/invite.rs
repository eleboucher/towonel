use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use zeroize::Zeroize;

/// Length of `invite_id` in bytes.
pub const INVITE_ID_LEN: usize = 16;
/// Length of `invite_secret` in bytes.
pub const INVITE_SECRET_LEN: usize = 32;
/// Length of the embedded tenant ML-DSA-65 seed in bytes.
pub const TENANT_SEED_LEN: usize = 32;

const TENANT_TOKEN_PREFIX: &str = "tt_inv_2_";
const EDGE_TOKEN_PREFIX: &str = "tt_edge_1_";

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

        let secret_bytes = B64.decode(parts[2])?;
        let invite_secret: [u8; INVITE_SECRET_LEN] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteSecretLen(secret_bytes.len()))?;

        let seed_bytes = B64.decode(parts[3])?;
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

/// A parsed edge invite token -- same v1 3-segment shape as before, different
/// prefix, redeemed by a VPS operator to register as an edge node.
///
/// `invite_secret` is zeroed on drop and redacted by [`fmt::Debug`].
/// Not `Clone` -- see [`InviteToken`] for the rationale.
#[derive(PartialEq, Eq)]
pub struct EdgeInviteToken {
    pub hub_url: String,
    pub invite_id: [u8; INVITE_ID_LEN],
    pub invite_secret: [u8; INVITE_SECRET_LEN],
}

impl fmt::Debug for EdgeInviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdgeInviteToken")
            .field("hub_url", &self.hub_url)
            .field("invite_id", &hex::encode(self.invite_id))
            .field("invite_secret", &"<redacted>")
            .finish()
    }
}

impl Drop for EdgeInviteToken {
    fn drop(&mut self) {
        self.invite_secret.zeroize();
    }
}

impl EdgeInviteToken {
    #[must_use]
    pub fn new(
        hub_url: impl Into<String>,
        invite_id: [u8; INVITE_ID_LEN],
        invite_secret: [u8; INVITE_SECRET_LEN],
    ) -> Self {
        Self {
            hub_url: hub_url.into(),
            invite_id,
            invite_secret,
        }
    }

    #[must_use]
    pub fn generate(hub_url: impl Into<String>) -> Self {
        let invite_id = fresh_bytes::<INVITE_ID_LEN>();
        let invite_secret = fresh_bytes::<INVITE_SECRET_LEN>();
        Self::new(hub_url, invite_id, invite_secret)
    }

    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{EDGE_TOKEN_PREFIX}{}.{}.{}",
            B64.encode(self.hub_url.as_bytes()),
            B64.encode(self.invite_id),
            B64.encode(self.invite_secret),
        )
    }

    pub fn decode(s: &str) -> Result<Self, InviteTokenError> {
        let body = s
            .strip_prefix(EDGE_TOKEN_PREFIX)
            .ok_or(InviteTokenError::WrongPrefix {
                expected: EDGE_TOKEN_PREFIX,
            })?;
        let parts: Vec<&str> = body.split('.').collect();
        if parts.len() != 3 {
            return Err(InviteTokenError::WrongSegmentCount {
                expected: 3,
                got: parts.len(),
            });
        }

        let hub_url = String::from_utf8(B64.decode(parts[0])?)?;

        let id_bytes = B64.decode(parts[1])?;
        let invite_id: [u8; INVITE_ID_LEN] = id_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteIdLen(id_bytes.len()))?;

        let secret_bytes = B64.decode(parts[2])?;
        let invite_secret: [u8; INVITE_SECRET_LEN] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InviteTokenError::BadInviteSecretLen(secret_bytes.len()))?;

        Ok(Self {
            hub_url,
            invite_id,
            invite_secret,
        })
    }

    #[must_use]
    pub fn invite_id_b64(&self) -> String {
        B64.encode(self.invite_id)
    }
}

/// SHA-256 of an invite secret -- what the hub stores and compares against
/// during redemption. Never the raw secret.
#[must_use]
pub fn hash_invite_secret(secret: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(secret);
    hasher.finalize().into()
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
    fn edge_v1_encode_decode_roundtrip() {
        let token = EdgeInviteToken::new(
            "https://node.towonel.example.eu:8443",
            [3u8; INVITE_ID_LEN],
            [4u8; INVITE_SECRET_LEN],
        );
        let encoded = token.encode();
        assert!(encoded.starts_with(EDGE_TOKEN_PREFIX));
        assert_eq!(EdgeInviteToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn tenant_and_edge_tokens_dont_cross_decode() {
        let tenant = InviteToken::new(
            "https://h",
            [1u8; INVITE_ID_LEN],
            [2u8; INVITE_SECRET_LEN],
            [5u8; TENANT_SEED_LEN],
        );
        let edge =
            EdgeInviteToken::new("https://h", [1u8; INVITE_ID_LEN], [2u8; INVITE_SECRET_LEN]);

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
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let h1 = hash_invite_secret(&[1u8; 32]);
        let h2 = hash_invite_secret(&[1u8; 32]);
        let h3 = hash_invite_secret(&[2u8; 32]);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }
}
