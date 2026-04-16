use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;

/// Length of `invite_id` in bytes.
pub const INVITE_ID_LEN: usize = 16;
/// Length of `invite_secret` in bytes.
pub const INVITE_SECRET_LEN: usize = 32;

const TENANT_TOKEN_PREFIX: &str = "tt_inv_1_";
const EDGE_TOKEN_PREFIX: &str = "tt_edge_1_";

#[derive(Debug, thiserror::Error)]
pub enum InviteTokenError {
    #[error("invite token has the wrong prefix (expected `{expected}`)")]
    WrongPrefix { expected: &'static str },
    #[error("invite token must contain exactly three dot-separated segments")]
    WrongSegmentCount,
    #[error("invite token segment is not valid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invite token hub_url is not valid UTF-8: {0}")]
    HubUrlEncoding(#[from] std::string::FromUtf8Error),
    #[error("invite_id must be exactly {INVITE_ID_LEN} bytes, got {0}")]
    BadInviteIdLen(usize),
    #[error("invite_secret must be exactly {INVITE_SECRET_LEN} bytes, got {0}")]
    BadInviteSecretLen(usize),
}

/// A parsed tenant invite token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteToken {
    pub hub_url: String,
    pub invite_id: [u8; INVITE_ID_LEN],
    pub invite_secret: [u8; INVITE_SECRET_LEN],
}

/// A parsed edge invite token — same structure as [`InviteToken`], different
/// prefix, redeemed by a VPS operator to register as an edge node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeInviteToken {
    pub hub_url: String,
    pub invite_id: [u8; INVITE_ID_LEN],
    pub invite_secret: [u8; INVITE_SECRET_LEN],
}

/// Implement encode/decode/generate for an invite token type with a given prefix.
macro_rules! impl_invite_token {
    ($Type:ident, $prefix:expr) => {
        impl $Type {
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

            pub fn generate(hub_url: impl Into<String>) -> Self {
                let (id, secret) = fresh_id_and_secret();
                Self::new(hub_url, id, secret)
            }

            pub fn encode(&self) -> String {
                encode_v1($prefix, &self.hub_url, &self.invite_id, &self.invite_secret)
            }

            pub fn decode(s: &str) -> Result<Self, InviteTokenError> {
                let (hub_url, invite_id, invite_secret) = decode_v1($prefix, s)?;
                Ok(Self {
                    hub_url,
                    invite_id,
                    invite_secret,
                })
            }

            /// Base64url-encoded id (how the id appears in the token and API).
            pub fn invite_id_b64(&self) -> String {
                B64.encode(self.invite_id)
            }
        }
    };
}

impl_invite_token!(InviteToken, TENANT_TOKEN_PREFIX);
impl_invite_token!(EdgeInviteToken, EDGE_TOKEN_PREFIX);

impl InviteToken {
    /// Short human-readable form of the invite id (first 8 hex chars).
    pub fn invite_id_short(&self) -> String {
        hex::encode(&self.invite_id[..4])
    }
}

/// SHA-256 of an invite secret — what the hub stores and compares against
/// during redemption. Never the raw secret.
pub fn hash_invite_secret(secret: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(secret);
    hasher.finalize().into()
}

fn fresh_id_and_secret() -> ([u8; INVITE_ID_LEN], [u8; INVITE_SECRET_LEN]) {
    let mut id = [0u8; INVITE_ID_LEN];
    let mut secret = [0u8; INVITE_SECRET_LEN];
    getrandom::fill(&mut id).expect("OS RNG failed");
    getrandom::fill(&mut secret).expect("OS RNG failed");
    (id, secret)
}

fn encode_v1(
    prefix: &str,
    hub_url: &str,
    id: &[u8; INVITE_ID_LEN],
    secret: &[u8; INVITE_SECRET_LEN],
) -> String {
    format!(
        "{prefix}{}.{}.{}",
        B64.encode(hub_url.as_bytes()),
        B64.encode(id),
        B64.encode(secret),
    )
}

fn decode_v1(
    prefix: &'static str,
    s: &str,
) -> Result<(String, [u8; INVITE_ID_LEN], [u8; INVITE_SECRET_LEN]), InviteTokenError> {
    let body = s
        .strip_prefix(prefix)
        .ok_or(InviteTokenError::WrongPrefix { expected: prefix })?;
    let parts: Vec<&str> = body.split('.').collect();
    if parts.len() != 3 {
        return Err(InviteTokenError::WrongSegmentCount);
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

    Ok((hub_url, invite_id, invite_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_encode_decode_roundtrip() {
        let token = InviteToken::new(
            "https://node.turbo.example.eu:8443",
            [1u8; INVITE_ID_LEN],
            [2u8; INVITE_SECRET_LEN],
        );
        let encoded = token.encode();
        assert!(encoded.starts_with(TENANT_TOKEN_PREFIX));
        assert_eq!(InviteToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn edge_encode_decode_roundtrip() {
        let token = EdgeInviteToken::new(
            "https://node.turbo.example.eu:8443",
            [3u8; INVITE_ID_LEN],
            [4u8; INVITE_SECRET_LEN],
        );
        let encoded = token.encode();
        assert!(encoded.starts_with(EDGE_TOKEN_PREFIX));
        assert_eq!(EdgeInviteToken::decode(&encoded).unwrap(), token);
    }

    /// Tenant and edge tokens must not be mistakenly decoded as each other.
    #[test]
    fn tenant_and_edge_tokens_dont_cross_decode() {
        let tenant = InviteToken::new("https://h", [1u8; INVITE_ID_LEN], [2u8; INVITE_SECRET_LEN]);
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
    fn rejects_wrong_prefix() {
        assert!(matches!(
            InviteToken::decode("tt_inv_0_aaa.bbb.ccc"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
        assert!(matches!(
            InviteToken::decode("not-a-token"),
            Err(InviteTokenError::WrongPrefix { .. })
        ));
    }

    #[test]
    fn rejects_wrong_segment_count() {
        assert!(matches!(
            InviteToken::decode("tt_inv_1_one.two"),
            Err(InviteTokenError::WrongSegmentCount)
        ));
        assert!(matches!(
            InviteToken::decode("tt_inv_1_one.two.three.four"),
            Err(InviteTokenError::WrongSegmentCount)
        ));
    }

    #[test]
    fn rejects_bad_lengths() {
        let encoded = format!(
            "{TENANT_TOKEN_PREFIX}{}.{}.{}",
            B64.encode(b"https://hub"),
            B64.encode([1u8; 8]),
            B64.encode([2u8; INVITE_SECRET_LEN]),
        );
        assert!(matches!(
            InviteToken::decode(&encoded),
            Err(InviteTokenError::BadInviteIdLen(8))
        ));
    }

    #[test]
    fn generate_produces_distinct_tokens() {
        let a = InviteToken::generate("https://hub");
        let b = InviteToken::generate("https://hub");
        assert_ne!(a.invite_id, b.invite_id);
        assert_ne!(a.invite_secret, b.invite_secret);

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
