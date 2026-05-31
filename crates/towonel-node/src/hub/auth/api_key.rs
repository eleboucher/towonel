//! Personal API key token shape: `twk_<secret>` where `secret` is
//! `base64url(32 random bytes)`. Only `sha256(secret)` is stored in
//! `api_keys.key_hash`; the raw token is shown to the user exactly once at
//! creation and never persisted, so a DB read leak can't reconstruct a key.
//!
//! Unlike session cookies there's no separate id component in the token — the
//! row id is for management (list/revoke) only, and lookup is by the unique
//! `key_hash` index.
#![allow(dead_code, reason = "consumed by web routes once mounted")]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};

/// Prefix that marks a `Bearer` token as a user API key (vs. the operator
/// key, which is a bare base64url string with no prefix). Lets the auth
/// extractor route the two without a constant-time compare against every key.
pub const KEY_PREFIX: &str = "twk_";

const SECRET_BYTES: usize = 32;

pub struct NewApiKey {
    /// Full token to hand back to the caller once: `twk_<secret>`.
    pub token: String,
    /// `sha256(secret)` — the only form that lands in the DB.
    pub key_hash: [u8; 32],
}

#[must_use]
pub fn mint() -> NewApiKey {
    let mut secret_bytes = [0u8; SECRET_BYTES];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG failure at runtime is unrecoverable"
    )]
    getrandom::fill(&mut secret_bytes).expect("OS RNG");
    let secret = B64.encode(secret_bytes);
    let key_hash = hash_secret(&secret);
    NewApiKey {
        token: format!("{KEY_PREFIX}{secret}"),
        key_hash,
    }
}

/// Parse a `Bearer` value into `sha256(secret)`. Returns `None` when the
/// token doesn't carry the API-key prefix or has an empty secret — callers
/// treat that the same as "not an API key" and fall through to other auth.
#[must_use]
pub fn parse(bearer_token: &str) -> Option<[u8; 32]> {
    let secret = bearer_token.strip_prefix(KEY_PREFIX)?;
    if secret.is_empty() {
        return None;
    }
    Some(hash_secret(secret))
}

fn hash_secret(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_parse_round_trips() {
        let k = mint();
        assert!(k.token.starts_with(KEY_PREFIX));
        let parsed = parse(&k.token).expect("parse");
        assert_eq!(parsed, k.key_hash);
    }

    #[test]
    fn parse_rejects_non_prefixed() {
        assert!(parse("deadbeef").is_none());
        assert!(parse("Bearer twk_abc").is_none());
        assert!(parse("twk_").is_none());
    }
}
