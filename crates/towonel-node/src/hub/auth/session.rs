//! Session token shape: `<id>.<secret>` where
//!   - `id` is `base64url(16 random bytes)` — joined against `sessions.id`.
//!   - `secret` is `base64url(32 random bytes)` — only `sha256(secret)` is
//!     stored in `sessions.token_hash`. The raw secret never lands in the DB,
//!     so a DB read leak doesn't grant session takeover.
#![allow(dead_code, reason = "consumed by web routes once mounted")]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};

pub const COOKIE_NAME: &str = "towonel_session";

const ID_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;

pub struct NewSession {
    pub id: String,
    pub cookie_value: String,
    pub token_hash: [u8; 32],
}

#[must_use]
pub fn mint() -> NewSession {
    let mut id_bytes = [0u8; ID_BYTES];
    let mut secret_bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut id_bytes).expect("OS RNG");
    getrandom::fill(&mut secret_bytes).expect("OS RNG");

    let id = B64.encode(id_bytes);
    let secret = B64.encode(secret_bytes);
    let cookie_value = format!("{id}.{secret}");

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let token_hash: [u8; 32] = hasher.finalize().into();

    NewSession {
        id,
        cookie_value,
        token_hash,
    }
}

/// Parse a cookie value back into `(session_id, sha256(secret))`. Returns
/// `None` for malformed inputs — callers treat that the same as "no session".
#[must_use]
pub fn parse(cookie_value: &str) -> Option<(String, [u8; 32])> {
    let (id, secret) = cookie_value.split_once('.')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let token_hash: [u8; 32] = hasher.finalize().into();
    Some((id.to_string(), token_hash))
}

#[must_use]
pub fn set_cookie_header(value: &str, max_age_secs: u64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{secure_attr}"
    )
}

#[must_use]
pub fn clear_cookie_header(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_attr}")
}

#[must_use]
pub fn extract_from_cookie_header(header: &str) -> Option<&str> {
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(concat!("towonel_session", "=")) {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_parse_round_trips() {
        let s = mint();
        let (id, hash) = parse(&s.cookie_value).expect("parse");
        assert_eq!(id, s.id);
        assert_eq!(hash, s.token_hash);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse("no-dot-here").is_none());
        assert!(parse(".onlyright").is_none());
        assert!(parse("onlyleft.").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn extract_finds_cookie_among_others() {
        let header = "_ga=GA1.1.x; towonel_session=abc.def; foo=bar";
        assert_eq!(extract_from_cookie_header(header), Some("abc.def"));
    }

    #[test]
    fn extract_returns_none_when_absent() {
        assert!(extract_from_cookie_header("_ga=GA1.1.x; foo=bar").is_none());
    }
}
