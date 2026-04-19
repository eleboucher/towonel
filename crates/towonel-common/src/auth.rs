//! Shared `Authorization: Signature <node_id>.<ts>.<sig>` scheme used by
//! agent → hub, edge → hub and hub → hub RPC.
//!
//! Callers on the signing side use [`sign_auth_header`]. Verifiers reconstruct
//! the same canonical message with [`canonical_message`] and [`body_hash_hex`]
//! (or use `hub::auth::verify_signature_header`, which wraps both).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};

/// Lowercase hex of `SHA-256(body)`, the body-binding segment of the signed
/// message. GET handlers pass `&[]`.
#[must_use]
pub fn body_hash_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Canonical message covered by the signature:
/// `"<domain>/<node_id_hex>/<ts_ms>/<body_hex>"`.
#[must_use]
pub fn canonical_message(domain: &str, node_id_hex: &str, ts_ms: u64, body: &[u8]) -> String {
    let body_hex = body_hash_hex(body);
    format!("{domain}/{node_id_hex}/{ts_ms}/{body_hex}")
}

/// Abstracts the two signing-key types used across the workspace:
/// [`ed25519_dalek::SigningKey`] (agent) and [`iroh::SecretKey`] (edge, hub).
pub trait AuthSigner {
    fn public_key_bytes(&self) -> [u8; 32];
    fn sign_bytes(&self, msg: &[u8]) -> [u8; 64];
}

impl AuthSigner for ed25519_dalek::SigningKey {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    fn sign_bytes(&self, msg: &[u8]) -> [u8; 64] {
        ed25519_dalek::Signer::sign(self, msg).to_bytes()
    }
}

impl AuthSigner for iroh::SecretKey {
    fn public_key_bytes(&self) -> [u8; 32] {
        *self.public().as_bytes()
    }
    fn sign_bytes(&self, msg: &[u8]) -> [u8; 64] {
        self.sign(msg).to_bytes()
    }
}

/// Build an `Authorization: Signature <node_id>.<ts>.<sig>` header. `body`
/// is hashed into the signed message so the signature covers the request
/// payload; pass `&[]` for GET handlers.
pub fn sign_auth_header<S: AuthSigner>(
    signer: &S,
    domain: &str,
    ts_ms: u64,
    body: &[u8],
) -> String {
    let node_id_hex = hex::encode(signer.public_key_bytes());
    let message = canonical_message(domain, &node_id_hex, ts_ms, body);
    let sig = signer.sign_bytes(message.as_bytes());
    format!("Signature {node_id_hex}.{ts_ms}.{}", B64.encode(sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_binding_changes_signature() {
        let sk = iroh::SecretKey::from([7u8; 32]);
        let a = sign_auth_header(&sk, "towonel/test/v1", 42, b"body-a");
        let b = sign_auth_header(&sk, "towonel/test/v1", 42, b"body-b");
        assert_ne!(a, b);
    }

    #[test]
    fn dalek_and_iroh_produce_same_header_for_same_secret_bytes() {
        let bytes = [9u8; 32];
        let dalek = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let iroh_sk = iroh::SecretKey::from(bytes);
        let a = sign_auth_header(&dalek, "towonel/test/v1", 100, b"x");
        let b = sign_auth_header(&iroh_sk, "towonel/test/v1", 100, b"x");
        assert_eq!(a, b);
    }

    #[test]
    fn header_shape() {
        let sk = iroh::SecretKey::from([1u8; 32]);
        let h = sign_auth_header(&sk, "towonel/test/v1", 42, b"");
        let body = h.strip_prefix("Signature ").expect("prefix");
        let parts: Vec<&str> = body.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 64);
        assert_eq!(parts[1], "42");
    }
}
