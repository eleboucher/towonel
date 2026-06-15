//! Shared `Authorization: Signature <node_id>.<ts>.<sig>` scheme used by
//! agent → hub, edge → hub and hub → hub RPC.
//!
//! Callers on the signing side use [`sign_auth_header`]. Verifiers reconstruct
//! the same canonical message with [`canonical_message`] and [`body_hash_hex`]
//! (or use `hub::auth::verify_signature_header`, which wraps both).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use crate::identity::{
    PQ_SIGNATURE_LEN, PqPublicKey, TenantId, TenantKeypair, verify_pq_signature,
};

/// Lowercase hex of `blake3(body)`.
///
/// Used as the body-binding segment of the signed message so a captured
/// header can't be replayed with a different payload within the freshness
/// window. GET handlers pass `&[]`.
///
/// Wire-format note: previously SHA-256. Hub and agent/edge must roll
/// together — this is not backward-compatible.
#[must_use]
pub fn body_hash_hex(body: &[u8]) -> String {
    hex::encode(blake3::hash(body).as_bytes())
}

/// Canonical message covered by the signature:
/// `"<domain>/<node_id_hex>/<ts_ms>/<body_hex>"`.
#[must_use]
pub fn canonical_message(domain: &str, node_id_hex: &str, ts_ms: u64, body: &[u8]) -> String {
    let body_hex = body_hash_hex(body);
    format!("{domain}/{node_id_hex}/{ts_ms}/{body_hex}")
}

/// Abstracts the two signing-key types used for transport auth.
///
/// [`ed25519_dalek::SigningKey`] (agent) and [`iroh::SecretKey`] (edge, hub).
/// Tenant config signing uses ML-DSA-65 instead — see `config_entry`.
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

/// Auth domain for read-only tenant requests, signed with the tenant's
/// ML-DSA key.
///
/// Used by `GET` tenant entries. Distinct from the ed25519 transport domains
/// so a signature can't be replayed across schemes.
pub const TENANT_REQUEST_AUTH_DOMAIN: &str = "towonel/tenant-request/v1";

/// Canonical message a tenant-request signature covers:
/// `"<domain>/<tenant_id_hex>/<ts_ms>"`. Read-only GETs carry no body.
fn tenant_request_message(domain: &str, tenant_id: &TenantId, ts_ms: u64) -> String {
    format!("{domain}/{tenant_id}/{ts_ms}")
}

/// Build `Authorization: Signature <tenant_id_hex>.<ts_ms>.<sig_b64>` proving
/// possession of the tenant's ML-DSA key, for a read-only tenant request.
#[must_use]
pub fn sign_tenant_request_header(kp: &TenantKeypair, domain: &str, ts_ms: u64) -> String {
    let tenant_id = kp.id();
    let message = tenant_request_message(domain, &tenant_id, ts_ms);
    let sig = kp.sign(message.as_bytes());
    format!("Signature {tenant_id}.{ts_ms}.{}", B64.encode(sig))
}

/// Parse and verify a tenant-signed request header, returning the
/// authenticated `TenantId`.
///
/// `lookup` resolves the tenant's ML-DSA public key (`None` ⇒ unknown tenant).
/// Freshness-only (no nonce cache): fine for an idempotent read where a replay
/// just re-reads authorized data.
pub fn verify_tenant_request_header(
    header_value: &str,
    domain: &str,
    now_ms_val: u64,
    max_skew_ms: u64,
    lookup: impl FnOnce(&TenantId) -> Option<PqPublicKey>,
) -> Result<TenantId, &'static str> {
    let rest = header_value
        .strip_prefix("Signature ")
        .ok_or("Authorization must be `Signature <tenant_id>.<ts>.<sig>`")?;
    let mut parts = rest.splitn(3, '.');
    let tenant_hex = parts.next().ok_or("missing tenant_id segment")?;
    let ts_str = parts.next().ok_or("missing timestamp segment")?;
    let sig_b64 = parts.next().ok_or("missing signature segment")?;

    let tenant_id: TenantId = tenant_hex
        .parse()
        .map_err(|_e| "tenant_id is not 32 hex bytes")?;
    let ts_ms: u64 = ts_str.parse().map_err(|_e| "timestamp is not a u64")?;
    if now_ms_val.abs_diff(ts_ms) > max_skew_ms {
        return Err("timestamp outside freshness window");
    }
    let sig: [u8; PQ_SIGNATURE_LEN] = B64
        .decode(sig_b64)
        .map_err(|_e| "signature is not base64url")?
        .try_into()
        .map_err(|_e| "signature has wrong length")?;
    let pubkey = lookup(&tenant_id).ok_or("unknown tenant")?;
    let message = tenant_request_message(domain, &tenant_id, ts_ms);
    if !verify_pq_signature(&pubkey, message.as_bytes(), &sig) {
        return Err("signature does not verify");
    }
    Ok(tenant_id)
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

    #[test]
    fn tenant_request_round_trip_and_rejections() {
        let kp = TenantKeypair::generate();
        let pubkey = kp.public_key().clone();
        let header = sign_tenant_request_header(&kp, TENANT_REQUEST_AUTH_DOMAIN, 1000);

        // Valid signature within the freshness window verifies to the signer.
        let id =
            verify_tenant_request_header(&header, TENANT_REQUEST_AUTH_DOMAIN, 1000, 60_000, |_| {
                Some(pubkey.clone())
            })
            .expect("valid signature should verify");
        assert_eq!(id, kp.id());

        // Stale timestamp rejected.
        verify_tenant_request_header(
            &header,
            TENANT_REQUEST_AUTH_DOMAIN,
            1000 + 120_000,
            60_000,
            |_| Some(pubkey.clone()),
        )
        .unwrap_err();

        // Wrong domain rejected (signature covers the domain).
        verify_tenant_request_header(&header, "towonel/other/v1", 1000, 60_000, |_| {
            Some(pubkey.clone())
        })
        .unwrap_err();

        // Unknown tenant (lookup miss) rejected.
        verify_tenant_request_header(&header, TENANT_REQUEST_AUTH_DOMAIN, 1000, 60_000, |_| None)
            .unwrap_err();

        // A different key's signature does not verify against this pubkey.
        let other = TenantKeypair::generate();
        let other_header = sign_tenant_request_header(&other, TENANT_REQUEST_AUTH_DOMAIN, 1000);
        verify_tenant_request_header(
            &other_header,
            TENANT_REQUEST_AUTH_DOMAIN,
            1000,
            60_000,
            |_| Some(pubkey.clone()),
        )
        .unwrap_err();
    }
}
