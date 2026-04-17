use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use turbo_common::time::now_ms;

/// Parse and verify `Authorization: Signature <node_id_hex>.<ts_ms>.<sig_b64>`.
///
/// Returns the 32-byte `node_id` on success. The caller is responsible for
/// checking whether that `node_id` is authorized (e.g. trusted peer, registered
/// edge, etc.).
///
/// `auth_domain` is the string prepended to the signed message
/// (e.g. `"turbo-tunnel/federation/v1"` or `"turbo-tunnel/edge-sub/v1"`).
/// `max_skew_ms` is the maximum allowed clock skew in milliseconds.
pub fn verify_signature_header(
    headers: &HeaderMap,
    auth_domain: &str,
    max_skew_ms: u64,
) -> Result<([u8; 32], u64), &'static str> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .ok_or("missing Authorization header")?
        .to_str()
        .map_err(|_| "malformed Authorization header")?;
    let body = auth
        .strip_prefix("Signature ")
        .ok_or("Authorization must be `Signature <node_id>.<ts>.<sig>`")?;

    let mut parts = body.splitn(3, '.');
    let node_id_hex = parts.next().ok_or("missing node_id segment")?;
    let ts_str = parts.next().ok_or("missing timestamp segment")?;
    let sig_b64 = parts.next().ok_or("missing signature segment")?;

    let node_id_bytes: [u8; 32] = hex::decode(node_id_hex)
        .map_err(|_| "node_id is not hex")?
        .try_into()
        .map_err(|_| "node_id must be 32 bytes")?;

    let ts_ms: u64 = ts_str.parse().map_err(|_| "timestamp is not a u64")?;
    if now_ms().abs_diff(ts_ms) > max_skew_ms {
        return Err("timestamp outside freshness window");
    }

    let sig_arr: [u8; 64] = B64
        .decode(sig_b64)
        .map_err(|_| "signature is not base64url")?
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;

    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&node_id_bytes)
        .map_err(|_| "node_id is not a valid Ed25519 public key")?;
    let message = format!("{auth_domain}/{node_id_hex}/{ts_ms}");
    pubkey
        .verify_strict(
            message.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_arr),
        )
        .map_err(|_| "signature does not verify")?;

    Ok((node_id_bytes, ts_ms))
}
