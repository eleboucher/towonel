//! Minimal hub RPC helpers shared by `stateless::{register, heartbeat}` and
//! `publish_tls`. Not a full SDK -- just POST-signed-entry + CBOR response
//! checking.

use anyhow::{Context, anyhow};
use serde::Deserialize;
use towonel_common::CBOR_CONTENT_TYPE;
use towonel_common::config_entry::{ConfigPayload, SignedConfigEntry};
use towonel_common::identity::TenantKeypair;

/// Typed error returned by the hub under the standard error envelope.
/// Downcast from an `anyhow::Error` via `err.downcast_ref::<HubApiError>()`.
#[derive(Debug, thiserror::Error)]
#[error("hub returned {status} ({code}): {message}")]
pub struct HubApiError {
    pub status: reqwest::StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorFields,
}

#[derive(Deserialize)]
struct ErrorFields {
    code: String,
    message: String,
}

/// Check an HTTP response and return the body bytes on success. On failure,
/// parses the hub's standard error envelope (`{"error":{"code","message"}}`)
/// into a typed [`HubApiError`] so callers can pattern-match on the code
/// instead of sniffing error strings.
pub async fn check_response(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let status = resp.status();
    let body = resp.bytes().await?.to_vec();
    if !status.is_success() {
        return Err(
            if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
                HubApiError {
                    status,
                    code: env.error.code,
                    message: env.error.message,
                }
                .into()
            } else {
                anyhow!("hub returned {status} with unparsable error body")
            },
        );
    }
    Ok(body)
}

/// Sign `payload` with `kp` and POST it to `/v1/entries` as CBOR. Returns
/// the parsed status or the error returned by the hub. Used by agent boot
/// (`UpsertAgent`) and by TLS policy publish.
pub async fn submit_entry(
    client: &reqwest::Client,
    hub_url: &str,
    kp: &TenantKeypair,
    payload: ConfigPayload,
) -> anyhow::Result<()> {
    let entry = SignedConfigEntry::sign(&payload, kp)?;
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body)?;

    let url = format!("{}/v1/entries", hub_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

    check_response(resp).await?;
    Ok(())
}

/// `true` if the last error from [`submit_entry`] is a `sequence_conflict`
/// -- an optimistic-concurrency race between multiple replicas picking the
/// same `max(sequence)+1`. The caller should re-fetch entries and retry.
#[must_use]
pub fn is_sequence_conflict(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HubApiError>()
        .is_some_and(|e| e.code == "sequence_conflict")
}

/// Fetch all signed entries for `tenant_id` and return the largest
/// `sequence` number. Returns 0 when the tenant has no entries yet.
pub async fn fetch_latest_sequence(
    client: &reqwest::Client,
    hub_url: &str,
    kp: &TenantKeypair,
) -> anyhow::Result<u64> {
    let url = format!(
        "{}/v1/tenants/{}/entries",
        hub_url.trim_end_matches('/'),
        kp.id(),
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    if !resp.status().is_success() {
        return Ok(0);
    }
    let bytes = resp.bytes().await?;
    let entries: Vec<SignedConfigEntry> = ciborium::from_reader(bytes.as_ref())
        .context("hub returned malformed tenant-entries CBOR")?;
    let pq_pubkey = kp.public_key();
    let mut max_seq = 0u64;
    for entry in &entries {
        if let Ok(payload) = entry.verify(pq_pubkey) {
            max_seq = max_seq.max(payload.sequence);
        }
    }
    Ok(max_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sequence_conflict_matches_typed_api_error() {
        let err: anyhow::Error = HubApiError {
            status: reqwest::StatusCode::CONFLICT,
            code: "sequence_conflict".to_string(),
            message: "sequence number already used".to_string(),
        }
        .into();
        assert!(is_sequence_conflict(&err));
    }

    #[test]
    fn is_sequence_conflict_rejects_other_codes() {
        let err: anyhow::Error = HubApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            code: "tenant_not_allowed".to_string(),
            message: String::new(),
        }
        .into();
        assert!(!is_sequence_conflict(&err));
    }

    #[test]
    fn is_sequence_conflict_rejects_bare_anyhow() {
        // A string-only anyhow error that happens to contain the magic word
        // must NOT be a false positive -- the whole point of the typed error
        // is to stop sniffing strings.
        let err = anyhow!("hub returned 500: sequence_conflict-ish text");
        assert!(!is_sequence_conflict(&err));
    }
}
