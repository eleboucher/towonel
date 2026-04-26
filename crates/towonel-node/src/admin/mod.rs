//! Operator-facing management commands -- the admin surface of the unified
//! `towonel` binary. Each submodule groups related commands; shared helpers
//! (URL/key resolution, response checking) live here.

pub mod entry;
pub mod invite;
pub mod tenant;

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use ed25519_dalek::SigningKey;
use towonel_common::hub_error;
use towonel_common::identity::write_key_file;

pub use towonel_common::CBOR_CONTENT_TYPE;
pub use towonel_common::JSON_CONTENT_TYPE_PLAIN as JSON_CONTENT_TYPE;

const OPERATOR_KEY_ENV: &str = "TOWONEL_OPERATOR_KEY";
const HUB_URL_ENV: &str = "TOWONEL_HUB_URL";
const HUB_LISTEN_ADDR_ENV: &str = "TOWONEL_HUB_LISTEN_ADDR";
const OPERATOR_KEY_PATH_ENV: &str = "TOWONEL_HUB_OPERATOR_API_KEY_PATH";
const DEFAULT_HUB_LISTEN_ADDR: &str = "0.0.0.0:8443";
const DEFAULT_OPERATOR_KEY_PATH: &str = "operator.key";

/// Check an HTTP response and return the body bytes on success, or a
/// formatted error on failure.
pub async fn check_response(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let status = resp.status();
    let body = resp.bytes().await?.to_vec();
    if status.is_success() {
        return Ok(body);
    }
    Err(hub_error::parse(status.as_u16(), &body).map_or_else(
        || {
            let preview = String::from_utf8_lossy(&body);
            anyhow!("hub returned {status}: {preview}")
        },
        Into::into,
    ))
}

pub fn resolve_hub_url(flag: Option<String>) -> String {
    if let Some(v) = flag {
        return v;
    }
    if let Ok(v) = std::env::var(HUB_URL_ENV) {
        return v;
    }
    // When running on the hub host, derive a loopback URL from the hub's
    // listen address so admin commands work without flags.
    let listen =
        std::env::var(HUB_LISTEN_ADDR_ENV).unwrap_or_else(|_| DEFAULT_HUB_LISTEN_ADDR.to_string());
    let port = listen.rsplit(':').next().unwrap_or("8443");
    format!("http://127.0.0.1:{port}")
}

pub fn resolve_tenant_key_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    flag.ok_or_else(|| {
        anyhow!(
            "--key-path not provided. Create a tenant key with `towonel tenant init` \
             and pass its path via --key-path."
        )
    })
}

pub fn resolve_operator_key(flag: Option<String>) -> anyhow::Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(OPERATOR_KEY_ENV) {
        return Ok(v);
    }
    let path = std::env::var(OPERATOR_KEY_PATH_ENV)
        .unwrap_or_else(|_| DEFAULT_OPERATOR_KEY_PATH.to_string());
    if let Ok(content) = std::fs::read_to_string(&path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!(
        "no operator API key available. Pass --api-key, set ${OPERATOR_KEY_ENV}, \
         or ensure the key file exists at {path} (override with ${OPERATOR_KEY_PATH_ENV})."
    ))
}

pub fn generate_and_save_agent_key(path: &Path) -> anyhow::Result<SigningKey> {
    let mut key_bytes = [0u8; 32];
    // OS RNG failures are unrecoverable and should not happen on any supported platform.
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut key_bytes).expect("OS RNG failed");
    let key = SigningKey::from_bytes(&key_bytes);
    write_key_file(path, &key.to_bytes())
        .with_context(|| format!("failed to write key file: {}", path.display()))?;
    Ok(key)
}
