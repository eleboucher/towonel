use anyhow::Context;
use serde::Deserialize;
use serde_json::json;

use super::{JSON_CONTENT_TYPE, check_response, resolve_hub_url, resolve_operator_key};

#[derive(Debug, Deserialize)]
struct ResyncResponse {
    tenants_ingested: usize,
    removals_ingested: usize,
    entries_ingested: usize,
    entries_skipped: usize,
}

pub async fn cmd_hub_resync(
    hub_url: Option<String>,
    api_key: Option<String>,
    peer_url: String,
    peer_key: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/admin/resync", hub_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let body = json!({
        "peer_url": peer_url,
        "peer_operator_key": peer_key,
    });
    let resp = client
        .post(&url)
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .json(&body)
        .send()
        .await
        .context("POST /v1/admin/resync")?;

    let bytes = check_response(resp).await?;
    let parsed: ResyncResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("unexpected response: {}", String::from_utf8_lossy(&bytes)))?;

    println!("resync complete:");
    println!("  tenants ingested: {}", parsed.tenants_ingested);
    println!("  removals ingested: {}", parsed.removals_ingested);
    println!("  entries ingested: {}", parsed.entries_ingested);
    println!("  entries skipped:  {}", parsed.entries_skipped);
    Ok(())
}
