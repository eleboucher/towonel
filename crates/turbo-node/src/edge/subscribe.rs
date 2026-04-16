use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use eventsource_stream::Eventsource;
use turbo_common::routing::RouteTable;

use super::router::Router;

const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 60;

/// Runs forever, applying `RouteTable` snapshots from the remote hub to
/// `router`. Returns only if `hub_url` is malformed; transient network
/// errors are logged and retried.
pub async fn run(
    hub_url: String,
    secret_key: iroh::SecretKey,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    let url = format!("{}/v1/routes/subscribe", hub_url.trim_end_matches('/'));
    let _ = reqwest::Url::parse(&url).context("invalid hub_url")?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building reqwest client")?;

    let mut backoff = RECONNECT_INITIAL_SECS;
    loop {
        match connect_and_stream(&client, &url, &secret_key, &router).await {
            Ok(()) => {
                tracing::info!("hub closed route subscription; reconnecting");
                backoff = RECONNECT_INITIAL_SECS;
            }
            Err(e) => {
                tracing::warn!(error = %e, "route subscription failed; backing off {}s", backoff);
            }
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(RECONNECT_MAX_SECS);
    }
}

async fn connect_and_stream(
    client: &reqwest::Client,
    url: &str,
    secret_key: &iroh::SecretKey,
    router: &Router,
) -> anyhow::Result<()> {
    let auth = signed_auth_header(secret_key);
    let resp = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .context("GET /v1/routes/subscribe")?
        .error_for_status()
        .context("hub rejected subscription")?;

    tracing::info!(hub = %url, "connected to hub route stream");

    use tokio_stream::StreamExt;
    let mut stream = resp.bytes_stream().eventsource();
    while let Some(result) = stream.next().await {
        match result {
            Ok(event) => {
                if event.event != "routes" {
                    tracing::debug!(kind = %event.event, "ignoring unknown SSE event");
                    continue;
                }
                apply_route_data(router, &event.data).await?;
            }
            Err(e) => {
                return Err(anyhow!("SSE stream error: {e}"));
            }
        }
    }
    Ok(())
}

fn signed_auth_header(secret_key: &iroh::SecretKey) -> String {
    let node_id = secret_key.public();
    let ts = turbo_common::time::now_ms();
    let message = format!("turbo-tunnel/edge-sub/v1/{node_id}/{ts}");
    let sig = secret_key.sign(message.as_bytes());
    format!("Signature {node_id}.{ts}.{}", B64.encode(sig.to_bytes()))
}

async fn apply_route_data(router: &Router, data: &str) -> anyhow::Result<()> {
    let cbor_bytes = B64
        .decode(data)
        .map_err(|e| anyhow!("routes event: base64 decode: {e}"))?;
    let table: RouteTable = ciborium::from_reader(cbor_bytes.as_slice())
        .map_err(|e| anyhow!("routes event: CBOR decode: {e}"))?;
    let count = table.len();
    router.replace(table).await;
    tracing::info!(hostnames = count, "applied route table from hub");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_auth_header_shape() {
        let sk = iroh::SecretKey::from([7u8; 32]);
        let h = signed_auth_header(&sk);
        assert!(h.starts_with("Signature "));
        let body = h.strip_prefix("Signature ").unwrap();
        let parts: Vec<&str> = body.split('.').collect();
        assert_eq!(parts.len(), 3, "node_id.ts.sig");
        assert_eq!(parts[0].len(), 64, "node_id is 64 hex chars");
        let _ts: u64 = parts[1].parse().expect("ts parses as u64");
        let sig = B64.decode(parts[2]).expect("sig is base64url");
        assert_eq!(sig.len(), 64, "ed25519 sig is 64 bytes");
    }
}
