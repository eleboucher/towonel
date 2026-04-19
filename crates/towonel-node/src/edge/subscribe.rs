use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use eventsource_stream::Eventsource;
use towonel_common::auth::sign_auth_header;
use towonel_common::routing::RouteTable;

use super::router::Router;

const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 60;

/// Runs forever, applying `RouteTable` snapshots from a remote hub to
/// `router`. On disconnect the task rotates through `hub_urls` before
/// applying exponential back-off, providing automatic hub failover when
/// multiple federated hubs are configured.
pub async fn run(
    hub_urls: Vec<String>,
    secret_key: iroh::SecretKey,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    if hub_urls.is_empty() {
        return Ok(());
    }

    let urls: Vec<String> = hub_urls
        .iter()
        .map(|base| {
            let url = format!("{}/v1/routes/subscribe", base.trim_end_matches('/'));
            reqwest::Url::parse(&url).context("invalid hub_url")?;
            Ok(url)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building reqwest client")?;

    let mut backoff = RECONNECT_INITIAL_SECS;
    let mut idx = 0usize; // index into `urls`, rotated on each attempt

    loop {
        let url = &urls[idx];
        match connect_and_stream(&client, url, &secret_key, &router).await {
            Ok(()) => {
                tracing::info!(%url, "hub closed route subscription; reconnecting");
                backoff = RECONNECT_INITIAL_SECS;
            }
            Err(e) => {
                let next_idx = (idx + 1) % urls.len();
                if urls.len() > 1 {
                    tracing::warn!(
                        error = %e,
                        current_hub = %url,
                        next_hub = %urls[next_idx],
                        "route subscription failed; rotating hub and backing off {}s",
                        backoff,
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        "route subscription failed; backing off {}s",
                        backoff
                    );
                }
                idx = next_idx;
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
    use tokio_stream::StreamExt;

    let auth = sign_auth_header(
        secret_key,
        "towonel/edge-sub/v1",
        towonel_common::time::now_ms(),
        &[],
    );
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
    let mut stream = resp.bytes_stream().eventsource();
    while let Some(result) = stream.next().await {
        match result {
            Ok(event) => {
                if event.event != "routes" {
                    tracing::debug!(kind = %event.event, "ignoring unknown SSE event");
                    continue;
                }
                apply_route_data(router, &event.data)?;
            }
            Err(e) => {
                return Err(anyhow!("SSE stream error: {e}"));
            }
        }
    }
    Ok(())
}

fn apply_route_data(router: &Router, data: &str) -> anyhow::Result<()> {
    let cbor_bytes = B64
        .decode(data)
        .map_err(|e| anyhow!("routes event: base64 decode: {e}"))?;
    let table: RouteTable = ciborium::from_reader(cbor_bytes.as_slice())
        .map_err(|e| anyhow!("routes event: CBOR decode: {e}"))?;
    let count = table.len();
    router.replace(table);
    tracing::info!(hostnames = count, "applied route table from hub");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_hub_urls_returns_immediately() {
        let router = Arc::new(super::super::router::Router::load_from_config(&[]).unwrap());
        let sk = iroh::SecretKey::from([1u8; 32]);
        let result = run(vec![], sk, router).await;
        assert!(result.is_ok());
    }
}
