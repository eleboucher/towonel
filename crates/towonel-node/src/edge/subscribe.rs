use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use backon::{ExponentialBuilder, Retryable};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use eventsource_stream::Eventsource;
use towonel_common::auth::sign_auth_header;
use towonel_common::routing::RouteTable;

use super::router::Router;

/// Runs forever, applying `RouteTable` snapshots from the hub to `router`.
/// Reconnects with exponential backoff on disconnect.
pub async fn run(
    hub_url: String,
    secret_key: iroh::SecretKey,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    let url = format!("{}/v1/routes/subscribe", hub_url.trim_end_matches('/'));
    reqwest::Url::parse(&url).context("invalid hub_url")?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building reqwest client")?;

    let policy = || {
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_mins(1))
            .with_max_times(usize::MAX)
            .with_jitter()
    };

    // Outer loop resets the backon schedule on every clean hub close so a
    // short flap doesn't accumulate delay.
    loop {
        let res = (|| async { connect_and_stream(&client, &url, &secret_key, &router).await })
            .retry(policy())
            .notify(|err, dur| {
                let backoff_ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
                tracing::warn!(
                    error = %err,
                    backoff_ms,
                    "route subscription failed; backing off",
                );
            })
            .await;

        if let Err(e) = res {
            // max_times=usize::MAX, so the Err branch is practically
            // unreachable; fall through to reconnect anyway.
            tracing::warn!(error = %e, "route subscription gave up; reconnecting");
        } else {
            tracing::info!(hub = %url, "hub closed route subscription; reconnecting");
        }
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
    async fn invalid_hub_url_fails_fast() {
        let router = Arc::new(super::super::router::Router::load_from_config(&[]).unwrap());
        let sk = iroh::SecretKey::from([1u8; 32]);
        let result = run("not a url".to_string(), sk, router).await;
        assert!(result.is_err());
    }
}
