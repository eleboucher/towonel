use std::time::{Duration, Instant};

use anyhow::Result;

/// Polls `check` every `interval` until it returns `Ok(Some(_))` or
/// `max_wait` elapses.
pub async fn poll_until<T, F, Fut>(
    interval: Duration,
    max_wait: Duration,
    label: &str,
    mut check: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + max_wait;
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        match check().await {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }
        if Instant::now() >= deadline {
            return Err(last_err.map_or_else(
                || anyhow::anyhow!("{label}: timed out after {max_wait:?}"),
                |e| anyhow::anyhow!("{label}: timed out after {max_wait:?}: {e:#}"),
            ));
        }
        tokio::time::sleep(interval).await;
    }
}
