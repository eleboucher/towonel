use std::time::{Duration, Instant};

use iroh::endpoint::RelayStatus;
use iroh::{Endpoint, Watcher as _};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub const DEFAULT_OUTAGE_THRESHOLD: Duration = Duration::from_mins(1);
pub const DEFAULT_KICK_COOLDOWN: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_secs(5);

#[must_use]
pub fn spawn(endpoint: Endpoint) -> JoinHandle<()> {
    spawn_with_config(endpoint, DEFAULT_OUTAGE_THRESHOLD, DEFAULT_KICK_COOLDOWN)
}

#[must_use]
pub fn spawn_with_config(
    endpoint: Endpoint,
    outage_threshold: Duration,
    kick_cooldown: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move { run(endpoint, outage_threshold, kick_cooldown).await })
}

async fn run(endpoint: Endpoint, outage_threshold: Duration, kick_cooldown: Duration) {
    let mut watcher = endpoint.home_relay_status();
    let mut first_outage_at: Option<Instant> = None;
    let mut last_kick_at: Option<Instant> = None;

    loop {
        match tokio::time::timeout(TICK, watcher.updated()).await {
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(_)) => return, // watcher disconnected; endpoint is gone.
        }
        let statuses = watcher.get();

        if statuses.is_empty() {
            first_outage_at = None;
            continue;
        }

        if statuses.iter().any(RelayStatus::is_connected) {
            if first_outage_at.is_some() {
                debug!("relay watchdog: connectivity restored");
            }
            first_outage_at = None;
            continue;
        }

        let outage = first_outage_at.get_or_insert_with(Instant::now).elapsed();
        if outage < outage_threshold {
            continue;
        }
        if let Some(last) = last_kick_at
            && last.elapsed() < kick_cooldown
        {
            continue;
        }

        for s in &statuses {
            warn!(
                relay = %s.url(),
                outage_secs = outage.as_secs(),
                error = ?s.last_error().map(std::string::ToString::to_string),
                "relay disconnected"
            );
        }
        info!(
            outage_secs = outage.as_secs(),
            relays = statuses.len(),
            "all home relays down, calling endpoint.network_change()"
        );
        endpoint.network_change().await;
        last_kick_at = Some(Instant::now());
    }
}
