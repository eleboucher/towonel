use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder};
use iroh::{Endpoint, EndpointAddr};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::protocol::ALPN_TUNNEL;

use crate::metrics::AgentMetrics;
use crate::stateless::EdgeContact;
use crate::tunnel::{self, ServiceMap};

const MIN_HEALTHY_SESSION: Duration = Duration::from_mins(1);

fn redial_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(30))
        .with_jitter()
        .without_max_times()
}

#[must_use]
pub fn spawn(
    endpoint: &Endpoint,
    contacts: &[EdgeContact],
    service_map: &Arc<ServiceMap>,
    metrics: &Arc<AgentMetrics>,
    shutdown: &CancellationToken,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    let mut spawned = 0usize;
    for contact in contacts {
        if contact.addrs.is_empty() {
            warn!(
                edge = %contact.id.fmt_short(),
                "skipping edge with no advertised socket addresses (relay disabled)"
            );
            continue;
        }
        let endpoint = endpoint.clone();
        let contact = contact.clone();
        let service_map = Arc::clone(service_map);
        let metrics = Arc::clone(metrics);
        let shutdown = shutdown.clone();
        set.spawn(async move {
            supervise(endpoint, contact, service_map, metrics, shutdown).await;
        });
        spawned += 1;
    }
    info!(
        supervisors = spawned,
        "edge reverse-dial supervisors spawned"
    );
    set
}

async fn supervise(
    endpoint: Endpoint,
    contact: EdgeContact,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    shutdown: CancellationToken,
) {
    let edge_label = contact.id.fmt_short().to_string();
    let span = info_span!("edge_supervisor", edge = %edge_label);
    async move {
        let mut backoff = redial_backoff().build();
        loop {
            if shutdown.is_cancelled() {
                info!("supervisor shutting down");
                return;
            }

            let dial_started = Instant::now();
            let outcome = tokio::select! {
                () = shutdown.cancelled() => {
                    info!("supervisor cancelled mid-dial");
                    return;
                }
                r = dial_and_serve(&endpoint, &contact, &service_map, &metrics) => r,
            };

            match outcome {
                Ok(session_duration) => {
                    if session_duration >= MIN_HEALTHY_SESSION {
                        debug!(
                            session_secs = session_duration.as_secs(),
                            "healthy session ended; resetting backoff"
                        );
                        backoff = redial_backoff().build();
                        continue;
                    }
                    debug!(
                        session_secs = session_duration.as_secs(),
                        "short-lived session; keeping backoff progression"
                    );
                }
                Err(e) => {
                    warn!(
                        dial_secs = dial_started.elapsed().as_secs(),
                        error = %e,
                        "edge dial failed"
                    );
                }
            }

            // without_max_times() makes None unreachable; saturate as a guardrail.
            let delay = backoff.next().unwrap_or(Duration::from_secs(30));
            #[expect(
                clippy::cast_possible_truncation,
                reason = "backoff is bounded well under u64::MAX millis"
            )]
            let backoff_ms = delay.as_millis() as u64;
            debug!(backoff_ms, "sleeping before redial");
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
    .instrument(span)
    .await;
}

/// Returns the elapsed session duration on success, or the dial error.
async fn dial_and_serve(
    endpoint: &Endpoint,
    contact: &EdgeContact,
    service_map: &Arc<ServiceMap>,
    metrics: &Arc<AgentMetrics>,
) -> anyhow::Result<Duration> {
    let mut addr = EndpointAddr::new(contact.id);
    for sock in &contact.addrs {
        addr = addr.with_ip_addr(*sock);
    }
    let conn = endpoint
        .connect(addr, ALPN_TUNNEL)
        .await
        .with_context(|| format!("connect to edge {} failed", contact.id.fmt_short()))?;

    let edge_label = contact.id.fmt_short().to_string();
    info!(edge = %edge_label, "edge session established");
    metrics
        .edge_session_reconnects
        .with_label_values(&[&edge_label])
        .inc();
    metrics
        .edge_session_state
        .with_label_values(&[&edge_label])
        .set(1);

    let started = Instant::now();
    tunnel::handle_connection(
        conn,
        contact.id,
        Arc::clone(service_map),
        Arc::clone(metrics),
    )
    .await;

    metrics
        .edge_session_state
        .with_label_values(&[&edge_label])
        .set(0);
    Ok(started.elapsed())
}
