use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder};
use iroh::{Endpoint, EndpointAddr};
use tokio::net::lookup_host;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::edge_cred::AuthFrame;
use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::tunnel::{CONTROL_STATUS_OK, read_control_status, write_control_prefix};

use crate::metrics::AgentMetrics;
use crate::stateless::{CachedEdgeCred, EdgeContact};
use crate::tunnel::{self, ServiceMap};

const PRESENT_CRED_TIMEOUT: Duration = Duration::from_secs(5);

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
    edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
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
        let edge_cred = Arc::clone(edge_cred);
        set.spawn(async move {
            supervise(endpoint, contact, service_map, metrics, shutdown, edge_cred).await;
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
    edge_cred: Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
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
                r = dial_and_serve(&endpoint, &contact, &service_map, &metrics, &edge_cred) => r,
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
    edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
) -> anyhow::Result<Duration> {
    let resolved = resolve_addrs(&contact.addrs).await;
    if resolved.is_empty() {
        anyhow::bail!("no addresses resolved for edge {}", contact.id.fmt_short());
    }
    let mut addr = EndpointAddr::new(contact.id);
    for sock in resolved {
        addr = addr.with_ip_addr(sock);
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

    if let Some(cred) = edge_cred.load_full() {
        present_edge_cred(&conn, &edge_label, &cred).await;
    }

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

/// Best-effort. Logs the outcome but never errors — the data path keeps
/// running whether the edge accepted the cred or not.
async fn present_edge_cred(
    conn: &iroh::endpoint::Connection,
    edge_label: &str,
    cred: &CachedEdgeCred,
) {
    let result = tokio::time::timeout(PRESENT_CRED_TIMEOUT, do_present_edge_cred(conn, cred)).await;
    match result {
        Ok(Ok(status)) if status == CONTROL_STATUS_OK => {
            info!(edge = %edge_label, "EdgeCred accepted");
        }
        Ok(Ok(status)) => {
            warn!(edge = %edge_label, status, "EdgeCred rejected by edge");
        }
        Ok(Err(e)) => {
            warn!(edge = %edge_label, error = %e, "presenting EdgeCred failed");
        }
        Err(_) => {
            warn!(edge = %edge_label, "EdgeCred presentation timed out");
        }
    }
}

async fn do_present_edge_cred(
    conn: &iroh::endpoint::Connection,
    cred: &CachedEdgeCred,
) -> anyhow::Result<u8> {
    let (mut send, mut recv) = conn.open_bi().await.context("open control bidi stream")?;
    write_control_prefix(&mut send)
        .await
        .context("write CONTROL_PREFIX")?;
    let frame = AuthFrame {
        kid: cred.kid,
        cred_cbor: cred.cred_cbor.clone(),
        sig: cred.sig,
    }
    .encode();
    send.write_all(&frame).await.context("write auth frame")?;
    send.finish().context("finish send stream")?;
    let status = read_control_status(&mut recv)
        .await
        .context("read control status")?;
    Ok(status)
}

async fn resolve_addrs(addrs: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for s in addrs {
        match lookup_host(s).await {
            Ok(iter) => out.extend(iter),
            Err(e) => warn!(addr = %s, error = %e, "edge address DNS lookup failed"),
        }
    }
    out
}
