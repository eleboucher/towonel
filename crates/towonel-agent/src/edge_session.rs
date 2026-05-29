use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::endpoint::{PathEvent, PathEventStream};
use iroh::{Endpoint, EndpointAddr, RelayUrl, TransportAddr};
use tokio::net::lookup_host;
use tokio::task::JoinSet;
use tokio_stream::StreamExt as _;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, warn};

use towonel_common::edge_cred::AuthFrame;
use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::tunnel::{CONTROL_STATUS_OK, read_control_status, write_control_prefix};

use crate::metrics::AgentMetrics;
use crate::stateless::{CachedEdgeCred, EdgeContact};
use crate::tunnel::{self, ServiceMap};

const PRESENT_CRED_TIMEOUT: Duration = Duration::from_secs(5);

const MIN_HEALTHY_SESSION: Duration = Duration::from_mins(1);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_FAILURE_DURATION: Duration = Duration::from_mins(5);
const REDIAL_DELAY: Duration = Duration::from_secs(5);

#[must_use]
pub fn spawn(
    endpoint: &Endpoint,
    contacts: &[EdgeContact],
    service_map: &Arc<ServiceMap>,
    metrics: &Arc<AgentMetrics>,
    shutdown: &CancellationToken,
    edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_url: Option<&RelayUrl>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    let mut spawned = 0usize;
    for contact in contacts {
        if contact.addrs.is_empty() && relay_url.is_none() {
            warn!(
                edge = %contact.id.fmt_short(),
                "skipping edge with no advertised socket addresses and no relay configured"
            );
            continue;
        }
        let endpoint = endpoint.clone();
        let contact = contact.clone();
        let service_map = Arc::clone(service_map);
        let metrics = Arc::clone(metrics);
        let shutdown = shutdown.clone();
        let edge_cred = Arc::clone(edge_cred);
        let relay_url = relay_url.cloned();
        set.spawn(async move {
            supervise(
                endpoint,
                contact,
                service_map,
                metrics,
                shutdown,
                edge_cred,
                relay_url,
            )
            .await;
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
    relay_url: Option<RelayUrl>,
) {
    let edge_label = contact.id.fmt_short().to_string();
    let span = info_span!("edge_supervisor", edge = %edge_label);
    async move {
        let mut failure_start: Option<Instant> = None;
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
                r = dial_and_serve(&endpoint, &contact, &service_map, &metrics, &edge_cred, relay_url.as_ref()) => r,
            };

            match outcome {
                Ok(session_duration) => {
                    if session_duration >= MIN_HEALTHY_SESSION {
                        debug!(
                            session_secs = session_duration.as_secs(),
                            "healthy session ended; resetting failure tracker"
                        );
                        failure_start = None;
                        continue;
                    }
                    debug!(
                        session_secs = session_duration.as_secs(),
                        "short-lived session"
                    );
                    failure_start.get_or_insert_with(Instant::now);
                }
                Err(e) => {
                    let failure_start = failure_start.get_or_insert_with(Instant::now);
                    let failure_duration = failure_start.elapsed();

                    if failure_duration >= MAX_FAILURE_DURATION {
                        error!(
                            edge = %edge_label,
                            failure_secs = failure_duration.as_secs(),
                            error = %e,
                            "edge connection failed for {MAX_FAILURE_DURATION:?}; giving up"
                        );
                        return;
                    }

                    warn!(
                        dial_secs = dial_started.elapsed().as_secs(),
                        failure_secs = failure_duration.as_secs(),
                        error = %e,
                        "edge dial failed"
                    );
                }
            }

            debug!(
                delay_secs = REDIAL_DELAY.as_secs(),
                "sleeping before redial"
            );
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(REDIAL_DELAY) => {}
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
    relay_url: Option<&RelayUrl>,
) -> anyhow::Result<Duration> {
    let resolved = resolve_addrs(&contact.addrs).await;
    if resolved.is_empty() && relay_url.is_none() {
        anyhow::bail!("no addresses resolved for edge {}", contact.id.fmt_short());
    }
    // Offer both: iroh prefers the direct path, falls back to relay.
    let mut addr = EndpointAddr::new(contact.id);
    for sock in resolved {
        addr = addr.with_ip_addr(sock);
    }
    if let Some(relay) = relay_url {
        addr = addr.with_relay_url(relay.clone());
    }
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, ALPN_TUNNEL))
        .await
        .with_context(|| format!("connect to edge {} timed out", contact.id.fmt_short()))?
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

    // iroh usually opens on the relay and upgrades to direct once holepunched.
    let path_watcher = tokio::spawn(watch_paths(
        conn.path_events(),
        edge_label.clone(),
        Arc::clone(metrics),
    ));

    let started = Instant::now();
    tunnel::handle_connection(
        conn,
        contact.id,
        Arc::clone(service_map),
        Arc::clone(metrics),
    )
    .await;

    path_watcher.abort();
    metrics.clear_edge_path(&edge_label);
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

/// Mirrors the connection's selected path into `edge_path` until it closes.
async fn watch_paths(mut events: PathEventStream, edge_label: String, metrics: Arc<AgentMetrics>) {
    while let Some(event) = events.next().await {
        if let PathEvent::Selected { remote_addr, .. } = event {
            let path = classify_path(&remote_addr);
            metrics.set_edge_path(&edge_label, path);
            info!(edge = %edge_label, path, "edge path selected");
        }
    }
}

fn classify_path(addr: &TransportAddr) -> &'static str {
    if addr.is_relay() {
        "relay"
    } else if addr.is_ip() {
        "direct"
    } else {
        "custom"
    }
}

async fn resolve_addrs(addrs: &[String]) -> Vec<SocketAddr> {
    let mut resolved = Vec::new();
    for s in addrs {
        match tokio::time::timeout(DNS_TIMEOUT, lookup_host(s)).await {
            Ok(Ok(iter)) => resolved.extend(iter),
            Ok(Err(e)) => warn!(addr = %s, error = %e, "edge address DNS lookup failed"),
            Err(_) => warn!(addr = %s, "edge address DNS lookup timed out"),
        }
    }
    filter_with(resolved, is_routable)
}

// Fall back to the unfiltered list if nothing is routable: iroh may still
// reach the node via the relay, and the v4/v6 mismatch the kernel sees now
// isn't worth turning into a hard failure.
fn filter_with(
    resolved: Vec<SocketAddr>,
    predicate: impl Fn(&SocketAddr) -> bool,
) -> Vec<SocketAddr> {
    let routable: Vec<SocketAddr> = resolved.iter().copied().filter(&predicate).collect();
    if routable.is_empty() {
        return resolved;
    }
    routable
}

// UDP connect performs a kernel route lookup without sending packets, so this
// returns false fast for v6 destinations on v4-only hosts.
fn is_routable(addr: &SocketAddr) -> bool {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    sock.connect(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = "203.0.113.1:80";
    const V6: &str = "[2001:db8::1]:80";

    #[test]
    fn loopback_is_routable() {
        assert!(is_routable(&"127.0.0.1:1".parse().unwrap()));
    }

    #[test]
    fn empty_input() {
        assert!(filter_with(Vec::new(), |_| true).is_empty());
    }

    #[test]
    fn drops_rejected() {
        let v4: SocketAddr = V4.parse().unwrap();
        let v6: SocketAddr = V6.parse().unwrap();
        assert_eq!(filter_with(vec![v4, v6], SocketAddr::is_ipv4), vec![v4]);
    }

    #[test]
    fn falls_back_when_all_rejected() {
        let input: Vec<SocketAddr> = vec![V4.parse().unwrap(), V6.parse().unwrap()];
        assert_eq!(filter_with(input.clone(), |_| false), input);
    }

    #[test]
    fn classify_path_maps_transport_addr() {
        let ip = TransportAddr::Ip(V4.parse().unwrap());
        let relay = TransportAddr::Relay("https://relay.example".parse().unwrap());
        assert_eq!(classify_path(&ip), "direct");
        assert_eq!(classify_path(&relay), "relay");
    }
}
