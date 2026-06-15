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
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::edge_cred::AuthFrame;
use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::tunnel::{CONTROL_STATUS_OK, read_control_status, write_control_prefix};

use crate::metrics::AgentMetrics;
use crate::stateless::{CachedEdgeCred, EdgeContact};
use crate::tunnel::{self, ServiceMap};

const PRESENT_CRED_TIMEOUT: Duration = Duration::from_secs(5);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const REDIAL_DELAY: Duration = Duration::from_secs(5);
/// Cap on the redial backoff when an edge keeps failing to connect.
const REDIAL_MAX_DELAY: Duration = Duration::from_mins(1);

struct ActiveSupervisor {
    token: CancellationToken,
    /// Addresses this supervisor was spawned with; a change for the same edge
    /// triggers a respawn.
    addrs: Vec<String>,
}

/// Per-edge supervisors reconciled against the hub's trusted-edge set. Each owns
/// a child of the process shutdown token, so an edge leaving the set is stopped
/// on its own without disturbing the others.
pub struct SupervisorPool {
    endpoint: Endpoint,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    edge_cred: Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_urls: Arc<Vec<RelayUrl>>,
    shutdown: CancellationToken,
    active: std::collections::HashMap<iroh::EndpointId, ActiveSupervisor>,
    tasks: JoinSet<()>,
}

impl SupervisorPool {
    pub fn new(
        endpoint: &Endpoint,
        service_map: &Arc<ServiceMap>,
        metrics: &Arc<AgentMetrics>,
        edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
        relay_urls: Vec<RelayUrl>,
        shutdown: &CancellationToken,
    ) -> Self {
        Self {
            endpoint: endpoint.clone(),
            service_map: Arc::clone(service_map),
            metrics: Arc::clone(metrics),
            edge_cred: Arc::clone(edge_cred),
            relay_urls: Arc::new(relay_urls),
            shutdown: shutdown.clone(),
            active: std::collections::HashMap::new(),
            tasks: JoinSet::new(),
        }
    }

    /// Match running supervisors to `contacts`: stop supervisors whose edge is
    /// no longer in the set, and start one for each newly-present dialable edge.
    /// Edges already supervised are left running.
    pub fn reconcile(&mut self, contacts: &[EdgeContact]) {
        // Drain supervisors that have exited (only happens on cancellation),
        // so the `tasks` set doesn't accumulate finished handles.
        while self.tasks.try_join_next().is_some() {}

        let desired: std::collections::HashMap<iroh::EndpointId, &[String]> = contacts
            .iter()
            .map(|c| (c.id, c.addrs.as_slice()))
            .collect();

        // Stop supervisors whose edge left the set, or whose advertised
        // addresses changed — the spawn loop below then redials the new ones.
        let stale: Vec<iroh::EndpointId> = self
            .active
            .iter()
            .filter_map(|(id, sup)| {
                let keep = matches!(desired.get(id), Some(addrs) if *addrs == sup.addrs.as_slice());
                (!keep).then_some(*id)
            })
            .collect();
        for id in stale {
            if let Some(sup) = self.active.remove(&id) {
                info!(edge = %id.fmt_short(), "edge left the set or changed address; stopping supervisor");
                sup.token.cancel();
            }
        }

        for contact in contacts {
            if self.active.contains_key(&contact.id) {
                continue;
            }
            if contact.addrs.is_empty() && self.relay_urls.is_empty() {
                warn!(
                    edge = %contact.id.fmt_short(),
                    "skipping edge with no advertised socket addresses and no relay configured"
                );
                continue;
            }
            let token = self.shutdown.child_token();
            let id = contact.id;
            info!(edge = %id.fmt_short(), "starting edge supervisor");
            self.tasks.spawn(supervise(
                self.endpoint.clone(),
                contact.clone(),
                Arc::clone(&self.service_map),
                Arc::clone(&self.metrics),
                token.clone(),
                Arc::clone(&self.edge_cred),
                Arc::clone(&self.relay_urls),
            ));
            self.active.insert(
                id,
                ActiveSupervisor {
                    token,
                    addrs: contact.addrs.clone(),
                },
            );
        }
    }

    /// Cancel every supervisor and wait for them to finish.
    pub async fn shutdown(mut self) {
        for (_, sup) in self.active.drain() {
            sup.token.cancel();
        }
        self.tasks.shutdown().await;
    }
}

async fn supervise(
    endpoint: Endpoint,
    contact: EdgeContact,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    shutdown: CancellationToken,
    edge_cred: Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_urls: Arc<Vec<RelayUrl>>,
) {
    let edge_label = contact.id.fmt_short().to_string();
    let span = info_span!("edge_supervisor", edge = %edge_label);
    // A permanently-gone edge is cancelled by reconcile, so this just redials a
    // transiently-down one until it returns. Backoff escalates while dials keep
    // failing fast and resets once a session has held for a while.
    let (endpoint, contact, service_map, metrics, edge_cred, relay_urls) = (
        &endpoint,
        &contact,
        &service_map,
        &metrics,
        &edge_cred,
        &relay_urls,
    );
    crate::retry::supervise(
        &format!("edge:{edge_label}"),
        &shutdown,
        REDIAL_DELAY,
        REDIAL_MAX_DELAY,
        || async move {
            let session = dial_and_serve(
                endpoint,
                contact,
                service_map,
                metrics,
                edge_cred,
                relay_urls,
            )
            .await?;
            debug!(session_secs = session.as_secs(), "session ended; redialing");
            Ok(())
        },
    )
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
    relay_urls: &[RelayUrl],
) -> anyhow::Result<Duration> {
    let resolved = resolve_addrs(&contact.addrs).await;
    if resolved.is_empty() && relay_urls.is_empty() {
        anyhow::bail!("no addresses resolved for edge {}", contact.id.fmt_short());
    }
    // Offer both: iroh prefers the direct path, falls back to relay.
    let mut addr = EndpointAddr::new(contact.id);
    for sock in resolved {
        addr = addr.with_ip_addr(sock);
    }
    for relay in relay_urls {
        addr = addr.with_relay_url(relay.clone());
    }
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, ALPN_TUNNEL))
        .await
        .with_context(|| format!("connect to edge {} timed out", contact.id.fmt_short()))?
        .with_context(|| format!("connect to edge {} failed", contact.id.fmt_short()))?;

    let edge_label = contact.id.fmt_short().to_string();

    // Validate the EdgeCred before counting the session live, so a rejected
    // cred doesn't bump reconnects or flip the session gauge.
    if let Some(cred) = edge_cred.load_full()
        && let Err(e) = present_edge_cred(&conn, &edge_label, &cred).await
    {
        return Err(e);
    }

    info!(edge = %edge_label, "edge session established");
    metrics
        .edge_session_reconnects
        .with_label_values(&[&edge_label])
        .inc();
    // Marks the session live; resets the gauge and aborts the path watcher on
    // Drop, surviving a mid-session cancellation (see `EdgeSessionGuard`).
    let mut guard = EdgeSessionGuard::live(Arc::clone(metrics), edge_label.clone());

    // iroh usually opens on the relay and upgrades to direct once holepunched.
    guard.path_watcher = Some(tokio::spawn(watch_paths(
        conn.path_events(),
        edge_label.clone(),
        Arc::clone(metrics),
    )));

    let started = Instant::now();
    tunnel::handle_connection(
        conn,
        contact.id,
        Arc::clone(service_map),
        Arc::clone(metrics),
    )
    .await;

    Ok(started.elapsed())
}

/// Holds an edge session's liveness gauge and path-watcher task, resetting both
/// on Drop. A cancelled session (supervisor token fired mid-connection) would
/// otherwise skip the straight-line cleanup, leaking the watcher and pinning
/// `edge_session_state` at 1.
struct EdgeSessionGuard {
    metrics: Arc<AgentMetrics>,
    edge_label: String,
    path_watcher: Option<tokio::task::JoinHandle<()>>,
}

impl EdgeSessionGuard {
    fn live(metrics: Arc<AgentMetrics>, edge_label: String) -> Self {
        metrics
            .edge_session_state
            .with_label_values(&[&edge_label])
            .set(1);
        Self {
            metrics,
            edge_label,
            path_watcher: None,
        }
    }
}

impl Drop for EdgeSessionGuard {
    fn drop(&mut self) {
        if let Some(h) = self.path_watcher.take() {
            h.abort();
        }
        self.metrics.clear_edge_path(&self.edge_label);
        self.metrics
            .edge_session_state
            .with_label_values(&[&self.edge_label])
            .set(0);
    }
}

/// A rejected cred means the session is never reported live and no routes
/// will point at it — fail so the supervisor redials with a refreshed cred.
async fn present_edge_cred(
    conn: &iroh::endpoint::Connection,
    edge_label: &str,
    cred: &CachedEdgeCred,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(PRESENT_CRED_TIMEOUT, do_present_edge_cred(conn, cred)).await;
    match result {
        Ok(Ok(status)) if status == CONTROL_STATUS_OK => {
            info!(edge = %edge_label, "EdgeCred accepted");
            Ok(())
        }
        Ok(Ok(status)) => {
            warn!(edge = %edge_label, status, "EdgeCred rejected by edge");
            anyhow::bail!("edge {edge_label} rejected EdgeCred (status {status})")
        }
        Ok(Err(e)) => {
            warn!(edge = %edge_label, error = %e, "presenting EdgeCred failed");
            Err(e.context("presenting EdgeCred"))
        }
        Err(_) => {
            warn!(edge = %edge_label, "EdgeCred presentation timed out");
            anyhow::bail!("EdgeCred presentation to edge {edge_label} timed out")
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
