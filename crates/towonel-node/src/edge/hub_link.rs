use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use towonel_common::edge_link::{
    EDGE_LINK_VERSION, EdgeCapabilities, EdgeToHub, HubSigningKey, HubToEdge, Kid,
    read_hub_to_edge, write_edge_to_hub,
};
use towonel_common::identity::AgentId;
use towonel_common::routing::RouteTable;

use super::port_reservations::PortReservations;

pub type LinkPsk = [u8; 32];

pub type SigningKeyMap = Arc<RwLock<HashMap<Kid, Vec<u8>>>>;

/// Outbound session events drained by the supervisor.
pub type SessionEventTx = mpsc::Sender<EdgeToHub>;
pub type SessionEventRx = mpsc::Receiver<EdgeToHub>;

/// Control-frame relay requests share the link but live on their own queue
/// so a hub stall on auth verification can't back-pressure session events.
pub type ControlRequestTx = mpsc::Sender<EdgeToHub>;
pub type ControlRequestRx = mpsc::Receiver<EdgeToHub>;

pub type PendingControl =
    Arc<Mutex<HashMap<u64, oneshot::Sender<super::hub_client::ControlResponse>>>>;

#[derive(Clone)]
pub struct HubLinkConfig {
    pub addr: String,
    pub psk: Arc<LinkPsk>,
    pub edge_id: [u8; 32],
    pub iroh_endpoints: Vec<String>,
    pub software_version: String,
    pub capabilities: EdgeCapabilities,
    pub public_ips: Vec<String>,
}

#[derive(Clone)]
pub struct HubLinkHandle {
    pub route_tx: broadcast::Sender<RouteTable>,
    pub signing_keys: SigningKeyMap,
    pub session_event_tx: SessionEventTx,
    pub session_event_rx: Arc<Mutex<Option<SessionEventRx>>>,
    pub control_request_tx: ControlRequestTx,
    pub control_request_rx: Arc<Mutex<Option<ControlRequestRx>>>,
    pub port_reservations: Arc<PortReservations>,
    pub next_request_id: Arc<AtomicU64>,
    pub pending_control: PendingControl,
    /// Source the supervisor reads to ship a `SessionsSnapshot` after each
    /// (re)connect. `None` only in unit tests that bypass the supervisor.
    pub sessions: Option<Arc<super::sessions::SessionRegistry>>,
}

impl HubLinkHandle {
    pub fn new(capacity: usize) -> Self {
        let (route_tx, _) = broadcast::channel(capacity);
        let (session_event_tx, session_event_rx) = mpsc::channel(capacity);
        let (control_request_tx, control_request_rx) = mpsc::channel(capacity);
        Self {
            route_tx,
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            session_event_tx,
            session_event_rx: Arc::new(Mutex::new(Some(session_event_rx))),
            control_request_tx,
            control_request_rx: Arc::new(Mutex::new(Some(control_request_rx))),
            port_reservations: PortReservations::new(),
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_control: Arc::new(Mutex::new(HashMap::new())),
            sessions: None,
        }
    }

    #[must_use]
    pub fn with_sessions(mut self, sessions: Arc<super::sessions::SessionRegistry>) -> Self {
        self.sessions = Some(sessions);
        self
    }
}

fn redial_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(30))
        .with_jitter()
        .without_max_times()
}

pub async fn run_supervisor(
    cfg: HubLinkConfig,
    handle: HubLinkHandle,
    shutdown: CancellationToken,
) {
    let mut backoff = redial_backoff().build();
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let result = tokio::select! {
            () = shutdown.cancelled() => break,
            r = run_once(&cfg, &handle, &shutdown) => r,
        };
        match result {
            Ok(()) => {
                info!("hub_link disconnected cleanly; reconnecting");
                backoff = redial_backoff().build();
            }
            Err(e) => {
                warn!(error = %e, "hub_link connection failed");
            }
        }
        let delay = backoff.next().unwrap_or(Duration::from_secs(30));
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(delay) => {}
        }
    }
    drain_pending_control(&handle);
}

async fn run_once(
    cfg: &HubLinkConfig,
    handle: &HubLinkHandle,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(&cfg.addr)
        .await
        .with_context(|| format!("connect to hub {}", cfg.addr))?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "hub_link set_nodelay failed");
    }
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    send_hello(&mut write_half, cfg).await?;
    let welcome = read_hub_to_edge(&mut reader)
        .await
        .context("read Welcome")?;
    match welcome {
        HubToEdge::Welcome {
            hub_id,
            signing_keys,
        } => {
            if signing_keys.is_empty() {
                warn!(
                    hub = %hex::encode(hub_id),
                    "hub Welcome carried zero signing keys; EdgeCred verification will fail"
                );
            }
            store_signing_keys(&handle.signing_keys, &signing_keys);
            info!(
                hub = %hex::encode(hub_id),
                keys = signing_keys.len(),
                wire_version = EDGE_LINK_VERSION,
                "hub_link established"
            );
        }
        other => anyhow::bail!("expected Welcome, got {other:?}"),
    }

    // Hub gates its initial RouteSnapshot on this frame, so always send
    // one — empty is fine. Sent inline before run_loop owns write_half.
    let snapshot_sessions = handle
        .sessions
        .as_ref()
        .map(|r| {
            r.active_with_tenant()
                .into_iter()
                .filter_map(|(eid, t)| match AgentId::from_bytes(eid.as_bytes()) {
                    Ok(a) => Some((a, t)),
                    Err(e) => {
                        warn!(
                            agent = %eid.fmt_short(),
                            error = %e,
                            "EndpointId did not round-trip to AgentId; omitted from snapshot"
                        );
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    write_edge_to_hub(
        &mut write_half,
        &EdgeToHub::SessionsSnapshot {
            sessions: snapshot_sessions,
        },
    )
    .await
    .context("send SessionsSnapshot")?;

    // mpsc receivers are single-consumer: take for this link, restore on disconnect.
    let mut session_rx = take_rx(&handle.session_event_rx);
    let mut control_rx = take_rx(&handle.control_request_rx);
    let result = run_loop(
        &mut reader,
        &mut write_half,
        handle,
        shutdown,
        session_rx.as_mut(),
        control_rx.as_mut(),
    )
    .await;
    restore_rx(&handle.session_event_rx, session_rx);
    restore_rx(&handle.control_request_rx, control_rx);
    drain_pending_control(handle);
    result
}

fn take_rx<T>(slot: &Arc<Mutex<Option<mpsc::Receiver<T>>>>) -> Option<mpsc::Receiver<T>> {
    let mut guard = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.take()
}

fn restore_rx<T>(slot: &Arc<Mutex<Option<mpsc::Receiver<T>>>>, rx: Option<mpsc::Receiver<T>>) {
    if let Some(rx) = rx {
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(rx);
    }
}

async fn run_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    handle: &HubLinkHandle,
    shutdown: &CancellationToken,
    mut session_rx: Option<&mut SessionEventRx>,
    mut control_rx: Option<&mut ControlRequestRx>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            frame = read_hub_to_edge(reader) => {
                let frame = frame.context("read hub frame")?;
                handle_frame(frame, handle);
            }
            outbound = recv_outbound(session_rx.as_deref_mut()) => {
                if let Some(ev) = outbound {
                    write_edge_to_hub(writer, &ev)
                        .await
                        .context("send session event")?;
                }
            }
            outbound = recv_outbound(control_rx.as_deref_mut()) => {
                if let Some(ev) = outbound {
                    write_edge_to_hub(writer, &ev)
                        .await
                        .context("send control request")?;
                }
            }
        }
    }
}

async fn recv_outbound(rx: Option<&mut mpsc::Receiver<EdgeToHub>>) -> Option<EdgeToHub> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn send_hello<W>(writer: &mut W, cfg: &HubLinkConfig) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let hello = EdgeToHub::Hello {
        edge_id: cfg.edge_id,
        iroh_endpoints: cfg.iroh_endpoints.clone(),
        software_version: cfg.software_version.clone(),
        psk: *cfg.psk,
        capabilities: cfg.capabilities.clone(),
        public_ips: cfg.public_ips.clone(),
    };
    write_edge_to_hub(writer, &hello)
        .await
        .context("send Hello")?;
    Ok(())
}

#[cfg(test)]
pub fn deliver_hub_frame_for_test(handle: &HubLinkHandle, frame: HubToEdge) {
    handle_frame(frame, handle);
}

fn handle_frame(frame: HubToEdge, handle: &HubLinkHandle) {
    match frame {
        HubToEdge::Welcome { .. } => {
            warn!("duplicate Welcome on established link; ignoring");
        }
        HubToEdge::RouteSnapshot { table } => {
            let hostnames = table.len();
            if handle.route_tx.send(*table).is_err() {
                tracing::debug!(hostnames, "no route subscribers yet");
            } else {
                tracing::info!(hostnames, "applied route table from hub");
            }
        }
        HubToEdge::KeyAdded(key) => {
            let mut guard = handle
                .signing_keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.insert(key.kid, key.public_key);
        }
        HubToEdge::KeyRetired { kid } => {
            let mut guard = handle
                .signing_keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.remove(&kid);
        }
        HubToEdge::PortReservationsSnapshot { entries } => {
            handle.port_reservations.replace_all(&entries);
            tracing::info!(count = entries.len(), "applied port reservations snapshot");
        }
        HubToEdge::PortReservationsChanged { added, removed } => {
            handle.port_reservations.apply_delta(&added, &removed);
            tracing::info!(
                added = added.len(),
                removed = removed.len(),
                "applied port reservations delta"
            );
        }
        HubToEdge::ControlResponse {
            request_id,
            status,
            body,
        } => {
            let sender = {
                let mut guard = handle
                    .pending_control
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.remove(&request_id)
            };
            match sender {
                Some(tx) => {
                    if tx.send((status, body)).is_err() {
                        tracing::debug!(request_id, "control response receiver gone (timed out?)");
                    }
                }
                None => {
                    tracing::debug!(request_id, "control response for unknown request_id");
                }
            }
        }
    }
}

/// Drops any oneshot senders still waiting; receivers wake with `RecvError`
/// instead of hanging until their timeout.
fn drain_pending_control(handle: &HubLinkHandle) {
    let mut guard = handle
        .pending_control
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !guard.is_empty() {
        tracing::debug!(
            pending = guard.len(),
            "dropping pending control requests on link disconnect"
        );
        guard.clear();
    }
}

fn store_signing_keys(map: &SigningKeyMap, keys: &[HubSigningKey]) {
    let mut guard = map
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.clear();
    for k in keys {
        guard.insert(k.kid, k.public_key.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::edge_link::write_hub_to_edge;
    use towonel_common::routing::RouteTable;

    #[test]
    fn handle_frame_routes_to_broadcast() {
        let handle = HubLinkHandle::new(8);
        let mut rx = handle.route_tx.subscribe();
        handle_frame(
            HubToEdge::RouteSnapshot {
                table: Box::new(RouteTable::default()),
            },
            &handle,
        );
        let recv = rx.try_recv();
        assert!(recv.is_ok(), "broadcast did not receive snapshot");
    }

    #[tokio::test]
    async fn welcome_populates_signing_key_map() {
        let handle = HubLinkHandle::new(1);
        let msg = HubToEdge::Welcome {
            hub_id: [0u8; 32],
            signing_keys: vec![
                HubSigningKey {
                    kid: 1,
                    public_key: vec![1u8; 1952],
                },
                HubSigningKey {
                    kid: 2,
                    public_key: vec![2u8; 1952],
                },
            ],
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &msg).await.unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        match got {
            HubToEdge::Welcome { signing_keys, .. } => {
                store_signing_keys(&handle.signing_keys, &signing_keys);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }
        let (len, has_one, has_two) = {
            let guard = handle.signing_keys.read().unwrap();
            (guard.len(), guard.contains_key(&1), guard.contains_key(&2))
        };
        assert_eq!(len, 2);
        assert!(has_one);
        assert!(has_two);
    }

    #[test]
    fn key_added_then_retired_updates_map() {
        let handle = HubLinkHandle::new(1);
        handle_frame(
            HubToEdge::KeyAdded(HubSigningKey {
                kid: 7,
                public_key: vec![7u8; 1952],
            }),
            &handle,
        );
        assert!(handle.signing_keys.read().unwrap().contains_key(&7));
        handle_frame(HubToEdge::KeyRetired { kid: 7 }, &handle);
        assert!(!handle.signing_keys.read().unwrap().contains_key(&7));
    }
}
