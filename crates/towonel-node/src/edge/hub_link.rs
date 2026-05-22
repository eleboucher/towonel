use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use towonel_common::edge_link::{
    EDGE_LINK_VERSION, EdgeToHub, HubSigningKey, HubToEdge, Kid, read_hub_to_edge,
    write_edge_to_hub,
};
use towonel_common::routing::RouteTable;

pub type LinkPsk = [u8; 32];

pub type SigningKeyMap = Arc<RwLock<HashMap<Kid, Vec<u8>>>>;

/// Outbound session events drained by the supervisor.
pub type SessionEventTx = mpsc::Sender<EdgeToHub>;
pub type SessionEventRx = mpsc::Receiver<EdgeToHub>;

#[derive(Clone)]
pub struct HubLinkConfig {
    pub addr: String,
    pub psk: Arc<LinkPsk>,
    pub edge_id: [u8; 32],
    pub iroh_endpoints: Vec<String>,
    pub software_version: String,
}

#[derive(Clone)]
pub struct HubLinkHandle {
    pub route_tx: broadcast::Sender<RouteTable>,
    pub signing_keys: SigningKeyMap,
    pub session_event_tx: SessionEventTx,
    pub session_event_rx: Arc<Mutex<Option<SessionEventRx>>>,
}

impl HubLinkHandle {
    pub fn new(capacity: usize) -> Self {
        let (route_tx, _) = broadcast::channel(capacity);
        let (session_event_tx, session_event_rx) = mpsc::channel(capacity);
        Self {
            route_tx,
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            session_event_tx,
            session_event_rx: Arc::new(Mutex::new(Some(session_event_rx))),
        }
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
            return;
        }
        let result = tokio::select! {
            () = shutdown.cancelled() => return,
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
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
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

    // mpsc receiver is single-consumer: take it for this link, return
    // it on disconnect so the next attempt drains the queue.
    let mut session_rx = {
        let mut guard = handle
            .session_event_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.take()
    };
    let result = run_loop(
        &mut reader,
        &mut write_half,
        handle,
        shutdown,
        session_rx.as_mut(),
    )
    .await;
    if let Some(rx) = session_rx {
        let mut guard = handle
            .session_event_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(rx);
    }
    result
}

async fn run_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    handle: &HubLinkHandle,
    shutdown: &CancellationToken,
    mut session_rx: Option<&mut SessionEventRx>,
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
            outbound = recv_session_event(session_rx.as_deref_mut()) => {
                if let Some(ev) = outbound {
                    write_edge_to_hub(writer, &ev)
                        .await
                        .context("send session event")?;
                }
            }
        }
    }
}

async fn recv_session_event(rx: Option<&mut SessionEventRx>) -> Option<EdgeToHub> {
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
    };
    write_edge_to_hub(writer, &hello)
        .await
        .context("send Hello")?;
    Ok(())
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
