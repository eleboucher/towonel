use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, info_span, warn};

use towonel_common::edge_link::{
    EdgeToHub, HubSigningKey, HubToEdge, PortReservationEntry, read_edge_to_hub, write_hub_to_edge,
};
use towonel_common::identity::AgentId;
use towonel_common::routing::RouteTable;
use towonel_common::time::now_ms;
use towonel_common::tunnel::CONTROL_STATUS_INTERNAL_ERROR;

use crate::edge::hub_client::ControlFrameHandler;

use super::api::AppState;
use super::live_edges::EdgeId;

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_INFLIGHT_CONTROL: usize = 32;

pub type LinkPsk = [u8; 32];

pub struct EdgeLinkServer {
    pub listener: TcpListener,
    pub psk: Arc<LinkPsk>,
    pub hub_id: [u8; 32],
    pub state: Arc<AppState>,
    pub control_handler: Arc<dyn ControlFrameHandler>,
}

impl EdgeLinkServer {
    /// Bind synchronously during startup so a bad `listen_addr` fails the
    /// hub instead of silently degrading inside a spawned task.
    pub async fn bind(
        listen_addr: &str,
        psk: Arc<LinkPsk>,
        hub_id: [u8; 32],
        state: Arc<AppState>,
        control_handler: Arc<dyn ControlFrameHandler>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!(listen = %listen_addr, "hub edge_link listening");
        Ok(Self {
            listener,
            psk,
            hub_id,
            state,
            control_handler,
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let Self {
            listener,
            psk,
            hub_id,
            state,
            control_handler,
        } = self;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("hub edge_link shutting down");
                    return Ok(());
                }
                accept = listener.accept() => {
                    let (stream, peer) = accept?;
                    let psk_clone = Arc::clone(&psk);
                    let state_clone = Arc::clone(&state);
                    let handler_clone = Arc::clone(&control_handler);
                    let route_rx = state.route_tx.subscribe();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let span = info_span!("edge_link", peer = %peer);
                        if let Err(e) = handle_connection(
                            stream,
                            peer,
                            &psk_clone,
                            hub_id,
                            state_clone,
                            handler_clone,
                            route_rx,
                            shutdown,
                        )
                        .instrument(span)
                        .await
                        {
                            warn!(peer = %peer, error = %e, "edge_link connection ended");
                        }
                    });
                }
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "private per-connection entry point; bundling these into a struct would obscure ownership of the half-streams"
)]
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    expected_psk: &LinkPsk,
    hub_id: [u8; 32],
    state: Arc<AppState>,
    control_handler: Arc<dyn ControlFrameHandler>,
    route_rx: broadcast::Receiver<RouteTable>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "edge_link set_nodelay failed");
    }
    let (read_half, write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    let hello = match tokio::time::timeout(HELLO_TIMEOUT, read_edge_to_hub(&mut reader)).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => anyhow::bail!("read Hello: {e}"),
        Err(_) => anyhow::bail!("hello timed out"),
    };

    let (edge_id, iroh_endpoints, software_version) = match hello {
        EdgeToHub::Hello {
            edge_id,
            iroh_endpoints,
            software_version,
            psk,
        } => {
            if expected_psk.ct_eq(&psk).into() {
                (edge_id, iroh_endpoints, software_version)
            } else {
                anyhow::bail!("Hello PSK mismatch");
            }
        }
        other => anyhow::bail!("first frame was not Hello: {other:?}"),
    };

    info!(
        peer = %peer,
        edge = %hex::encode(edge_id),
        version = %software_version,
        endpoints = iroh_endpoints.len(),
        "edge_link authenticated"
    );

    let signing_keys = current_signing_keys(&state)?;
    let welcome = HubToEdge::Welcome {
        hub_id,
        signing_keys,
    };
    let mut writer = write_half;
    // Upsert AFTER Welcome lands so a peer that disconnects mid-handshake
    // doesn't leave a stale entry; there is no janitor yet.
    write_hub_to_edge(&mut writer, &welcome).await?;
    state.live_edges.upsert(edge_id, iroh_endpoints, now_ms());

    let (writer_tx, writer_rx) = mpsc::channel::<HubToEdge>(64);
    let writer_task = tokio::spawn(run_writer(writer, writer_rx));
    let pusher_task = tokio::spawn(push_routes(route_rx, writer_tx.clone(), state.clone()));
    let port_pusher_task = tokio::spawn(push_port_reservations(
        state.port_reservations_tx.subscribe(),
        writer_tx.clone(),
        state.clone(),
    ));

    let control_semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT_CONTROL));
    let result = read_loop(
        reader,
        &state,
        edge_id,
        &control_handler,
        &control_semaphore,
        writer_tx.clone(),
        shutdown.clone(),
    )
    .await;

    drop(writer_tx);
    pusher_task.abort();
    port_pusher_task.abort();
    writer_task.abort();
    state.live_edges.remove(&edge_id);
    info!(edge = %hex::encode(edge_id), "edge_link disconnected");
    result
}

async fn read_loop<R>(
    mut reader: R,
    state: &Arc<AppState>,
    edge_id: EdgeId,
    control_handler: &Arc<dyn ControlFrameHandler>,
    control_semaphore: &Arc<Semaphore>,
    writer_tx: mpsc::Sender<HubToEdge>,
    shutdown: CancellationToken,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            frame = read_edge_to_hub(&mut reader) => {
                match frame {
                    Ok(EdgeToHub::Hello { .. }) => {
                        warn!(edge = %hex::encode(edge_id), "duplicate Hello on established link; ignoring");
                    }
                    Ok(EdgeToHub::SessionAdded { agent_id, tenant_id }) => {
                        bump_liveness(state, agent_id, tenant_id).await;
                    }
                    Ok(EdgeToHub::SessionRemoved { agent_id }) => {
                        tracing::debug!(agent = %agent_id, "session removed");
                    }
                    Ok(EdgeToHub::SessionsSnapshot { sessions }) => {
                        // Bump all, rebuild once — avoids N back-to-back rebuilds
                        // on edge reconnect that converge to the same table.
                        let mut any_transition = false;
                        for (agent_id, tenant_id) in sessions {
                            if bump_liveness_only(state, agent_id, tenant_id).await {
                                any_transition = true;
                            }
                        }
                        if any_transition
                            && let Err(e) = super::api::rebuild_and_broadcast_routes(state).await
                        {
                            warn!(error = %e, "route rebuild after SessionsSnapshot failed");
                        }
                    }
                    Ok(EdgeToHub::ControlRequest { request_id, frame }) => {
                        if let Ok(permit) = Arc::clone(control_semaphore).try_acquire_owned() {
                            // Spawn so a slow handler doesn't block the read loop.
                            let handler = Arc::clone(control_handler);
                            let writer_tx = writer_tx.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let (status, body) = match handler.handle(frame).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        warn!(request_id, error = %e, "control handler errored");
                                        (CONTROL_STATUS_INTERNAL_ERROR, Vec::new())
                                    }
                                };
                                if writer_tx
                                    .send(HubToEdge::ControlResponse {
                                        request_id,
                                        status,
                                        body,
                                    })
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!(request_id, "control response writer closed");
                                }
                            });
                        } else {
                            warn!(request_id, "control queue at capacity; refusing");
                            if writer_tx
                                .try_send(HubToEdge::ControlResponse {
                                    request_id,
                                    status: CONTROL_STATUS_INTERNAL_ERROR,
                                    body: Vec::new(),
                                })
                                .is_err()
                            {
                                tracing::debug!(
                                    request_id,
                                    "writer queue full while reporting overload"
                                );
                            }
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("read frame: {e}")),
                }
            }
        }
    }
}

async fn bump_liveness(
    state: &Arc<AppState>,
    agent_id: AgentId,
    tenant_id: towonel_common::identity::TenantId,
) {
    if !bump_liveness_only(state, agent_id, tenant_id).await {
        return;
    }
    if let Err(e) = super::api::rebuild_and_broadcast_routes(state).await {
        warn!(error = %e, "route rebuild after session_added failed");
    }
}

/// Bump only; returns the transition so the caller batches the rebuild.
async fn bump_liveness_only(
    state: &Arc<AppState>,
    agent_id: AgentId,
    tenant_id: towonel_common::identity::TenantId,
) -> bool {
    let now = now_ms();
    let cutoff = now.saturating_sub(super::api::AGENT_LIVE_TTL_MS);
    match state.liveness.bump(&tenant_id, &agent_id, now, cutoff).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "edge_link session liveness bump failed");
            false
        }
    }
}

async fn run_writer<W>(mut writer: W, mut rx: mpsc::Receiver<HubToEdge>) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(msg) = rx.recv().await {
        write_hub_to_edge(&mut writer, &msg).await?;
    }
    Ok(())
}

async fn push_routes(
    mut route_rx: broadcast::Receiver<RouteTable>,
    writer_tx: mpsc::Sender<HubToEdge>,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    // Initial snapshot so a fresh edge converges before the next mutation.
    if let Ok(initial) = build_current_route_table(&state).await
        && writer_tx
            .send(HubToEdge::RouteSnapshot {
                table: Box::new(initial),
            })
            .await
            .is_err()
    {
        return Ok(());
    }
    loop {
        match route_rx.recv().await {
            Ok(table) => {
                if writer_tx
                    .send(HubToEdge::RouteSnapshot {
                        table: Box::new(table),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "edge_link route stream lagged");
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

async fn build_current_route_table(state: &Arc<AppState>) -> anyhow::Result<RouteTable> {
    let cutoff = now_ms().saturating_sub(super::api::AGENT_LIVE_TTL_MS);
    let (entries, live) = tokio::try_join!(
        state.db.get_all_entries(),
        state.liveness.live_agents(cutoff)
    )?;
    let policy = state.policy.load();
    Ok(RouteTable::from_entries_with_liveness(
        &entries,
        &policy,
        Some(&live),
    ))
}

fn current_signing_keys(state: &AppState) -> anyhow::Result<Vec<HubSigningKey>> {
    let signer = state.signer.as_ref();
    let pubkey = signer.public_key().as_bytes().to_vec();
    Ok(vec![HubSigningKey::new(signer.kid(), pubkey)?])
}

async fn push_port_reservations(
    mut delta_rx: broadcast::Receiver<PortReservationDelta>,
    writer_tx: mpsc::Sender<HubToEdge>,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let initial = current_port_reservations(&state).await.unwrap_or_default();
    if writer_tx
        .send(HubToEdge::PortReservationsSnapshot { entries: initial })
        .await
        .is_err()
    {
        return Ok(());
    }
    loop {
        match delta_rx.recv().await {
            Ok(delta) => {
                if writer_tx
                    .send(HubToEdge::PortReservationsChanged {
                        added: delta.added,
                        removed: delta.removed,
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "edge_link port reservations stream lagged");
                if let Ok(snapshot) = current_port_reservations(&state).await
                    && writer_tx
                        .send(HubToEdge::PortReservationsSnapshot { entries: snapshot })
                        .await
                        .is_err()
                {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

async fn current_port_reservations(
    state: &Arc<AppState>,
) -> anyhow::Result<Vec<PortReservationEntry>> {
    let rows = state.db.list_port_reservations(None).await?;
    Ok(rows
        .into_iter()
        .map(|r| PortReservationEntry {
            tenant_id: r.tenant_id,
            ip: r.ip_address,
            port: r.port,
            protocol: r.protocol.as_str().to_string(),
        })
        .collect())
}

#[derive(Clone, Debug)]
pub struct PortReservationDelta {
    pub added: Vec<PortReservationEntry>,
    pub removed: Vec<PortReservationEntry>,
}
