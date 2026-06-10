pub mod health;
pub mod hub_client;
pub mod hub_link;
pub mod proxy_protocol;
pub mod router;
pub mod sessions;

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointAddr;
use iroh::endpoint::Endpoint;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::edge_cred::{AuthFrame, EdgeCred};
use towonel_common::http_host::extract_host_header;
use towonel_common::metrics::GaugeGuard;
use towonel_common::sni::extract_sni;
use towonel_common::tls_policy::TlsMode;
use towonel_common::tunnel::{
    CONTROL_STATUS_INTERNAL_ERROR, CONTROL_STATUS_INVALID, CONTROL_STATUS_NOT_IMPLEMENTED,
    CONTROL_STATUS_OK, COPY_BUF_SIZE, ClientAddrs, DatagramFrameReader, MAX_UDP_DATAGRAM,
    TCP_ROUTE_PREFIX, UDP_ROUTE_PREFIX, copy_buf_counting, forward_quic_to_writer,
    read_control_prefix, write_control_status, write_datagram_frame, write_handshake,
};

use self::health::{EdgeMetrics, session_reject_reason};
use self::hub_client::HubClient;
use self::router::Router;
use self::sessions::{AgentSession, SessionRegistry};
use crate::config::ProxyProtocolConfig;

/// Maximum bytes to peek from a TCP connection to extract the TLS `ClientHello`.
/// 16 KiB is more than enough for any realistic `ClientHello`.
const PEEK_BUF_SIZE: usize = 16_384;

/// Cap on retries while waiting for a full `ClientHello` to arrive in the
/// kernel peek buffer. With a 5 ms sleep between attempts this gives the peer
/// ~100 ms to finish sending the record — more than enough for realistic
/// handshakes even across a congested link.
const PEEK_MAX_ATTEMPTS: u32 = 20;
const PEEK_RETRY_DELAY: Duration = Duration::from_millis(5);

/// Bound on how long we'll wait for a trusted peer to deliver its PROXY v2
/// header. Without this, a misconfigured Caddy or a noisy port-scanner inside
/// the docker bridge could pin one accept task per stalled connection and
/// exhaust FDs. Caddy's own listener wrapper defaults to 2s.
const PROXY_PROTOCOL_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard cap on UDP sessions per listener. UDP source addresses are
/// trivially spoofable so an attacker could otherwise pin millions of
/// `(src_ip, src_port)` sessions, each allocating a tokio task + QUIC
/// stream. Datagrams arriving for an already-tracked peer are unaffected;
/// only attempts to create a *new* session past the cap are dropped.
///
/// Drop-new (not LRU): LRU would evict the legitimate established session
/// in favour of the attacker's freshest spoofed source, which is the
/// opposite of what we want. Override with
/// `TOWONEL_EDGE_MAX_UDP_SESSIONS_PER_LISTENER`.
const DEFAULT_MAX_UDP_SESSIONS_PER_LISTENER: usize = 4_096;

fn max_udp_sessions_from_env() -> usize {
    std::env::var("TOWONEL_EDGE_MAX_UDP_SESSIONS_PER_LISTENER")
        .ok()
        .as_deref()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_UDP_SESSIONS_PER_LISTENER)
}

/// Hard cap on simultaneously in-flight TCP connections. Each accept holds a
/// permit for the lifetime of the per-connection task; on overload, new
/// accepts close the socket and bump `connections_rejected_overload`. 50k
/// matches the typical default ulimit -n of a Linux box and is comfortably
/// above realistic steady-state load. Override with the
/// `TOWONEL_EDGE_MAX_INFLIGHT_CONNECTIONS` env var.
const DEFAULT_MAX_INFLIGHT_CONNECTIONS: usize = 50_000;

fn max_inflight_connections_from_env() -> usize {
    std::env::var("TOWONEL_EDGE_MAX_INFLIGHT_CONNECTIONS")
        .ok()
        .as_deref()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_INFLIGHT_CONNECTIONS)
}

/// How long edge shutdown waits for in-flight connections before forcing them
/// closed. Under the typical 30s Kubernetes grace period so the edge exits
/// before SIGKILL. Override with `TOWONEL_EDGE_DRAIN_TIMEOUT_SECS`.
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 25;

fn drain_timeout_from_env() -> Duration {
    std::env::var("TOWONEL_EDGE_DRAIN_TIMEOUT_SECS")
        .ok()
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or_else(
            || Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS),
            Duration::from_secs,
        )
}

/// The edge: listens on one TCP port, peeks the SNI, and forwards raw TLS
/// bytes to the agent. Agent/origin handles TLS termination. An optional
/// plain-HTTP listener routes by Host header.
pub struct Edge {
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    sessions: Arc<SessionRegistry>,
    listen_addr: String,
    http_listen_addr: Option<String>,
    health_listen_addr: String,
    listen_workers: usize,
    proxy_protocol: Arc<ProxyProtocolConfig>,
    metrics: EdgeMetrics,
    hub_client: Option<Arc<dyn HubClient>>,
    tcp_services: bool,
    udp_services: bool,
}

impl Edge {
    pub fn new(
        router: Arc<Router>,
        endpoint: Arc<Endpoint>,
        listen_addr: String,
        health_listen_addr: String,
        max_connections_per_tenant: usize,
    ) -> Self {
        let metrics = EdgeMetrics::new();
        let sessions = Arc::new(SessionRegistry::new(
            metrics.clone(),
            max_connections_per_tenant,
        ));
        Self {
            router,
            endpoint,
            sessions,
            listen_addr,
            http_listen_addr: None,
            health_listen_addr,
            listen_workers: 1,
            proxy_protocol: Arc::default(),
            metrics,
            hub_client: None,
            tcp_services: true,
            udp_services: true,
        }
    }

    #[must_use]
    pub fn with_hub_client(mut self, client: Arc<dyn HubClient>) -> Self {
        self.hub_client = Some(client);
        self
    }

    #[must_use]
    pub fn sessions(&self) -> Arc<SessionRegistry> {
        Arc::clone(&self.sessions)
    }

    #[must_use]
    pub(crate) fn with_proxy_protocol(mut self, cfg: ProxyProtocolConfig) -> Self {
        self.proxy_protocol = Arc::new(cfg);
        self
    }

    #[must_use]
    pub fn with_listen_workers(mut self, n: usize) -> Self {
        self.listen_workers = n.max(1);
        self
    }

    #[must_use]
    pub fn with_http_listen_addr(mut self, addr: Option<String>) -> Self {
        self.http_listen_addr = addr;
        self
    }

    #[must_use]
    pub const fn with_tcp_services(mut self, enabled: bool) -> Self {
        self.tcp_services = enabled;
        self
    }

    #[must_use]
    pub const fn with_udp_services(mut self, enabled: bool) -> Self {
        self.udp_services = enabled;
        self
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear listener spawn + drain orchestration; splitting hides the lifecycle"
    )]
    pub async fn run(&self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let health_app = health::router(self.metrics.clone());
        let health_listener = TcpListener::bind(&self.health_listen_addr).await?;
        info!(listen = %self.health_listen_addr, "edge health server listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(health_listener, health_app).await {
                tracing::error!(error = %e, "edge health server exited");
            }
        });

        let max_inflight = max_inflight_connections_from_env();
        let drain_timeout = drain_timeout_from_env();
        info!(
            max_inflight,
            ?drain_timeout,
            "edge connection cap configured"
        );
        let ctx = Arc::new(ConnCtx {
            router: Arc::clone(&self.router),
            sessions: Arc::clone(&self.sessions),
            metrics: self.metrics.clone(),
            proxy_protocol: Arc::clone(&self.proxy_protocol),
            hub_client: self.hub_client.clone(),
            connection_permits: Arc::new(tokio::sync::Semaphore::new(max_inflight)),
        });
        // Long-lived agent (iroh) connections get their own pool: if they drew
        // from the client `connection_permits`, the shutdown drain (which
        // acquires that whole pool) would block the full timeout while any
        // agent stays connected. Agent connections are closed by
        // `endpoint.close()` after `run()` returns.
        let agent_permits = Arc::new(tokio::sync::Semaphore::new(max_inflight));

        let listeners = bind_listeners(&self.listen_addr, self.listen_workers).await?;
        info!(
            listen = %self.listen_addr,
            workers = listeners.len(),
            "edge listening"
        );

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(listeners.len() + 3);
        for listener in listeners {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(accept_loop(
                listener,
                ctx,
                ListenerKind::Tls,
                shutdown.clone(),
            )));
        }

        if let Some(http_addr) = self.http_listen_addr.as_deref() {
            let http_listeners = bind_listeners(http_addr, self.listen_workers).await?;
            info!(
                listen = %http_addr,
                workers = http_listeners.len(),
                "edge http listening"
            );
            for listener in http_listeners {
                let ctx = Arc::clone(&ctx);
                tasks.push(tokio::spawn(accept_loop(
                    listener,
                    ctx,
                    ListenerKind::Http,
                    shutdown.clone(),
                )));
            }
        }

        if self.tcp_services {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(tcp_listener_reconciler(ctx, shutdown.clone())));
        }

        if self.udp_services {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(udp_listener_reconciler(ctx, shutdown.clone())));
        }

        // Agents dialing in register sessions; the legacy outbound-dial
        // path stays available for agents still running in accept mode.
        {
            let endpoint = Arc::clone(&self.endpoint);
            let sessions = Arc::clone(&self.sessions);
            let router = Arc::clone(&self.router);
            let metrics = self.metrics.clone();
            let hub_client = self.hub_client.clone();
            let permits = Arc::clone(&agent_permits);
            tasks.push(tokio::spawn(iroh_accept_loop(
                endpoint,
                sessions,
                router,
                metrics,
                hub_client,
                permits,
                shutdown.clone(),
            )));
        }

        if let Some(hub_client) = self.hub_client.as_ref() {
            let stream = hub_client.subscribe_routes();
            let router = Arc::clone(&self.router);
            tasks.push(tokio::spawn(route_sync_loop(
                stream,
                router,
                shutdown.clone(),
            )));
        }

        shutdown.cancelled().await;
        info!("edge: shutdown requested; no longer accepting, draining in-flight connections");

        // Loops select on the same token and return; join them so the listeners
        // are closed before we wait on in-flight work.
        for task in tasks {
            if let Err(e) = task.await {
                warn!("edge accept loop join error: {e}");
            }
        }

        // Each in-flight client task holds a permit; acquiring the whole pool
        // blocks until they finish, bounded by the drain timeout. Agent (iroh)
        // connections use a separate pool and UDP sessions are not
        // permit-tracked, so neither blocks this drain.
        let max = u32::try_from(max_inflight).unwrap_or(u32::MAX);
        match tokio::time::timeout(
            drain_timeout,
            Arc::clone(&ctx.connection_permits).acquire_many_owned(max),
        )
        .await
        {
            Ok(Ok(_permits)) => info!("edge: all in-flight connections drained"),
            Ok(Err(e)) => warn!("edge: drain semaphore closed unexpectedly: {e}"),
            Err(_) => warn!(
                remaining = max_inflight - ctx.connection_permits.available_permits(),
                ?drain_timeout,
                "edge: drain timed out; closing remaining connections"
            ),
        }
        Ok(())
    }
}

async fn route_sync_loop(
    mut stream: hub_client::RouteStream,
    router: Arc<Router>,
    shutdown: CancellationToken,
) {
    use tokio_stream::StreamExt;
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            next = stream.next() => match next {
                Some(table) => {
                    let count = table.len();
                    router.replace(table);
                    info!(hostnames = count, "dynamic route update applied");
                }
                None => break,
            },
        }
    }
    info!("route stream closed, stopping sync loop");
}

async fn iroh_accept_loop(
    endpoint: Arc<Endpoint>,
    sessions: Arc<SessionRegistry>,
    router: Arc<Router>,
    metrics: EdgeMetrics,
    hub_client: Option<Arc<dyn HubClient>>,
    agent_permits: Arc<tokio::sync::Semaphore>,
    shutdown: CancellationToken,
) {
    info!("edge iroh accept loop ready");
    loop {
        let incoming = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                info!("edge iroh accept loop shutting down");
                return;
            }
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else {
            info!("edge iroh endpoint closed, stopping accept loop");
            return;
        };
        let Ok(permit) = Arc::clone(&agent_permits).try_acquire_owned() else {
            metrics.connections_rejected_overload.inc();
            drop(incoming);
            continue;
        };
        let sessions = Arc::clone(&sessions);
        let router = Arc::clone(&router);
        let metrics = metrics.clone();
        let hub_client = hub_client.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_inbound_agent(incoming, sessions, router, metrics, hub_client).await
            {
                debug!(error = %e, "inbound agent connection ended with error");
            }
        });
    }
}

async fn handle_inbound_agent(
    incoming: iroh::endpoint::Incoming,
    sessions: Arc<SessionRegistry>,
    router: Arc<Router>,
    metrics: EdgeMetrics,
    hub_client: Option<Arc<dyn HubClient>>,
) -> anyhow::Result<()> {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            metrics
                .sessions_rejected_total
                .with_label_values(&[session_reject_reason::HANDSHAKE_ERROR])
                .inc();
            return Err(anyhow::anyhow!("iroh handshake failed: {e}"));
        }
    };
    let agent_id = conn.remote_id();
    if !router.is_known_agent(&agent_id) {
        metrics
            .sessions_rejected_total
            .with_label_values(&[session_reject_reason::UNKNOWN_AGENT])
            .inc();
        warn!(
            agent = %agent_id.fmt_short(),
            "rejecting inbound iroh connection from unknown agent"
        );
        conn.close(403u32.into(), b"unknown agent");
        return Ok(());
    }

    let session = Arc::new(AgentSession::new(agent_id, conn.clone()));
    sessions.register(&session);

    let accept_loop = {
        let conn = conn.clone();
        let sessions = Arc::clone(&sessions);
        let hub_client = hub_client.clone();
        async move {
            while let Ok((send, recv)) = conn.accept_bi().await {
                let hub_client = hub_client.clone();
                let sessions = Arc::clone(&sessions);
                let conn = conn.clone();
                tokio::spawn(handle_agent_stream(
                    send, recv, conn, agent_id, hub_client, sessions,
                ));
            }
        }
    };

    tokio::select! {
        () = accept_loop => {}
        _close = conn.closed() => {}
    }
    let tenant = sessions.tenant_for(&agent_id);
    // Gated on the removal: on supersede the new session is already live
    // and notifying here would clear its liveness entry mid-flight.
    let removed = sessions.remove_if_current(&session);
    if removed
        && let Some(tenant_id) = tenant
        && let Some(client) = hub_client.as_deref()
        && let Ok(aid) = towonel_common::identity::AgentId::from_bytes(agent_id.as_bytes())
    {
        client.record_session_removed(tenant_id, aid).await;
    }
    Ok(())
}

/// Extract `(tenant_id, agent_id)` from an `AuthFrame`. The hub has
/// already verified the signature.
fn decode_cred_identity(
    frame: &[u8],
) -> Option<(
    towonel_common::identity::TenantId,
    towonel_common::identity::AgentId,
)> {
    let auth = AuthFrame::decode(frame).ok()?;
    let cred = EdgeCred::from_cbor(&auth.cred_cbor).ok()?;
    Some((cred.tenant_id, cred.agent_id))
}

const CONTROL_FRAME_MAX_BYTES: usize = 64 * 1024;
/// 10 s — caps slowloris dribblers; generous for a 64 KiB frame.
const CONTROL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_RESET_BODY_WRITE_FAILED: u32 = 1;

async fn handle_agent_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    conn: iroh::endpoint::Connection,
    agent_id: iroh::EndpointId,
    hub_client: Option<Arc<dyn HubClient>>,
    sessions: Arc<SessionRegistry>,
) {
    match tokio::time::timeout(
        CONTROL_STREAM_TIMEOUT,
        run_control_stream(send, recv, conn, agent_id, hub_client, sessions),
    )
    .await
    {
        Ok(()) => {}
        Err(_) => {
            warn!(
                agent = %agent_id.fmt_short(),
                timeout_secs = CONTROL_STREAM_TIMEOUT.as_secs(),
                "control stream exceeded deadline; dropping"
            );
        }
    }
}

async fn run_control_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    conn: iroh::endpoint::Connection,
    agent_id: iroh::EndpointId,
    hub_client: Option<Arc<dyn HubClient>>,
    sessions: Arc<SessionRegistry>,
) {
    if let Err(e) = read_control_prefix(&mut recv).await {
        debug!(
            agent = %agent_id.fmt_short(),
            error = %e,
            "agent-initiated stream did not start with CONTROL_PREFIX; dropping"
        );
        return;
    }

    // Agent half-closes its send to mark "request complete"; we read to EOF.
    let frame = match recv.read_to_end(CONTROL_FRAME_MAX_BYTES).await {
        Ok(buf) => buf,
        Err(e) => {
            warn!(
                agent = %agent_id.fmt_short(),
                error = %e,
                cap_bytes = CONTROL_FRAME_MAX_BYTES,
                "control frame exceeded cap or stream errored"
            );
            if let Err(e) = write_control_status(&mut send, CONTROL_STATUS_INVALID).await {
                debug!(agent = %agent_id.fmt_short(), error = %e, "writing INVALID status failed");
            }
            if let Err(e) = send.finish() {
                debug!(agent = %agent_id.fmt_short(), error = %e, "finishing stream after INVALID failed");
            }
            return;
        }
    };

    let (status, body) = match hub_client.as_deref() {
        Some(client) => match client.handle_control_frame(frame.clone()).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!(
                    agent = %agent_id.fmt_short(),
                    error = %e,
                    "hub control handler returned error"
                );
                (CONTROL_STATUS_INTERNAL_ERROR, Vec::new())
            }
        },
        None => (CONTROL_STATUS_NOT_IMPLEMENTED, Vec::new()),
    };

    if status == CONTROL_STATUS_OK
        && let Some(client) = hub_client.as_deref()
        && let Some((tenant_id, cred_agent_id)) = decode_cred_identity(&frame)
    {
        // The hub verified the credential but does not see our authenticated
        // iroh agent_id. A credential issued for a different agent must be
        // rejected here, otherwise it would route while evading the per-tenant
        // connection cap (which keys on agent_id).
        if cred_agent_id.as_bytes() != agent_id.as_bytes() {
            warn!(
                agent = %agent_id.fmt_short(),
                "rejecting agent connection: credential agent_id does not match connection"
            );
            conn.close(403u32.into(), b"credential agent_id mismatch");
            return;
        }
        if sessions.record_tenant(agent_id, tenant_id) {
            client.record_session_added(tenant_id, cred_agent_id).await;
        } else {
            warn!(
                agent = %agent_id.fmt_short(),
                "rejecting agent connection: tenant at connection limit"
            );
            // Close our own connection, not a registry lookup that could hit
            // a superseding session for the same agent_id.
            conn.close(429u32.into(), b"tenant connection limit reached");
            return;
        }
    }

    if let Err(e) = write_control_status(&mut send, status).await {
        debug!(agent = %agent_id.fmt_short(), error = %e, "writing control status failed");
        return;
    }
    if !body.is_empty()
        && let Err(e) = send.write_all(&body).await
    {
        debug!(agent = %agent_id.fmt_short(), error = %e, "writing control response body failed");
        // Reset (not finish) so the agent distinguishes truncation from EOF.
        if let Err(e) = send.reset(CONTROL_RESET_BODY_WRITE_FAILED.into()) {
            debug!(agent = %agent_id.fmt_short(), error = %e, "resetting stream failed");
        }
        return;
    }
    if let Err(e) = send.finish() {
        debug!(agent = %agent_id.fmt_short(), error = %e, "finishing control stream failed");
    }
}

/// Routing path for accepted connections: TLS routes by SNI, HTTP by Host
/// header.
#[derive(Clone, Copy)]
enum ListenerKind {
    Tls,
    Http,
}

/// One accept loop — shared by all reuseport workers.
async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<ConnCtx>,
    kind: ListenerKind,
    shutdown: CancellationToken,
) {
    loop {
        let (tcp_stream, peer_addr) = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("TCP accept error: {e}");
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&ctx.connection_permits).try_acquire_owned() else {
            // Counter is the canonical signal here; logging per drop on a
            // sustained accept-DoS would itself become a hot path.
            ctx.metrics.connections_rejected_overload.inc();
            drop(tcp_stream);
            continue;
        };
        if let Err(e) = tcp_stream.set_nodelay(true) {
            debug!(%peer_addr, error = %e, "failed to set TCP_NODELAY on client socket");
        }
        debug!(%peer_addr, "accepted TCP connection");

        let ctx = Arc::clone(&ctx);
        // Stack-allocated `PEEK_BUF_SIZE` buffer lives inside the future; the
        // tokio spawn already boxes it, so there's no extra allocation.
        #[expect(
            clippy::large_futures,
            reason = "tokio::spawn already boxes the future"
        )]
        tokio::spawn(async move {
            let _permit = permit; // released when this task exits
            let result = match kind {
                ListenerKind::Tls => handle_connection(tcp_stream, peer_addr, &ctx).await,
                ListenerKind::Http => handle_http_connection(tcp_stream, peer_addr, &ctx).await,
            };
            if let Err(e) = result {
                debug!(%peer_addr, error = %e, "connection handling failed");
            }
        });
    }
}

/// Bind one or more TCP listeners on `listen_addr`. When `workers > 1` (Unix
/// only) each listener uses `SO_REUSEPORT` so the kernel load-balances
/// incoming SYNs across accept queues — the standard trick for scaling
/// accept past a single-core bottleneck.
async fn bind_listeners(listen_addr: &str, workers: usize) -> anyhow::Result<Vec<TcpListener>> {
    let addr: std::net::SocketAddr = listen_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen_addr {listen_addr:?}: {e}"))?;
    let n = workers.max(1);

    if n == 1 {
        return Ok(vec![TcpListener::bind(addr).await?]);
    }

    #[cfg(unix)]
    {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let socket = match addr {
                std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };
            socket.set_reuseaddr(true)?;
            socket.set_reuseport(true)?;
            socket.bind(addr)?;
            out.push(socket.listen(1024)?);
        }
        Ok(out)
    }

    #[cfg(not(unix))]
    {
        warn!(
            workers,
            "SO_REUSEPORT fan-out not supported on this platform; falling back to 1 listener"
        );
        Ok(vec![TcpListener::bind(addr).await?])
    }
}

/// Per-edge context shared across every incoming connection. Wrapped in an
/// `Arc` so per-connection tasks bump a single refcount instead of cloning
/// ~seven `Arc`s each.
struct ConnCtx {
    router: Arc<Router>,
    sessions: Arc<SessionRegistry>,
    metrics: EdgeMetrics,
    proxy_protocol: Arc<ProxyProtocolConfig>,
    /// Lets the client routing path tell the hub an agent is gone when it
    /// evicts a dead session (so hub liveness doesn't go stale until the next
    /// link reconnect).
    hub_client: Option<Arc<dyn HubClient>>,
    /// Hard cap on in-flight TCP connections (TLS + raw TCP services). An
    /// `OwnedSemaphorePermit` is acquired per accept and held for the
    /// lifetime of the spawned `handle_*_connection` task. When the cap is
    /// reached new accepts drop the connection and increment
    /// `metrics.connections_rejected_overload`.
    connection_permits: Arc<tokio::sync::Semaphore>,
}

/// Dispatch a single incoming TCP connection: peek the SNI and pass through
/// to the agent.
#[expect(
    clippy::large_futures,
    reason = "spawned via tokio::spawn which already boxes"
)]
async fn handle_connection(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    ctx.metrics.total_connections.inc();
    let _active = GaugeGuard::inc(&ctx.metrics.active_connections);

    let result = handle_connection_inner(tcp_stream, peer_addr, ctx).await;

    if let Err(ref e) = result {
        debug!(%peer_addr, error = %e, "connection ended with error");
    }

    result
}

/// Retry the candidate sweep a few times to ride out the brief window
/// where an agent's session is in transition (supersede race after
/// reconnect). Each attempt is a cheap session lookup; no dialing.
const PICK_AGENT_ATTEMPTS: u32 = 3;
const PICK_AGENT_BACKOFF: Duration = Duration::from_millis(200);

/// Shuffle `candidates` for fair spread, then try each agent's session.
/// `refresh` is called between attempts to pick up route-table updates that
/// landed during the supersede window. Returns the first stream that opens.
async fn pick_agent_and_open_stream(
    ctx: &ConnCtx,
    mut candidates: self::router::Candidates,
    mut refresh: impl FnMut() -> Option<self::router::Candidates>,
) -> anyhow::Result<(
    EndpointAddr,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
)> {
    fastrand::shuffle(&mut candidates);

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PICK_AGENT_ATTEMPTS {
        for agent_addr in &candidates {
            match open_agent_stream(ctx, agent_addr.id).await {
                Ok((send, recv)) => {
                    if let Some(tenant) = ctx.sessions.tenant_for(&agent_addr.id) {
                        ctx.metrics
                            .tenant_connections_total
                            .with_label_values(&[&tenant.to_string()])
                            .inc();
                    }
                    return Ok((agent_addr.clone(), send, recv));
                }
                Err(e) => {
                    debug!(
                        agent = %agent_addr.id.fmt_short(),
                        attempt,
                        error = %e,
                        "agent session not usable, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }
        if attempt + 1 < PICK_AGENT_ATTEMPTS {
            tokio::time::sleep(PICK_AGENT_BACKOFF.saturating_mul(1u32 << attempt)).await;
            if let Some(mut next) = refresh() {
                fastrand::shuffle(&mut next);
                candidates = next;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!("all agents failed after {PICK_AGENT_ATTEMPTS} attempts")
    }))
}

/// Peek bytes until a full TLS record is visible in the kernel buffer,
/// allowing SNI extraction to succeed even when the `ClientHello` is split
/// across multiple TCP segments. Returns once the record is complete or the
/// attempt budget is exhausted.
async fn peek_client_hello(tcp: &TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    for attempt in 0..PEEK_MAX_ATTEMPTS {
        let n = tcp.peek(buf).await?;
        let peeked = buf.get(..n).unwrap_or(buf);
        if tls_record_complete(peeked) || n >= buf.len() {
            return Ok(n);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending ClientHello",
            ));
        }
        if attempt + 1 < PEEK_MAX_ATTEMPTS {
            tokio::time::sleep(PEEK_RETRY_DELAY).await;
        }
    }
    tcp.peek(buf).await
}

/// TLS record framing: `[content_type:1][version:2][length:2][fragment:length]`.
/// Returns true once we have the full fragment.
fn tls_record_complete(buf: &[u8]) -> bool {
    let Some(&len_hi) = buf.get(3) else {
        return false;
    };
    let Some(&len_lo) = buf.get(4) else {
        return false;
    };
    buf.len() >= 5 + usize::from(u16::from_be_bytes([len_hi, len_lo]))
}

/// Recover the real client address before TLS peek/handshake. Trusted-CIDR
/// peers must prepend a PROXY v2 header; untrusted peers are passed through.
///
/// While the feature is on, every connection from a trusted CIDR is required
/// to carry the header — dropping the upstream PROXY config without also
/// flipping `TOWONEL_EDGE_PROXY_PROTOCOL` off hard-fails every connection.
async fn resolve_peer_addr(
    tcp_stream: &mut TcpStream,
    immediate_peer: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<std::net::SocketAddr> {
    if !ctx.proxy_protocol.is_trusted(immediate_peer.ip()) {
        return Ok(immediate_peer);
    }
    let read =
        tokio::time::timeout(PROXY_PROTOCOL_TIMEOUT, proxy_protocol::read_v2(tcp_stream)).await;
    match read {
        Ok(Ok(addr)) => {
            debug!(advertised = %addr, immediate = %immediate_peer, "PROXY v2 header consumed");
            Ok(addr)
        }
        Ok(Err(e)) => Err(anyhow::anyhow!(
            "trusted peer {immediate_peer} sent invalid PROXY v2 header: {e}"
        )),
        Err(_) => Err(anyhow::anyhow!(
            "trusted peer {immediate_peer} did not send PROXY v2 header within {PROXY_PROTOCOL_TIMEOUT:?}"
        )),
    }
}

#[expect(
    clippy::large_futures,
    reason = "spawned via tokio::spawn which already boxes"
)]
async fn handle_connection_inner(
    mut tcp_stream: TcpStream,
    immediate_peer: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    let peer_addr = match resolve_peer_addr(&mut tcp_stream, immediate_peer, ctx).await {
        Ok(a) => a,
        Err(e) => {
            drop(tcp_stream.shutdown().await);
            return Err(e);
        }
    };

    let span = info_span!("conn", peer = %peer_addr);
    async move {
        let start = Instant::now();

        let prep = match prepare_connection(&tcp_stream, ctx).await {
            Ok(p) => p,
            Err(e) => {
                drop(tcp_stream.shutdown().await);
                return Err(e);
            }
        };

        let Preparation {
            hostname,
            policy,
            agent_addr,
            send_stream,
            recv_stream,
        } = prep;
        let agent_short = agent_addr.id.fmt_short();
        // Resolve the tenant before piping: an abnormal close can remove the
        // session mid-transfer, so looking it up afterward would drop the
        // per-tenant byte counts for exactly the connections we want to keep.
        let tenant = ctx.sessions.tenant_for(&agent_addr.id);
        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst: tcp_stream.local_addr()?,
        };
        let (bytes_in, bytes_out) = match policy {
            TlsMode::Passthrough => {
                pipe_tcp(
                    tcp_stream,
                    &hostname,
                    client_addrs,
                    send_stream,
                    recv_stream,
                )
                .await?
            }
        };
        ctx.metrics.total_bytes_in.inc_by(bytes_in);
        ctx.metrics.total_bytes_out.inc_by(bytes_out);
        if let Some(tenant) = tenant {
            ctx.metrics
                .record_tenant_bytes(&tenant, bytes_in, bytes_out);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "connection won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(
            %hostname,
            agent = %agent_short,
            mode = policy.label(),
            bytes_in,
            bytes_out,
            duration_ms,
            "connection closed"
        );
        Ok(())
    }
    .instrument(span)
    .await
}

struct Preparation {
    hostname: String,
    policy: TlsMode,
    agent_addr: EndpointAddr,
    send_stream: iroh::endpoint::SendStream,
    recv_stream: iroh::endpoint::RecvStream,
}

async fn prepare_connection(tcp_stream: &TcpStream, ctx: &ConnCtx) -> anyhow::Result<Preparation> {
    let mut peek_buf = [0u8; PEEK_BUF_SIZE];
    let n = peek_client_hello(tcp_stream, &mut peek_buf).await?;
    let peeked = peek_buf.get(..n).unwrap_or(&peek_buf);
    let hostname = extract_sni(peeked)
        .ok_or_else(|| anyhow::anyhow!("no SNI found in ClientHello"))?
        .to_string();
    // SNI must not forge a route-key prefix the agent dispatches on.
    if towonel_common::routing::is_reserved_route_key(&hostname) {
        anyhow::bail!("SNI uses a reserved route-key prefix: {hostname}");
    }
    debug!(%hostname, "SNI extracted");

    let (candidates, policy) = ctx
        .router
        .route(&hostname)
        .ok_or_else(|| anyhow::anyhow!("no route for hostname: {hostname}"))?;
    debug!(
        %hostname,
        candidates = candidates.len(),
        mode = policy.label(),
        "route matched"
    );

    let (agent_addr, send_stream, recv_stream) =
        pick_agent_and_open_stream(ctx, candidates, || {
            ctx.router.route(&hostname).map(|(c, _)| c)
        })
        .await?;
    debug!(agent = %agent_addr.id.fmt_short(), "agent selected, stream opened");

    Ok(Preparation {
        hostname,
        policy,
        agent_addr,
        send_stream,
        recv_stream,
    })
}

#[expect(
    clippy::large_futures,
    reason = "spawned via tokio::spawn which already boxes"
)]
async fn handle_http_connection(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    ctx.metrics.total_connections.inc();
    let _active = GaugeGuard::inc(&ctx.metrics.active_connections);
    let result = handle_http_connection_inner(tcp_stream, peer_addr, ctx).await;
    if let Err(ref e) = result {
        debug!(%peer_addr, error = %e, "HTTP connection ended with error");
    }
    result
}

#[expect(
    clippy::large_futures,
    reason = "spawned via tokio::spawn which already boxes"
)]
async fn handle_http_connection_inner(
    mut tcp_stream: TcpStream,
    immediate_peer: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    let peer_addr = match resolve_peer_addr(&mut tcp_stream, immediate_peer, ctx).await {
        Ok(a) => a,
        Err(e) => {
            drop(tcp_stream.shutdown().await);
            return Err(e);
        }
    };

    let span = info_span!("http_conn", peer = %peer_addr);
    async move {
        let start = Instant::now();

        let hostname = match peek_http_hostname(&tcp_stream).await {
            Ok(h) => h,
            Err(e) => {
                drop(tcp_stream.shutdown().await);
                return Err(e);
            }
        };

        let (candidates, _policy) = ctx
            .router
            .route(&hostname)
            .ok_or_else(|| anyhow::anyhow!("no route for hostname: {hostname}"))?;
        debug!(%hostname, candidates = candidates.len(), "http route matched");

        let (agent_addr, send_stream, recv_stream) =
            pick_agent_and_open_stream(ctx, candidates, || {
                ctx.router.route(&hostname).map(|(c, _)| c)
            })
            .await?;
        let agent_short = agent_addr.id.fmt_short();
        // Resolve the tenant before piping: an abnormal close can remove the
        // session mid-transfer, so looking it up afterward would drop the
        // per-tenant byte counts.
        let tenant = ctx.sessions.tenant_for(&agent_addr.id);

        // The agent keys its cleartext origin-`:80` dial off
        // `dst.port() == 80`; the listener may be bound elsewhere (tests).
        let mut dst = tcp_stream.local_addr()?;
        dst.set_port(80);
        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst,
        };
        let (bytes_in, bytes_out) = pipe_tcp(
            tcp_stream,
            &hostname,
            client_addrs,
            send_stream,
            recv_stream,
        )
        .await?;

        ctx.metrics.total_bytes_in.inc_by(bytes_in);
        ctx.metrics.total_bytes_out.inc_by(bytes_out);
        if let Some(tenant) = tenant {
            ctx.metrics
                .record_tenant_bytes(&tenant, bytes_in, bytes_out);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "connection won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(
            %hostname,
            agent = %agent_short,
            bytes_in,
            bytes_out,
            duration_ms,
            "http connection closed"
        );
        Ok(())
    }
    .instrument(span)
    .await
}

/// [`peek_client_hello`] for plain HTTP: peek until the full request head
/// (`\r\n\r\n`) is visible.
async fn peek_http_request(tcp: &TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    for attempt in 0..PEEK_MAX_ATTEMPTS {
        let n = tcp.peek(buf).await?;
        let peeked = buf.get(..n).unwrap_or(buf);
        if peeked.windows(4).any(|w| w == b"\r\n\r\n") || n >= buf.len() {
            return Ok(n);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending HTTP request",
            ));
        }
        if attempt + 1 < PEEK_MAX_ATTEMPTS {
            tokio::time::sleep(PEEK_RETRY_DELAY).await;
        }
    }
    tcp.peek(buf).await
}

async fn peek_http_hostname(tcp: &TcpStream) -> anyhow::Result<String> {
    let mut peek_buf = [0u8; PEEK_BUF_SIZE];
    let n = peek_http_request(tcp, &mut peek_buf).await?;
    let peeked = peek_buf.get(..n).unwrap_or(&peek_buf);
    extract_host_header(peeked).ok_or_else(|| anyhow::anyhow!("no Host header in HTTP request"))
}

/// Open a bi-stream on the agent's registered session. Returns an error
/// if the agent has no session (offline) or if `open_bi` fails on a
/// broken connection — the supersede-race retry happens at the caller.
async fn open_agent_stream(
    ctx: &ConnCtx,
    agent_id: iroh::EndpointId,
) -> anyhow::Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    let Some(session) = ctx.sessions.get(&agent_id) else {
        ctx.metrics.route_no_session_total.inc();
        anyhow::bail!("agent {} has no active session", agent_id.fmt_short());
    };
    match session.open_stream().await {
        Ok(pair) => Ok(pair),
        Err(e) => {
            // Capture the tenant before removing so we can tell the hub the
            // agent is gone — the `conn.closed()` cleanup path would otherwise
            // see the entry already removed and skip the notification.
            let tenant = ctx.sessions.tenant_for(&agent_id);
            if ctx.sessions.remove_if_current(&session) {
                notify_session_removed(ctx, tenant, agent_id).await;
            }
            Err(anyhow::anyhow!(
                "open_bi on agent {} session failed: {e}",
                agent_id.fmt_short()
            ))
        }
    }
}

/// Tell the hub an agent session is gone, if a hub client and tenant are known.
async fn notify_session_removed(
    ctx: &ConnCtx,
    tenant: Option<towonel_common::identity::TenantId>,
    agent_id: iroh::EndpointId,
) {
    if let Some(tenant_id) = tenant
        && let Some(client) = ctx.hub_client.as_deref()
        && let Ok(aid) = towonel_common::identity::AgentId::from_bytes(agent_id.as_bytes())
    {
        client.record_session_removed(tenant_id, aid).await;
    }
}

async fn tcp_listener_reconciler(ctx: Arc<ConnCtx>, shutdown: CancellationToken) {
    let mut active: std::collections::HashMap<u16, ActiveListener> =
        std::collections::HashMap::new();
    let mut rx = ctx.router.subscribe_tcp_listener_changes();

    // Reconcile once at boot so existing bindings come up before we wait on changes.
    reconcile_tcp_listeners(&ctx, &mut active);

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            res = rx.changed() => {
                if res.is_err() {
                    break;
                }
                reconcile_tcp_listeners(&ctx, &mut active);
            }
        }
    }
    // Stop the per-service accept loops; their in-flight connections drain
    // via the shared permit pool.
    for (_, existing) in active.drain() {
        existing.handle.abort();
    }
}

fn reconcile_tcp_listeners(
    ctx: &Arc<ConnCtx>,
    active: &mut std::collections::HashMap<u16, ActiveListener>,
) {
    let desired = ctx.router.desired_tcp_listeners();

    let stale_ports: Vec<u16> = active
        .iter()
        .filter(|(port, current)| desired.get(port) != Some(&current.binding))
        .map(|(port, _)| *port)
        .collect();
    for port in stale_ports {
        if let Some(existing) = active.remove(&port) {
            info!(
                port,
                tenant = %existing.binding.tenant,
                service = %existing.binding.service,
                "unbinding tcp listener"
            );
            existing.handle.abort();
        }
    }

    for (port, binding) in &desired {
        if active.contains_key(port) {
            continue;
        }
        let Some(listener) = bind_tcp_port(*port, binding) else {
            continue;
        };
        info!(
            port,
            tenant = %binding.tenant,
            service = %binding.service,
            "edge tcp listener bound"
        );
        let handle = tokio::spawn(tcp_accept_loop(listener, binding.clone(), Arc::clone(ctx)));
        active.insert(
            *port,
            ActiveListener {
                binding: binding.clone(),
                handle,
            },
        );
    }
}

struct ActiveListener {
    binding: towonel_common::routing::TcpListenerBinding,
    handle: tokio::task::JoinHandle<()>,
}

/// Try a dual-stack v6 bind first (single FD serving both families), fall back
/// to v4. `set_only_v6(false)` is explicit because the `bindv6only` sysctl
/// default differs between Linux and *BSD.
fn bind_dual_stack_socket<L>(
    port: u16,
    ty: socket2::Type,
    proto: socket2::Protocol,
    finalize: impl Fn(socket2::Socket) -> Option<L>,
) -> Option<L> {
    let v6 = std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);
    if let Some(listener) = make_bound_socket(v6, ty, proto, true).and_then(&finalize) {
        return Some(listener);
    }
    let v4 = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
    make_bound_socket(v4, ty, proto, false).and_then(&finalize)
}

fn make_bound_socket(
    addr: std::net::SocketAddr,
    ty: socket2::Type,
    proto: socket2::Protocol,
    dual_stack: bool,
) -> Option<socket2::Socket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, ty, Some(proto)).ok()?;
    if dual_stack {
        drop(sock.set_only_v6(false));
    }
    sock.set_nonblocking(true).ok()?;
    drop(sock.set_reuse_address(true));
    sock.bind(&addr.into()).ok()?;
    Some(sock)
}

fn bind_tcp_port(
    port: u16,
    binding: &towonel_common::routing::TcpListenerBinding,
) -> Option<TcpListener> {
    let listener =
        bind_dual_stack_socket(port, socket2::Type::STREAM, socket2::Protocol::TCP, |s| {
            s.listen(1024).ok()?;
            TcpListener::from_std(s.into()).ok()
        });
    if listener.is_none() {
        warn!(
            port,
            tenant = %binding.tenant,
            service = %binding.service,
            "failed to bind tcp listener on both v6 and v4",
        );
    }
    listener
}

async fn tcp_accept_loop(
    listener: TcpListener,
    binding: towonel_common::routing::TcpListenerBinding,
    ctx: Arc<ConnCtx>,
) {
    let binding = Arc::new(binding);
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(service = %binding.service, "tcp accept error: {e}");
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&ctx.connection_permits).try_acquire_owned() else {
            ctx.metrics.connections_rejected_overload.inc();
            debug!(%peer_addr, service = %binding.service, "edge inflight cap reached; dropping accepted tcp service connection");
            drop(tcp_stream);
            continue;
        };
        if let Err(e) = tcp_stream.set_nodelay(true) {
            debug!(%peer_addr, error = %e, "failed to set TCP_NODELAY on tcp service client");
        }
        debug!(%peer_addr, service = %binding.service, "accepted tcp service connection");

        let ctx = Arc::clone(&ctx);
        let binding = Arc::clone(&binding);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_tcp_connection(tcp_stream, peer_addr, &binding, &ctx).await {
                debug!(%peer_addr, service = %binding.service, error = %e, "tcp service connection handling failed");
            }
        });
    }
}

async fn handle_tcp_connection(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    binding: &towonel_common::routing::TcpListenerBinding,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    ctx.metrics.total_connections.inc();
    let _active = GaugeGuard::inc(&ctx.metrics.active_connections);
    let span = info_span!("tcp", peer = %peer_addr, service = %binding.service);
    async move {
        let start = Instant::now();

        let candidates = ctx
            .router
            .route_tcp_service(&binding.tenant, &binding.service)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no agents serving tcp service `{}` for tenant `{}`",
                    binding.service,
                    binding.tenant
                )
            })?;
        debug!(
            tenant = %binding.tenant,
            service = %binding.service,
            candidates = candidates.len(),
            "tcp route matched"
        );

        let (agent_addr, send_stream, recv_stream) =
            pick_agent_and_open_stream(ctx, candidates, || {
                ctx.router
                    .route_tcp_service(&binding.tenant, &binding.service)
            })
            .await?;
        let agent_short = agent_addr.id.fmt_short();
        debug!(agent = %agent_short, "tcp agent selected, stream opened");

        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst: tcp_stream.local_addr()?,
        };

        let route_key = format!("{TCP_ROUTE_PREFIX}{}", binding.service);
        let (bytes_in, bytes_out) = pipe_tcp(
            tcp_stream,
            &route_key,
            client_addrs,
            send_stream,
            recv_stream,
        )
        .await?;

        ctx.metrics.total_bytes_in.inc_by(bytes_in);
        ctx.metrics.total_bytes_out.inc_by(bytes_out);
        ctx.metrics
            .record_tenant_bytes(&binding.tenant, bytes_in, bytes_out);

        #[expect(
            clippy::cast_possible_truncation,
            reason = "tcp connection won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(
            service = %binding.service,
            agent = %agent_short,
            bytes_in,
            bytes_out,
            duration_ms,
            "tcp connection closed"
        );
        Ok(())
    }
    .instrument(span)
    .await
}

async fn pipe_tcp(
    tcp_stream: TcpStream,
    route_key: &str,
    client_addrs: ClientAddrs,
    mut send_stream: iroh::endpoint::SendStream,
    mut recv_stream: iroh::endpoint::RecvStream,
) -> anyhow::Result<(u64, u64)> {
    write_handshake(&mut send_stream, route_key, client_addrs).await?;

    let (tcp_read, mut tcp_write) = tcp_stream.into_split();
    let mut tcp_read = tokio::io::BufReader::with_capacity(COPY_BUF_SIZE, tcp_read);

    let c2a = async {
        let (n, res) = copy_buf_counting(&mut tcp_read, &mut send_stream).await;
        if let Err(ref e) = res {
            warn!(%route_key, "client->agent forward: {e}");
        }
        drop(send_stream.finish());
        n
    };
    let a2c = async {
        let (n, res) = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tcp_write).await;
        if let Err(ref e) = res {
            warn!(%route_key, "agent->client forward: {e}");
        }
        drop(tcp_write.shutdown().await);
        n
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a, a2c))
}

/// Idle window before an inactive UDP session is reaped. Picked to match
/// common NAT keepalive defaults so a quiet flow doesn't get torn down out
/// from under a client that was just being polite.
const UDP_SESSION_IDLE: Duration = Duration::from_mins(1);

/// Bound on how many datagrams we buffer per session in the channel from
/// the public UDP socket to the per-session QUIC pump. Drops the oldest on
/// overflow rather than blocking the listener and stalling other sessions.
const UDP_SESSION_QUEUE: usize = 64;

async fn udp_listener_reconciler(ctx: Arc<ConnCtx>, shutdown: CancellationToken) {
    let mut active: std::collections::HashMap<u16, ActiveListener> =
        std::collections::HashMap::new();
    let mut rx = ctx.router.subscribe_udp_listener_changes();

    reconcile_udp_listeners(&ctx, &mut active);

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            res = rx.changed() => {
                if res.is_err() {
                    break;
                }
                reconcile_udp_listeners(&ctx, &mut active);
            }
        }
    }
    for (_, existing) in active.drain() {
        existing.handle.abort();
    }
}

fn reconcile_udp_listeners(
    ctx: &Arc<ConnCtx>,
    active: &mut std::collections::HashMap<u16, ActiveListener>,
) {
    let desired = ctx.router.desired_udp_listeners();

    let stale_ports: Vec<u16> = active
        .iter()
        .filter(|(port, current)| desired.get(port) != Some(&current.binding))
        .map(|(port, _)| *port)
        .collect();
    for port in stale_ports {
        if let Some(existing) = active.remove(&port) {
            info!(
                port,
                tenant = %existing.binding.tenant,
                service = %existing.binding.service,
                "unbinding udp listener"
            );
            existing.handle.abort();
        }
    }

    for (port, binding) in &desired {
        if active.contains_key(port) {
            continue;
        }
        let Some(socket) = bind_udp_port(*port, binding) else {
            continue;
        };
        info!(
            port,
            tenant = %binding.tenant,
            service = %binding.service,
            "edge udp listener bound"
        );
        let tokio_socket = match UdpSocket::from_std(socket) {
            Ok(s) => s,
            Err(e) => {
                warn!(port, error = %e, "failed to register udp socket with tokio");
                continue;
            }
        };
        let handle = tokio::spawn(udp_listen_loop(
            Arc::new(tokio_socket),
            binding.clone(),
            Arc::clone(ctx),
        ));
        active.insert(
            *port,
            ActiveListener {
                binding: binding.clone(),
                handle,
            },
        );
    }
}

fn bind_udp_port(
    port: u16,
    binding: &towonel_common::routing::UdpListenerBinding,
) -> Option<std::net::UdpSocket> {
    let sock = bind_dual_stack_socket(port, socket2::Type::DGRAM, socket2::Protocol::UDP, |s| {
        Some(s.into())
    });
    if sock.is_none() {
        warn!(
            port,
            tenant = %binding.tenant,
            service = %binding.service,
            "failed to bind udp listener on both v6 and v4",
        );
    }
    sock
}

/// One UDP-socket-per-listener accept loop. Multiplexes incoming datagrams
/// across per-client-address sessions; each session owns a fresh QUIC stream
/// tagged `udp:<service>`.
type UdpSessions = std::collections::HashMap<std::net::SocketAddr, mpsc::Sender<bytes::Bytes>>;

/// Receive-buffer chunk for the UDP listener. Each datagram is split off the
/// chunk as a refcounted `Bytes` (no copy, no per-datagram allocation); a
/// fresh chunk is allocated only once spare capacity dips below one
/// max-size datagram.
const UDP_RECV_CHUNK: usize = 4 * MAX_UDP_DATAGRAM;

async fn udp_listen_loop(
    socket: Arc<UdpSocket>,
    binding: towonel_common::routing::UdpListenerBinding,
    ctx: Arc<ConnCtx>,
) {
    let binding = Arc::new(binding);
    let sessions: Arc<tokio::sync::Mutex<UdpSessions>> =
        Arc::new(tokio::sync::Mutex::new(UdpSessions::new()));
    let session_cap = max_udp_sessions_from_env();

    // Per-datagram hot path: resolve the tenant's counter child once.
    let tenant_bytes_in = ctx
        .metrics
        .tenant_bytes
        .with_label_values(&[&binding.tenant.to_string(), "in"]);

    let mut chunk = bytes::BytesMut::with_capacity(UDP_RECV_CHUNK);
    loop {
        // `recv_buf_from` appends into spare capacity, so keep at least one
        // max-size datagram spare or an oversized datagram would truncate.
        if chunk.capacity() < MAX_UDP_DATAGRAM {
            chunk = bytes::BytesMut::with_capacity(UDP_RECV_CHUNK);
        }
        let (n, peer_addr) = match socket.recv_buf_from(&mut chunk).await {
            Ok(v) => v,
            Err(e) => {
                warn!(service = %binding.service, "udp recv error: {e}");
                continue;
            }
        };
        let datagram = chunk.split_to(n).freeze();

        // Single critical section: get-or-create the session sender, then
        // release the lock before `try_send`. A stale entry (closed channel,
        // pump exited) is recreated in place. New sessions are refused once
        // the per-listener cap is hit so a UDP source-address flood can't
        // exhaust tasks/FDs/streams.
        let tx = {
            let mut map = sessions.lock().await;
            match map.get(&peer_addr) {
                Some(tx) if !tx.is_closed() => tx.clone(),
                _ => {
                    if map.len() >= session_cap {
                        drop(map);
                        ctx.metrics.connections_rejected_overload.inc();
                        continue;
                    }
                    let (tx, rx) = mpsc::channel::<bytes::Bytes>(UDP_SESSION_QUEUE);
                    map.insert(peer_addr, tx.clone());
                    drop(map);
                    let socket_for_session = Arc::clone(&socket);
                    let binding_for_session = Arc::clone(&binding);
                    let ctx_for_session = Arc::clone(&ctx);
                    let sessions_for_session = Arc::clone(&sessions);
                    let tx_for_cleanup = tx.clone();
                    tokio::spawn(async move {
                        udp_session_pump(
                            socket_for_session,
                            peer_addr,
                            binding_for_session,
                            ctx_for_session,
                            rx,
                        )
                        .await;
                        // Only evict our own entry: if the listener already
                        // recreated the session (new channel) for this peer,
                        // removing here would kill the live replacement.
                        let mut map = sessions_for_session.lock().await;
                        if map
                            .get(&peer_addr)
                            .is_some_and(|cur| cur.same_channel(&tx_for_cleanup))
                        {
                            map.remove(&peer_addr);
                        }
                    });
                    tx
                }
            }
        };

        if tx.try_send(datagram).is_err() {
            debug!(
                service = %binding.service,
                %peer_addr,
                "udp session queue full, dropping datagram"
            );
        } else {
            // Count only datagrams handed off for forwarding, not ones dropped
            // at the session cap or a full queue.
            ctx.metrics.total_bytes_in.inc_by(n as u64);
            tenant_bytes_in.inc_by(n as u64);
        }
    }
}

/// One UDP session: receive datagrams from the public socket via `rx`, ship
/// them over a fresh QUIC stream to an agent, and write the agent's reply
/// frames back to the public socket addressed at `peer_addr`. The session
/// ends when either side closes or idle time hits [`UDP_SESSION_IDLE`].
async fn udp_session_pump(
    socket: Arc<UdpSocket>,
    peer_addr: std::net::SocketAddr,
    binding: Arc<towonel_common::routing::UdpListenerBinding>,
    ctx: Arc<ConnCtx>,
    mut rx: mpsc::Receiver<bytes::Bytes>,
) {
    let span = info_span!("udp_session", peer = %peer_addr, service = %binding.service);
    async move {
        let Some(candidates) = ctx.router.route_udp_service(&binding.tenant, &binding.service)
        else {
            warn!(
                tenant = %binding.tenant,
                service = %binding.service,
                "no agents serving udp service; dropping session",
            );
            return;
        };

        let (agent_addr, mut send_stream, mut recv_stream) =
            match pick_agent_and_open_stream(&ctx, candidates, || {
                ctx.router
                    .route_udp_service(&binding.tenant, &binding.service)
            })
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "no agent could accept udp session");
                    return;
                }
            };

        let route_key = format!("{UDP_ROUTE_PREFIX}{}", binding.service);
        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "udp listener has no local_addr; dropping session");
                return;
            }
        };
        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst: local_addr,
        };
        if let Err(e) = write_handshake(&mut send_stream, &route_key, client_addrs).await {
            warn!(error = %e, "udp handshake to agent failed");
            return;
        }

        debug!(agent = %agent_addr.id.fmt_short(), "udp session opened");

        // Per-datagram hot path: resolve the tenant's counter child once.
        let tenant_bytes_out = ctx
            .metrics
            .tenant_bytes
            .with_label_values(&[&binding.tenant.to_string(), "out"]);

        // `select!` (not `join!`) so an idle-timeout on the edge->agent side
        // tears down the agent->edge side too. Otherwise a quiet origin
        // would leak one task per session.
        let mut frame_reader = DatagramFrameReader::new();
        loop {
            tokio::select! {
                framed = tokio::time::timeout(UDP_SESSION_IDLE, rx.recv()) => {
                    match framed {
                        Ok(Some(datagram)) => {
                            if let Err(e) = write_datagram_frame(&mut send_stream, &datagram).await {
                                debug!(error = %e, "edge->agent udp frame write failed");
                                break;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
                read = frame_reader.next(&mut recv_stream) => {
                    match read {
                        Ok(payload) => {
                            match socket.send_to(payload, peer_addr).await {
                                Ok(sent) => {
                                    ctx.metrics.total_bytes_out.inc_by(sent as u64);
                                    tenant_bytes_out.inc_by(sent as u64);
                                }
                                Err(e) => {
                                    debug!(error = %e, "udp send_to client failed");
                                    break;
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => {
                            debug!(error = %e, "agent->edge udp frame read failed");
                            break;
                        }
                    }
                }
            }
        }
        drop(send_stream.finish());
        debug!("udp session closed");
    }
    .instrument(span)
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn server_side_with(payload: &[u8]) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn peek_http_hostname_extracts_host() {
        let req = b"GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: app.alice.test\r\n\r\n";
        let (server, _client) = server_side_with(req).await;
        let hostname = Box::pin(peek_http_hostname(&server)).await.unwrap();
        assert_eq!(hostname, "app.alice.test");
    }

    #[tokio::test]
    async fn peek_http_hostname_waits_for_split_request_head() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.al")
            .await
            .unwrap();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(b"ice.test\r\n\r\n").await.unwrap();
            client
        });

        let hostname = Box::pin(peek_http_hostname(&server)).await.unwrap();
        assert_eq!(hostname, "app.alice.test");
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn peek_http_hostname_rejects_missing_host_header() {
        let req = b"GET / HTTP/1.0\r\nUser-Agent: probe\r\n\r\n";
        let (server, _client) = server_side_with(req).await;
        let err = Box::pin(peek_http_hostname(&server)).await.unwrap_err();
        assert!(err.to_string().contains("no Host header"), "got: {err}");
    }

    #[tokio::test]
    async fn peek_http_request_errors_on_close_without_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(client);
        // Wait for the FIN to land so peek observes EOF.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = [0u8; PEEK_BUF_SIZE];
        let err = peek_http_request(&server, &mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn peek_http_request_returns_partial_head_after_budget() {
        // Bytes received before a FIN stay peekable; the loop returns them
        // after its budget and Host extraction fails upstream.
        let (server, client) = server_side_with(b"GET / HTTP/1.1\r\n").await;
        drop(client);
        let mut buf = [0u8; PEEK_BUF_SIZE];
        let n = peek_http_request(&server, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"GET / HTTP/1.1\r\n");
        assert!(extract_host_header(&buf[..n]).is_none());
    }
}
