pub mod health;
pub mod hub_client;
pub mod hub_link;
pub mod port_reservations;
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
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::edge_cred::{AuthFrame, EdgeCred};
use towonel_common::sni::extract_sni;
use towonel_common::tls_policy::TlsMode;
use towonel_common::tunnel::{
    CONTROL_STATUS_INTERNAL_ERROR, CONTROL_STATUS_INVALID, CONTROL_STATUS_NOT_IMPLEMENTED,
    CONTROL_STATUS_OK, COPY_BUF_SIZE, ClientAddrs, MAX_UDP_DATAGRAM, TCP_ROUTE_PREFIX,
    UDP_ROUTE_PREFIX, forward_quic_to_writer, read_control_prefix, read_datagram_frame,
    write_control_status, write_datagram_frame, write_handshake,
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

/// The edge: listens on one TCP port, peeks the SNI, and forwards raw TLS
/// bytes to the agent. Agent/origin handles TLS termination.
pub struct Edge {
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    sessions: Arc<SessionRegistry>,
    listen_addr: String,
    health_listen_addr: String,
    listen_workers: usize,
    proxy_protocol: Arc<ProxyProtocolConfig>,
    metrics: EdgeMetrics,
    hub_client: Option<Arc<dyn HubClient>>,
}

impl Edge {
    pub fn new(
        router: Arc<Router>,
        endpoint: Arc<Endpoint>,
        listen_addr: String,
        health_listen_addr: String,
    ) -> Self {
        let metrics = EdgeMetrics::new();
        let sessions = Arc::new(SessionRegistry::new(metrics.clone()));
        Self {
            router,
            endpoint,
            sessions,
            listen_addr,
            health_listen_addr,
            listen_workers: 1,
            proxy_protocol: Arc::default(),
            metrics,
            hub_client: None,
        }
    }

    #[must_use]
    pub fn with_hub_client(mut self, client: Arc<dyn HubClient>) -> Self {
        self.hub_client = Some(client);
        self
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

    pub async fn run(&self) -> anyhow::Result<()> {
        let health_app = health::router(self.metrics.clone());
        let health_listener = TcpListener::bind(&self.health_listen_addr).await?;
        info!(listen = %self.health_listen_addr, "edge health server listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(health_listener, health_app).await {
                tracing::error!(error = %e, "edge health server exited");
            }
        });

        let ctx = Arc::new(ConnCtx {
            router: Arc::clone(&self.router),
            sessions: Arc::clone(&self.sessions),
            metrics: self.metrics.clone(),
            proxy_protocol: Arc::clone(&self.proxy_protocol),
        });

        let listeners = bind_listeners(&self.listen_addr, self.listen_workers).await?;
        info!(
            listen = %self.listen_addr,
            workers = listeners.len(),
            "edge listening"
        );

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(listeners.len() + 3);
        for listener in listeners {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(accept_loop(listener, ctx)));
        }

        {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(tcp_listener_reconciler(ctx)));
        }

        {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(udp_listener_reconciler(ctx)));
        }

        // Agents dialing in register sessions; the legacy outbound-dial
        // path stays available for agents still running in accept mode.
        {
            let endpoint = Arc::clone(&self.endpoint);
            let sessions = Arc::clone(&self.sessions);
            let router = Arc::clone(&self.router);
            let metrics = self.metrics.clone();
            let hub_client = self.hub_client.clone();
            tasks.push(tokio::spawn(iroh_accept_loop(
                endpoint, sessions, router, metrics, hub_client,
            )));
        }

        if let Some(hub_client) = self.hub_client.as_ref() {
            let stream = hub_client.subscribe_routes();
            let router = Arc::clone(&self.router);
            tasks.push(tokio::spawn(route_sync_loop(stream, router)));
        }

        for task in tasks {
            // Accept loops never return `Ok`; only observe task panics.
            if let Err(e) = task.await {
                warn!("accept loop panicked: {e}");
            }
        }
        Ok(())
    }
}

async fn route_sync_loop(mut stream: hub_client::RouteStream, router: Arc<Router>) {
    use tokio_stream::StreamExt;
    while let Some(table) = stream.next().await {
        let count = table.len();
        router.replace(table);
        info!(hostnames = count, "dynamic route update applied");
    }
    info!("route stream closed, stopping sync loop");
}

async fn iroh_accept_loop(
    endpoint: Arc<Endpoint>,
    sessions: Arc<SessionRegistry>,
    router: Arc<Router>,
    metrics: EdgeMetrics,
    hub_client: Option<Arc<dyn HubClient>>,
) {
    info!("edge iroh accept loop ready");
    loop {
        let Some(incoming) = endpoint.accept().await else {
            info!("edge iroh endpoint closed, stopping accept loop");
            return;
        };
        let sessions = Arc::clone(&sessions);
        let router = Arc::clone(&router);
        let metrics = metrics.clone();
        let hub_client = hub_client.clone();
        tokio::spawn(async move {
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
                tokio::spawn(handle_agent_stream(
                    send, recv, agent_id, hub_client, sessions,
                ));
            }
        }
    };

    tokio::select! {
        () = accept_loop => {}
        _close = conn.closed() => {}
    }
    let tenant = sessions.tenant_for(&agent_id);
    sessions.remove_if_current(&session);
    if let Some(tenant_id) = tenant
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
    agent_id: iroh::EndpointId,
    hub_client: Option<Arc<dyn HubClient>>,
    sessions: Arc<SessionRegistry>,
) {
    match tokio::time::timeout(
        CONTROL_STREAM_TIMEOUT,
        run_control_stream(send, recv, agent_id, hub_client, sessions),
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
        && cred_agent_id.as_bytes() == agent_id.as_bytes()
    {
        sessions.record_tenant(agent_id, tenant_id);
        client.record_session_added(tenant_id, cred_agent_id).await;
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

/// One accept loop — shared by all reuseport workers.
async fn accept_loop(listener: TcpListener, ctx: Arc<ConnCtx>) {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("TCP accept error: {e}");
                continue;
            }
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
            if let Err(e) = handle_connection(tcp_stream, peer_addr, &ctx).await {
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
    ctx.metrics.active_connections.inc();

    let result = handle_connection_inner(tcp_stream, peer_addr, ctx).await;

    ctx.metrics.active_connections.dec();

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
/// Returns the first stream that opens.
async fn pick_agent_and_open_stream(
    ctx: &ConnCtx,
    mut candidates: self::router::Candidates,
) -> anyhow::Result<(
    EndpointAddr,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
)> {
    fastrand::shuffle(&mut candidates);

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PICK_AGENT_ATTEMPTS {
        for agent_addr in &candidates {
            match open_agent_stream(&ctx.sessions, &ctx.metrics, agent_addr.id).await {
                Ok((send, recv)) => {
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
        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst: tcp_stream.local_addr()?,
        };
        let (bytes_in, bytes_out) = match policy {
            TlsMode::Passthrough => {
                pipe_passthrough(
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
        pick_agent_and_open_stream(ctx, candidates).await?;
    debug!(agent = %agent_addr.id.fmt_short(), "agent selected, stream opened");

    Ok(Preparation {
        hostname,
        policy,
        agent_addr,
        send_stream,
        recv_stream,
    })
}

async fn pipe_passthrough(
    tcp_stream: TcpStream,
    hostname: &str,
    client_addrs: ClientAddrs,
    mut send_stream: iroh::endpoint::SendStream,
    mut recv_stream: iroh::endpoint::RecvStream,
) -> anyhow::Result<(u64, u64)> {
    write_handshake(&mut send_stream, hostname, client_addrs).await?;

    let (tcp_read, mut tcp_write) = tcp_stream.into_split();
    let mut tcp_read = tokio::io::BufReader::with_capacity(COPY_BUF_SIZE, tcp_read);

    let c2a = async {
        let res = tokio::io::copy_buf(&mut tcp_read, &mut send_stream).await;
        if let Err(ref e) = res {
            warn!(%hostname, "client->agent forward: {e}");
        }
        drop(send_stream.finish());
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tcp_write).await;
        if let Err(ref e) = res {
            warn!(%hostname, "agent->client forward: {e}");
        }
        drop(tcp_write.shutdown().await);
        res.unwrap_or(0)
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a, a2c))
}

/// Open a bi-stream on the agent's registered session. Returns an error
/// if the agent has no session (offline) or if `open_bi` fails on a
/// broken connection — the supersede-race retry happens at the caller.
async fn open_agent_stream(
    sessions: &SessionRegistry,
    metrics: &EdgeMetrics,
    agent_id: iroh::EndpointId,
) -> anyhow::Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    let Some(session) = sessions.get(&agent_id) else {
        metrics.route_no_session_total.inc();
        anyhow::bail!("agent {} has no active session", agent_id.fmt_short());
    };
    match session.open_stream().await {
        Ok(pair) => Ok(pair),
        Err(e) => {
            sessions.remove_if_current(&session);
            Err(anyhow::anyhow!(
                "open_bi on agent {} session failed: {e}",
                agent_id.fmt_short()
            ))
        }
    }
}

async fn tcp_listener_reconciler(ctx: Arc<ConnCtx>) {
    let mut active: std::collections::HashMap<u16, ActiveListener> =
        std::collections::HashMap::new();
    let mut rx = ctx.router.subscribe_tcp_listener_changes();

    // Reconcile once at boot so existing bindings come up before we wait on changes.
    reconcile_tcp_listeners(&ctx, &mut active);

    loop {
        if rx.changed().await.is_err() {
            return;
        }
        reconcile_tcp_listeners(&ctx, &mut active);
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
        if let Err(e) = tcp_stream.set_nodelay(true) {
            debug!(%peer_addr, error = %e, "failed to set TCP_NODELAY on tcp service client");
        }
        debug!(%peer_addr, service = %binding.service, "accepted tcp service connection");

        let ctx = Arc::clone(&ctx);
        let binding = Arc::clone(&binding);
        tokio::spawn(async move {
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
    ctx.metrics.active_connections.inc();
    let span = info_span!("tcp", peer = %peer_addr, service = %binding.service);
    let result = async move {
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
            pick_agent_and_open_stream(ctx, candidates).await?;
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
    .await;

    ctx.metrics.active_connections.dec();
    result
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
        let res = tokio::io::copy_buf(&mut tcp_read, &mut send_stream).await;
        if let Err(ref e) = res {
            warn!(%route_key, "client->agent forward: {e}");
        }
        drop(send_stream.finish());
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tcp_write).await;
        if let Err(ref e) = res {
            warn!(%route_key, "agent->client forward: {e}");
        }
        drop(tcp_write.shutdown().await);
        res.unwrap_or(0)
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

async fn udp_listener_reconciler(ctx: Arc<ConnCtx>) {
    let mut active: std::collections::HashMap<u16, ActiveListener> =
        std::collections::HashMap::new();
    let mut rx = ctx.router.subscribe_udp_listener_changes();

    reconcile_udp_listeners(&ctx, &mut active);

    loop {
        if rx.changed().await.is_err() {
            return;
        }
        reconcile_udp_listeners(&ctx, &mut active);
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
type UdpSessions = std::collections::HashMap<std::net::SocketAddr, mpsc::Sender<Vec<u8>>>;

async fn udp_listen_loop(
    socket: Arc<UdpSocket>,
    binding: towonel_common::routing::UdpListenerBinding,
    ctx: Arc<ConnCtx>,
) {
    let binding = Arc::new(binding);
    let sessions: Arc<tokio::sync::Mutex<UdpSessions>> =
        Arc::new(tokio::sync::Mutex::new(UdpSessions::new()));

    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        let (n, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(service = %binding.service, "udp recv error: {e}");
                continue;
            }
        };
        ctx.metrics.total_bytes_in.inc_by(n as u64);
        #[expect(
            clippy::indexing_slicing,
            reason = "UdpSocket::recv_from bounds n <= buf.len()"
        )]
        let datagram = buf[..n].to_vec();

        // Single critical section: get-or-create the session sender, then
        // release the lock before `try_send`. A stale entry (closed channel,
        // pump exited) is recreated in place.
        let tx = {
            let mut map = sessions.lock().await;
            match map.get(&peer_addr) {
                Some(tx) if !tx.is_closed() => tx.clone(),
                _ => {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(UDP_SESSION_QUEUE);
                    map.insert(peer_addr, tx.clone());
                    drop(map);
                    let socket_for_session = Arc::clone(&socket);
                    let binding_for_session = Arc::clone(&binding);
                    let ctx_for_session = Arc::clone(&ctx);
                    let sessions_for_session = Arc::clone(&sessions);
                    tokio::spawn(async move {
                        udp_session_pump(
                            socket_for_session,
                            peer_addr,
                            binding_for_session,
                            ctx_for_session,
                            rx,
                        )
                        .await;
                        sessions_for_session.lock().await.remove(&peer_addr);
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
    mut rx: mpsc::Receiver<Vec<u8>>,
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
            match pick_agent_and_open_stream(&ctx, candidates).await {
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

        // `select!` (not `join!`) so an idle-timeout on the edge->agent side
        // tears down the agent->edge side too. Otherwise a quiet origin
        // would leak one task per session.
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
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
                read = read_datagram_frame(&mut recv_stream, &mut buf) => {
                    match read {
                        Ok(n) => {
                            #[expect(
                                clippy::indexing_slicing,
                                reason = "read_datagram_frame bounds n <= buf.len()"
                            )]
                            let payload = &buf[..n];
                            match socket.send_to(payload, peer_addr).await {
                                Ok(sent) => ctx.metrics.total_bytes_out.inc_by(sent as u64),
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
