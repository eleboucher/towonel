pub mod acme;
pub mod health;
pub mod proxy_protocol;
pub mod router;
pub mod subscribe;
pub mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use iroh::EndpointAddr;
use iroh::endpoint::{Connection, Endpoint};
use smallvec::SmallVec;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::sni::extract_sni;
use towonel_common::tls_policy::TlsMode;
use towonel_common::tunnel::{
    COPY_BUF_SIZE, ClientAddrs, MAX_UDP_DATAGRAM, TCP_ROUTE_PREFIX, UDP_ROUTE_PREFIX,
    forward_quic_to_writer, read_datagram_frame, write_datagram_frame, write_handshake,
};

use self::acme::AcmeCoordinator;
use self::health::EdgeMetrics;
use self::router::Router;
use self::tls::CertStore;
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

/// Pool of iroh QUIC connections, keyed by agent `EndpointId`.
///
/// QUIC connections are expensive to establish; streams are cheap. We keep
/// one connection per agent and open multiple streams over it. iroh's
/// `Connection` is cheaply cloneable (internal `Arc`), so callers can take
/// a handle out of the map without blocking.
type AgentPool = papaya::HashMap<iroh::EndpointId, Connection>;

/// Per-agent consecutive connect failures. Reset to 0 on success;
/// `fetch_add(1)` on failure. Ordering by this value demotes recently
/// failing agents without remembering how long ago they failed.
type AgentHealthState = AtomicU32;

/// Shared map of per-agent health. Populated lazily on first connection
/// attempt. Never shrinks (agents that disappear from the route table
/// leave a harmless stale entry).
type AgentHealthMap = papaya::HashMap<iroh::EndpointId, Arc<AgentHealthState>>;

/// The edge: listens on one TCP port, peeks the SNI, looks up the hostname's
/// TLS policy, and dispatches:
///   - `Passthrough`: raw TLS bytes forwarded to the agent (agent/origin handles TLS)
///   - `Terminate`: edge handshakes TLS here, forwards plaintext to the agent
///   - `Hub self-route`: SNI matches the colocated hub's public hostname; TLS
///     is terminated and proxied to the local hub HTTP listener.
///
/// A single port serves both modes. Tenants pick per-hostname.
pub struct Edge {
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    agent_pool: Arc<AgentPool>,
    agent_health: Arc<AgentHealthMap>,
    listen_addr: String,
    health_listen_addr: String,
    listen_workers: usize,
    tls: Option<TlsState>,
    hub_self_route: Option<Arc<HubSelfRoute>>,
    proxy_protocol: Arc<ProxyProtocolConfig>,
    metrics: EdgeMetrics,
}

struct TlsState {
    acceptor: tokio_rustls::TlsAcceptor,
    cert_store: CertStore,
    acme: Option<Arc<AcmeCoordinator>>,
}

pub struct HubSelfRoute {
    pub hostname: String,
    pub local_addr: String,
}

impl Edge {
    pub fn new(
        router: Arc<Router>,
        endpoint: Arc<Endpoint>,
        listen_addr: String,
        health_listen_addr: String,
    ) -> Self {
        Self {
            router,
            endpoint,
            agent_pool: Arc::new(AgentPool::new()),
            agent_health: Arc::new(AgentHealthMap::new()),
            listen_addr,
            health_listen_addr,
            listen_workers: 1,
            tls: None,
            hub_self_route: None,
            proxy_protocol: Arc::default(),
            metrics: EdgeMetrics::new(),
        }
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

    pub fn with_tls(mut self, cert_store: CertStore, acme: Option<Arc<AcmeCoordinator>>) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(cert_store.server_config());
        self.tls = Some(TlsState {
            acceptor,
            cert_store,
            acme,
        });
        self
    }

    #[must_use]
    pub fn with_hub_self_route(mut self, route: HubSelfRoute) -> Self {
        self.hub_self_route = Some(Arc::new(route));
        self
    }

    pub fn acme(&self) -> Option<Arc<AcmeCoordinator>> {
        self.tls.as_ref().and_then(|t| t.acme.clone())
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
            endpoint: Arc::clone(&self.endpoint),
            pool: Arc::clone(&self.agent_pool),
            health: Arc::clone(&self.agent_health),
            metrics: self.metrics.clone(),
            tls_acceptor: self.tls.as_ref().map(|t| t.acceptor.clone()),
            cert_store: self.tls.as_ref().map(|t| t.cert_store.clone()),
            acme: self.tls.as_ref().and_then(|t| t.acme.clone()),
            hub_self_route: self.hub_self_route.clone(),
            proxy_protocol: Arc::clone(&self.proxy_protocol),
        });

        let listeners = bind_listeners(&self.listen_addr, self.listen_workers).await?;
        info!(
            listen = %self.listen_addr,
            workers = listeners.len(),
            tls = self.tls.is_some(),
            "edge listening"
        );

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(listeners.len());
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

        for task in tasks {
            // Accept loops never return `Ok`; only observe task panics.
            if let Err(e) = task.await {
                warn!("accept loop panicked: {e}");
            }
        }
        Ok(())
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
    endpoint: Arc<Endpoint>,
    pool: Arc<AgentPool>,
    health: Arc<AgentHealthMap>,
    metrics: EdgeMetrics,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    cert_store: Option<CertStore>,
    acme: Option<Arc<AcmeCoordinator>>,
    hub_self_route: Option<Arc<HubSelfRoute>>,
    proxy_protocol: Arc<ProxyProtocolConfig>,
}

/// Dispatch a single incoming TCP connection. Peek the SNI, look up the
/// hostname's policy, then either terminate TLS here or pass through to the
/// agent.
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

fn get_health(health: &AgentHealthMap, id: iroh::EndpointId) -> Arc<AgentHealthState> {
    let guard = health.pin();
    if let Some(existing) = guard.get(&id) {
        return Arc::clone(existing);
    }
    // Concurrent insert is fine: whoever lost the race drops their Arc and we
    // return the winning one. All callers ultimately see the same Arc.
    Arc::clone(guard.get_or_insert(id, Arc::new(AgentHealthState::new(0))))
}

/// Shuffle `candidates` for fair spread, then stable-sort by consecutive
/// failures so healthy agents are tried before failing ones. Dials in order
/// until one succeeds; records success/failure as a side effect. Returns the
/// chosen agent plus an open bidirectional QUIC stream.
async fn pick_agent_and_open_stream(
    ctx: &ConnCtx,
    mut candidates: self::router::Candidates,
) -> anyhow::Result<(
    EndpointAddr,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
)> {
    fastrand::shuffle(&mut candidates);
    let mut scored: SmallVec<[(EndpointAddr, Arc<AgentHealthState>); 4]> =
        SmallVec::with_capacity(candidates.len());
    for addr in candidates {
        let h = get_health(&ctx.health, addr.id);
        scored.push((addr, h));
    }
    scored.sort_by_key(|(_, h)| h.load(Ordering::Relaxed));

    let mut last_err: Option<anyhow::Error> = None;
    for (agent_addr, health) in scored {
        match open_agent_stream(&ctx.endpoint, &ctx.pool, agent_addr.clone()).await {
            Ok((send, recv)) => {
                health.store(0, Ordering::Relaxed);
                return Ok((agent_addr, send, recv));
            }
            Err(e) => {
                health.fetch_add(1, Ordering::Relaxed);
                debug!(
                    agent = %agent_addr.id.fmt_short(),
                    error = %e,
                    "agent stream open failed, trying next"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all agents failed")))
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
    let peer_addr = resolve_peer_addr(&mut tcp_stream, immediate_peer, ctx).await?;

    let span = info_span!("conn", peer = %peer_addr);
    async move {
        let start = Instant::now();

        let mut peek_buf = [0u8; PEEK_BUF_SIZE];
        let n = peek_client_hello(&tcp_stream, &mut peek_buf).await?;

        let peeked = peek_buf.get(..n).unwrap_or(&peek_buf);
        let hostname =
            extract_sni(peeked).ok_or_else(|| anyhow::anyhow!("no SNI found in ClientHello"))?;
        debug!(%hostname, "SNI extracted");

        if let Some(self_route) = ctx.hub_self_route.as_ref()
            && self_route.hostname.eq_ignore_ascii_case(hostname)
        {
            let (bytes_in, bytes_out) =
                pipe_to_local_hub(tcp_stream, hostname, &self_route.local_addr, ctx).await?;
            ctx.metrics.total_bytes_in.inc_by(bytes_in);
            ctx.metrics.total_bytes_out.inc_by(bytes_out);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "connection won't last 584 million years"
            )]
            let duration_ms = start.elapsed().as_millis() as u64;
            debug!(
                %hostname,
                bytes_in,
                bytes_out,
                duration_ms,
                "hub self-route connection closed"
            );
            return Ok(());
        }

        let (candidates, policy) = ctx
            .router
            .route(hostname)
            .ok_or_else(|| anyhow::anyhow!("no route for hostname: {hostname}"))?;
        debug!(
            %hostname,
            candidates = candidates.len(),
            mode = policy.label(),
            "route matched"
        );

        let (agent_addr, send_stream, recv_stream) =
            pick_agent_and_open_stream(ctx, candidates).await?;
        let agent_short = agent_addr.id.fmt_short();
        debug!(agent = %agent_short, "agent selected, stream opened");

        let client_addrs = ClientAddrs {
            src: peer_addr,
            dst: tcp_stream.local_addr()?,
        };

        let (bytes_in, bytes_out) = match policy {
            TlsMode::Passthrough => {
                pipe_passthrough(tcp_stream, hostname, client_addrs, send_stream, recv_stream)
                    .await?
            }
            TlsMode::Terminate => {
                pipe_terminate(
                    tcp_stream,
                    hostname,
                    client_addrs,
                    send_stream,
                    recv_stream,
                    ctx,
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
        drop(send_stream.finish());
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tcp_write).await;
        drop(tcp_write.shutdown().await);
        res.unwrap_or(0)
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a, a2c))
}

async fn pipe_terminate(
    tcp_stream: TcpStream,
    hostname: &str,
    client_addrs: ClientAddrs,
    mut send_stream: iroh::endpoint::SendStream,
    mut recv_stream: iroh::endpoint::RecvStream,
    ctx: &ConnCtx,
) -> anyhow::Result<(u64, u64)> {
    let acceptor = ctx
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS termination configured but acceptor missing"))?;
    let cert_store = ctx
        .cert_store
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS termination configured but cert store missing"))?;

    if !cert_store.has_cert(hostname) {
        match &ctx.acme {
            Some(acme) => acme.ensure_cert(hostname).await?,
            None => anyhow::bail!("no cert for {hostname} and ACME disabled"),
        }
    }

    let tls_stream = acceptor.accept(tcp_stream).await?;
    debug!(%hostname, "TLS handshake complete");
    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_read = tokio::io::BufReader::with_capacity(COPY_BUF_SIZE, tls_read);

    write_handshake(&mut send_stream, hostname, client_addrs).await?;

    let c2a = async {
        let res = tokio::io::copy_buf(&mut tls_read, &mut send_stream).await;
        drop(send_stream.finish());
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tls_write).await;
        drop(tls_write.shutdown().await);
        res.unwrap_or(0)
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a, a2c))
}

async fn pipe_to_local_hub(
    tcp_stream: TcpStream,
    hostname: &str,
    local_addr: &str,
    ctx: &ConnCtx,
) -> anyhow::Result<(u64, u64)> {
    let acceptor = ctx
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("hub self-route requires TLS termination"))?;
    let cert_store = ctx
        .cert_store
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("hub self-route requires a cert store"))?;

    if !cert_store.has_cert(hostname) {
        match &ctx.acme {
            Some(acme) => acme.ensure_cert(hostname).await?,
            None => anyhow::bail!("no cert for hub hostname {hostname} and ACME disabled"),
        }
    }

    let mut tls_stream = acceptor.accept(tcp_stream).await?;
    debug!(%hostname, "TLS handshake complete (hub self-route)");

    let mut local = TcpStream::connect(local_addr).await.map_err(|e| {
        anyhow::anyhow!("hub self-route: failed to connect to local hub at {local_addr}: {e}")
    })?;
    drop(local.set_nodelay(true));

    let (c2h, h2c) = tokio::io::copy_bidirectional(&mut tls_stream, &mut local)
        .await
        .unwrap_or((0, 0));
    Ok((c2h, h2c))
}

/// Return a new bidirectional QUIC stream to the agent, reusing a pooled
/// connection when possible.
///
/// If the pooled connection's `open_bi` fails (peer went away, idle-timed
/// out, etc.), we drop it and dial a fresh one. `agent_addr` may include
/// direct socket addresses so iroh can connect without relay/discovery.
async fn open_agent_stream(
    endpoint: &Endpoint,
    pool: &AgentPool,
    agent_addr: EndpointAddr,
) -> anyhow::Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    let agent_id = agent_addr.id;

    let cached = pool.pin().get(&agent_id).cloned();
    if let Some(conn) = cached {
        match conn.open_bi().await {
            Ok(pair) => return Ok(pair),
            Err(e) => {
                debug!(
                    agent = %agent_id.fmt_short(),
                    error = %e,
                    "pooled connection broken, reconnecting"
                );
                pool.pin().remove(&agent_id);
            }
        }
    }

    info!(agent = %agent_id.fmt_short(), "connecting to agent");
    let conn = endpoint.connect(agent_addr, ALPN_TUNNEL).await?;
    let path_type = conn
        .paths()
        .into_iter()
        .find(iroh::endpoint::PathInfo::is_selected)
        .map_or("unknown", |p| if p.is_relay() { "relay" } else { "direct" });
    info!(
        agent = %agent_id.fmt_short(),
        path = path_type,
        "agent connection established"
    );
    let pair = conn.open_bi().await?;
    pool.pin().insert(agent_id, conn);
    Ok(pair)
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
        drop(send_stream.finish());
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(Vec::new(), &mut recv_stream, &mut tcp_write).await;
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
