pub mod acme;
pub mod health;
pub mod router;
pub mod subscribe;
pub mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::EndpointAddr;
use iroh::endpoint::{Connection, Endpoint};
use smallvec::SmallVec;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::sni::extract_sni;
use towonel_common::tls_policy::TlsMode;
use towonel_common::tunnel::{ClientAddrs, write_handshake};

use self::acme::AcmeCoordinator;
use self::health::EdgeMetrics;
use self::router::Router;
use self::tls::CertStore;

/// Maximum bytes to peek from a TCP connection to extract the TLS `ClientHello`.
/// 16 KiB is more than enough for any realistic `ClientHello`.
const PEEK_BUF_SIZE: usize = 16_384;

/// Byte-pipe buffer size for `tokio::io::copy_buf`. 64 KiB matches QUIC's typical
/// window-unit and keeps syscall overhead low on bulk transfers.
const COPY_BUF_SIZE: usize = 64 * 1024;

/// Cap on retries while waiting for a full `ClientHello` to arrive in the
/// kernel peek buffer. With a 5 ms sleep between attempts this gives the peer
/// ~100 ms to finish sending the record — more than enough for realistic
/// handshakes even across a congested link.
const PEEK_MAX_ATTEMPTS: u32 = 20;
const PEEK_RETRY_DELAY: Duration = Duration::from_millis(5);

/// Typical route candidate count: one agent per hostname in most tenants,
/// occasionally 2-3 for HA. Inline capacity of 4 keeps the scoring path
/// allocation-free for the common case.
type AgentScoreVec<T> = SmallVec<[T; 4]>;

/// Pool of iroh QUIC connections, keyed by agent `EndpointId`.
///
/// QUIC connections are expensive to establish; streams are cheap. We keep
/// one connection per agent and open multiple streams over it. iroh's
/// `Connection` is cheaply cloneable (internal `Arc`), so callers can take
/// a handle out of the map without blocking.
type AgentPool = papaya::HashMap<iroh::EndpointId, Connection>;

/// Per-agent health state. Lock-free via atomics so the hot path doesn't
/// contend on a shared mutex.
struct AgentHealthState {
    /// Consecutive connection failures. Reset to 0 on success.
    consecutive_failures: AtomicU32,
    /// Unix timestamp (seconds) of the last successful stream open.
    last_success_ts: AtomicU64,
}

impl AgentHealthState {
    const fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            last_success_ts: AtomicU64::new(0),
        }
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_success_ts.store(now, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Lower score = healthier. Agents with no failures sort first; among
    /// those, the most recently successful one wins.
    fn score(&self) -> (u32, u64) {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        let recency_inv = u64::MAX - self.last_success_ts.load(Ordering::Relaxed);
        (failures, recency_inv)
    }
}

/// Shared map of per-agent health. Populated lazily on first connection
/// attempt. Never shrinks (agents that disappear from the route table
/// leave a harmless stale entry).
type AgentHealthMap = papaya::HashMap<iroh::EndpointId, Arc<AgentHealthState>>;

/// The edge: listens on one TCP port, peeks the SNI, looks up the hostname's
/// TLS policy, and dispatches:
///   - `Passthrough`: raw TLS bytes forwarded to the agent (agent/origin handles TLS)
///   - `Terminate`: edge handshakes TLS here, forwards plaintext to the agent
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
    metrics: EdgeMetrics,
}

struct TlsState {
    acceptor: tokio_rustls::TlsAcceptor,
    cert_store: CertStore,
    acme: Option<Arc<AcmeCoordinator>>,
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
            metrics: EdgeMetrics::new(),
        }
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

    pub async fn run(&self) -> anyhow::Result<()> {
        let health_app = health::router(self.metrics.clone());
        let health_listener = TcpListener::bind(&self.health_listen_addr).await?;
        info!(listen = %self.health_listen_addr, "edge health server listening");
        tokio::spawn(async move {
            axum::serve(health_listener, health_app).await.ok();
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
        });

        let listeners = bind_listeners(&self.listen_addr, self.listen_workers).await?;
        info!(
            listen = %self.listen_addr,
            workers = listeners.len(),
            tls = self.tls.is_some(),
            "edge listening"
        );

        let mut tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let ctx = Arc::clone(&ctx);
            tasks.push(tokio::spawn(accept_loop(listener, ctx)));
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
}

/// Dispatch a single incoming TCP connection. Peek the SNI, look up the
/// hostname's policy, then either terminate TLS here or pass through to the
/// agent.
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
    let state = Arc::new(AgentHealthState::new());
    // Concurrent insert is fine: whoever lost the race drops their Arc and we
    // return the winning one. All callers ultimately see the same Arc.
    Arc::clone(guard.get_or_insert(id, state))
}

/// Score `candidates` by agent health, then dial them in order until one
/// succeeds. Records success/failure into the health map as a side effect.
/// Returns the chosen agent plus an open bidirectional QUIC stream.
async fn pick_agent_and_open_stream(
    ctx: &ConnCtx,
    candidates: Vec<EndpointAddr>,
) -> anyhow::Result<(
    EndpointAddr,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
)> {
    let mut scored: AgentScoreVec<(EndpointAddr, Arc<AgentHealthState>, (u32, u64))> =
        SmallVec::with_capacity(candidates.len());
    for addr in candidates {
        let h = get_health(&ctx.health, addr.id);
        let score = h.score();
        scored.push((addr, h, score));
    }
    scored.sort_by_key(|(_, _, score)| *score);

    let mut last_err: Option<anyhow::Error> = None;
    for (agent_addr, health_state, _) in scored {
        match open_agent_stream(&ctx.endpoint, &ctx.pool, agent_addr.clone()).await {
            Ok((send, recv)) => {
                health_state.record_success();
                return Ok((agent_addr, send, recv));
            }
            Err(e) => {
                health_state.record_failure();
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
        if tls_record_complete(&buf[..n]) || n >= buf.len() {
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
    buf.len() >= 5 && buf.len() >= 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]]))
}

async fn handle_connection_inner(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    let span = info_span!("conn", peer = %peer_addr);
    async move {
        let start = Instant::now();

        let mut peek_buf = vec![0u8; PEEK_BUF_SIZE];
        let n = peek_client_hello(&tcp_stream, &mut peek_buf).await?;

        let hostname = extract_sni(&peek_buf[..n])
            .ok_or_else(|| anyhow::anyhow!("no SNI found in ClientHello"))?;
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
        let agent_short = agent_addr.id.fmt_short();
        debug!(agent = %agent_short, "agent selected, stream opened");

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
            TlsMode::Terminate => {
                pipe_terminate(
                    tcp_stream,
                    &hostname,
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

        // truncation intentional:
        #[allow(clippy::cast_possible_truncation)]
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
        let _ = send_stream.finish();
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(&mut recv_stream, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
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
        let _ = send_stream.finish();
        res.unwrap_or(0)
    };
    let a2c = async {
        let res = forward_quic_to_writer(&mut recv_stream, &mut tls_write).await;
        let _ = tls_write.shutdown().await;
        res.unwrap_or(0)
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a, a2c))
}

/// Zero-copy forward from an iroh `RecvStream` to any `AsyncWrite`. Uses
/// `read_chunk` so the bytes stay in Quinn's receive buffer; we hand a `Bytes`
/// slice straight to the writer without passing through an intermediate
/// `BufReader`. This saves one `memcpy` per byte and ~64 KiB of RSS per
/// stream direction compared to `BufReader + copy_buf`.
async fn forward_quic_to_writer<W>(
    recv: &mut iroh::endpoint::RecvStream,
    writer: &mut W,
) -> std::io::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        match recv.read_chunk(usize::MAX).await {
            Ok(Some(chunk)) => {
                writer.write_all(&chunk.bytes).await?;
                total = total.saturating_add(chunk.bytes.len() as u64);
            }
            Ok(None) => return Ok(total),
            Err(e) => return Err(std::io::Error::other(e)),
        }
    }
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
