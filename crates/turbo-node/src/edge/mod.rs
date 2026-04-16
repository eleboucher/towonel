pub mod acme;
pub mod health;
pub mod router;
pub mod subscribe;
pub mod tls;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use iroh::EndpointAddr;
use iroh::endpoint::{Connection, Endpoint};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info, info_span, warn};

use turbo_common::protocol::ALPN_TUNNEL;
use turbo_common::sni::extract_sni;
use turbo_common::tls_policy::TlsMode;
use turbo_common::tunnel::write_hostname_header;

use self::acme::AcmeCoordinator;
use self::health::EdgeMetrics;
use self::router::Router;
use self::tls::CertStore;

/// Maximum bytes to peek from a TCP connection to extract the TLS ClientHello.
/// 16 KiB is more than enough for any realistic ClientHello.
const PEEK_BUF_SIZE: usize = 16_384;

/// Pool of iroh QUIC connections, keyed by agent EndpointId.
///
/// QUIC connections are expensive to establish; streams are cheap. We keep
/// one connection per agent and open multiple streams over it. iroh's
/// `Connection` is cheaply cloneable (internal `Arc`), so callers can take
/// a handle out of the map without holding the lock across awaits.
type AgentPool = Mutex<HashMap<iroh::EndpointId, Connection>>;

/// Per-agent health state. Lock-free via atomics so the hot path doesn't
/// contend on a shared mutex.
struct AgentHealthState {
    /// Consecutive connection failures. Reset to 0 on success.
    consecutive_failures: AtomicU32,
    /// Unix timestamp (seconds) of the last successful stream open.
    last_success_ts: AtomicU64,
}

impl AgentHealthState {
    fn new() -> Self {
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
type AgentHealthMap = Mutex<HashMap<iroh::EndpointId, Arc<AgentHealthState>>>;

/// The edge: listens on one TCP port, peeks the SNI, looks up the hostname's
/// TLS policy, and dispatches:
///   - `Passthrough`: raw TLS bytes forwarded to the agent (agent/origin handles TLS)
///   - `Terminate`: edge handshakes TLS here, forwards plaintext to the agent
///
/// A single port serves both modes. Community members pick per-hostname.
pub struct Edge {
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    agent_pool: Arc<AgentPool>,
    agent_health: Arc<AgentHealthMap>,
    listen_addr: String,
    health_listen_addr: String,
    tls: Option<TlsState>,
    metrics: EdgeMetrics,
}

struct TlsState {
    server_config: Arc<rustls::ServerConfig>,
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
            agent_pool: Arc::new(Mutex::new(HashMap::new())),
            agent_health: Arc::new(Mutex::new(HashMap::new())),
            listen_addr,
            health_listen_addr,
            tls: None,
            metrics: EdgeMetrics::new(),
        }
    }

    pub fn with_tls(mut self, cert_store: CertStore, acme: Option<Arc<AcmeCoordinator>>) -> Self {
        let server_config = cert_store.server_config();
        self.tls = Some(TlsState {
            server_config,
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

        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!(listen = %self.listen_addr, tls = self.tls.is_some(), "edge listening");

        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("TCP accept error: {e}");
                    continue;
                }
            };
            debug!(%peer_addr, "accepted TCP connection");

            let ctx = ConnCtx {
                router: Arc::clone(&self.router),
                endpoint: Arc::clone(&self.endpoint),
                pool: Arc::clone(&self.agent_pool),
                health: Arc::clone(&self.agent_health),
                metrics: self.metrics.clone(),
                tls_acceptor: self
                    .tls
                    .as_ref()
                    .map(|t| tokio_rustls::TlsAcceptor::from(Arc::clone(&t.server_config))),
                cert_store: self.tls.as_ref().map(|t| t.cert_store.clone()),
                acme: self.tls.as_ref().and_then(|t| t.acme.clone()),
            };

            tokio::spawn(async move {
                if let Err(e) = handle_connection(tcp_stream, peer_addr, ctx).await {
                    debug!(%peer_addr, error = %e, "connection handling failed");
                }
            });
        }
    }
}

/// Per-connection context shared between the dispatch paths.
#[derive(Clone)]
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
    ctx: ConnCtx,
) -> anyhow::Result<()> {
    ctx.metrics.total_connections.inc();
    ctx.metrics.active_connections.inc();

    let result = handle_connection_inner(tcp_stream, peer_addr, &ctx).await;

    ctx.metrics.active_connections.dec();

    if let Err(ref e) = result {
        debug!(%peer_addr, error = %e, "connection ended with error");
    }

    result
}

async fn get_health(health: &AgentHealthMap, id: iroh::EndpointId) -> Arc<AgentHealthState> {
    let mut map = health.lock().await;
    map.entry(id)
        .or_insert_with(|| Arc::new(AgentHealthState::new()))
        .clone()
}

async fn handle_connection_inner(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ctx: &ConnCtx,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let mut peek_buf = vec![0u8; PEEK_BUF_SIZE];
    let n = tcp_stream.peek(&mut peek_buf).await?;

    let hostname = extract_sni(&peek_buf[..n])
        .ok_or_else(|| anyhow::anyhow!("no SNI found in ClientHello"))?;

    debug!(%hostname, "extracted SNI");

    let mut agents = ctx
        .router
        .lookup(&hostname)
        .await
        .ok_or_else(|| anyhow::anyhow!("no route for hostname: {hostname}"))?;

    {
        let mut scored: Vec<(EndpointAddr, (u32, u64))> = Vec::with_capacity(agents.len());
        for addr in agents.drain(..) {
            let h = get_health(&ctx.health, addr.id).await;
            scored.push((addr, h.score()));
        }
        scored.sort_by_key(|(_, score)| *score);
        agents = scored.into_iter().map(|(addr, _)| addr).collect();
    }

    if agents.is_empty() {
        anyhow::bail!("agent list empty for hostname: {hostname}");
    }

    let policy = ctx.router.tls_policy(&hostname).await;

    let mut last_err: Option<anyhow::Error> = None;
    let mut chosen: Option<(
        EndpointAddr,
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
    )> = None;

    for agent_addr in agents {
        let agent_health_state = get_health(&ctx.health, agent_addr.id).await;
        match open_agent_stream(&ctx.endpoint, &ctx.pool, agent_addr.clone()).await {
            Ok((send, recv)) => {
                agent_health_state.record_success();
                chosen = Some((agent_addr, send, recv));
                break;
            }
            Err(e) => {
                agent_health_state.record_failure();
                debug!(
                    agent = %agent_addr.id.fmt_short(),
                    error = %e,
                    "agent stream open failed, trying next"
                );
                last_err = Some(e);
            }
        }
    }

    let (agent_addr, send_stream_chosen, recv_stream_chosen) =
        chosen.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("all agents failed")))?;

    let agent_id = agent_addr.id;

    let span = info_span!("conn",
        %hostname,
        peer = %peer_addr,
        agent = %agent_id.fmt_short(),
        mode = tls_mode_label(&policy),
    );

    async {
        let (send_stream, recv_stream) = (send_stream_chosen, recv_stream_chosen);

        let (bytes_in, bytes_out) = match policy {
            TlsMode::Passthrough => {
                pipe_passthrough(tcp_stream, &hostname, send_stream, recv_stream).await?
            }
            TlsMode::Terminate => {
                pipe_terminate(tcp_stream, &hostname, send_stream, recv_stream, ctx).await?
            }
        };

        ctx.metrics.total_bytes_in.inc_by(bytes_in);
        ctx.metrics.total_bytes_out.inc_by(bytes_out);

        info!(
            bytes_in,
            bytes_out,
            duration_ms = start.elapsed().as_millis() as u64,
            "connection closed"
        );
        Ok(())
    }
    .instrument(span)
    .await
}

fn tls_mode_label(mode: &TlsMode) -> &'static str {
    match mode {
        TlsMode::Passthrough => "passthrough",
        TlsMode::Terminate => "terminate",
    }
}

async fn pipe_passthrough(
    tcp_stream: TcpStream,
    hostname: &str,
    mut send_stream: iroh::endpoint::SendStream,
    mut recv_stream: iroh::endpoint::RecvStream,
) -> anyhow::Result<(u64, u64)> {
    write_hostname_header(&mut send_stream, hostname).await?;

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let c2a = async {
        let res = tokio::io::copy(&mut tcp_read, &mut send_stream).await;
        let _ = send_stream.finish();
        res
    };
    let a2c = async {
        let res = tokio::io::copy(&mut recv_stream, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
        res
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a.unwrap_or(0), a2c.unwrap_or(0)))
}

async fn pipe_terminate(
    tcp_stream: TcpStream,
    hostname: &str,
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

    if !cert_store.has_cert(hostname).await {
        match &ctx.acme {
            Some(acme) => acme.ensure_cert(hostname).await?,
            None => anyhow::bail!("no cert for {hostname} and ACME disabled"),
        }
    }

    let tls_stream = acceptor.accept(tcp_stream).await?;
    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    debug!(%hostname, "TLS terminated");
    write_hostname_header(&mut send_stream, hostname).await?;

    let c2a = async {
        let res = tokio::io::copy(&mut tls_read, &mut send_stream).await;
        let _ = send_stream.finish();
        res
    };
    let a2c = async {
        let res = tokio::io::copy(&mut recv_stream, &mut tls_write).await;
        let _ = tls_write.shutdown().await;
        res
    };

    let (c2a, a2c) = tokio::join!(c2a, a2c);
    Ok((c2a.unwrap_or(0), a2c.unwrap_or(0)))
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

    let cached = pool.lock().await.get(&agent_id).cloned();
    if let Some(conn) = cached {
        match conn.open_bi().await {
            Ok(pair) => return Ok(pair),
            Err(e) => {
                debug!(
                    agent = %agent_id.fmt_short(),
                    error = %e,
                    "pooled connection broken, reconnecting"
                );
                pool.lock().await.remove(&agent_id);
            }
        }
    }

    info!(agent = %agent_id.fmt_short(), "connecting to agent");
    let conn = endpoint.connect(agent_addr, ALPN_TUNNEL).await?;
    let pair = conn.open_bi().await?;
    pool.lock().await.insert(agent_id, conn);
    Ok(pair)
}
