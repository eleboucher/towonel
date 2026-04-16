pub mod health;
pub mod router;
pub mod subscribe;

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
use turbo_common::tunnel::write_hostname_header;

use self::health::EdgeMetrics;
use self::router::Router;

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

/// The edge: listens on a TCP port, extracts SNI from TLS ClientHello, routes
/// to the correct agent via an iroh QUIC stream, and does bidirectional copy.
/// The edge never holds TLS private keys.
pub struct Edge {
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    agent_pool: Arc<AgentPool>,
    agent_health: Arc<AgentHealthMap>,
    listen_addr: String,
    health_listen_addr: String,
    metrics: EdgeMetrics,
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
            metrics: EdgeMetrics::new(),
        }
    }

    /// Run the edge. Binds a TCP listener, starts the health/metrics HTTP
    /// server, and spawns a task per TCP connection.
    ///
    /// The edge endpoint is outbound-only -- it does not accept incoming iroh
    /// connections, so no incoming guard is needed.
    pub async fn run(&self) -> anyhow::Result<()> {
        let health_app = health::router(self.metrics.clone());
        let health_listener = TcpListener::bind(&self.health_listen_addr).await?;
        info!(listen = %self.health_listen_addr, "edge health server listening");
        tokio::spawn(async move {
            axum::serve(health_listener, health_app).await.ok();
        });

        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!(listen = %self.listen_addr, "edge listening (TLS passthrough mode)");

        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("TCP accept error: {e}");
                    continue;
                }
            };
            debug!(%peer_addr, "accepted TCP connection");

            let router = Arc::clone(&self.router);
            let endpoint = Arc::clone(&self.endpoint);
            let pool = Arc::clone(&self.agent_pool);
            let health = Arc::clone(&self.agent_health);
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    tcp_stream, peer_addr, router, endpoint, pool, health, metrics,
                )
                .await
                {
                    debug!(%peer_addr, error = %e, "connection handling failed");
                }
            });
        }
    }
}

/// Handle a single incoming TCP connection: peek SNI, route, tunnel.
async fn handle_connection(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    pool: Arc<AgentPool>,
    health: Arc<AgentHealthMap>,
    metrics: EdgeMetrics,
) -> anyhow::Result<()> {
    metrics.total_connections.inc();
    metrics.active_connections.inc();

    let result = handle_connection_inner(
        tcp_stream, peer_addr, router, endpoint, pool, health, &metrics,
    )
    .await;

    metrics.active_connections.dec();

    if let Err(ref e) = result {
        debug!(%peer_addr, error = %e, "connection ended with error");
    }

    result
}

/// Get or create the health state for an agent.
async fn get_health(health: &AgentHealthMap, id: iroh::EndpointId) -> Arc<AgentHealthState> {
    let mut map = health.lock().await;
    map.entry(id)
        .or_insert_with(|| Arc::new(AgentHealthState::new()))
        .clone()
}

/// Inner logic for a single connection, separated so that the caller can
/// reliably decrement `active_connections` regardless of the outcome.
async fn handle_connection_inner(
    tcp_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    router: Arc<Router>,
    endpoint: Arc<Endpoint>,
    pool: Arc<AgentPool>,
    health: Arc<AgentHealthMap>,
    metrics: &EdgeMetrics,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let mut peek_buf = vec![0u8; PEEK_BUF_SIZE];
    let n = tcp_stream.peek(&mut peek_buf).await?;

    let hostname = extract_sni(&peek_buf[..n])
        .ok_or_else(|| anyhow::anyhow!("no SNI found in ClientHello"))?;

    debug!(%hostname, "extracted SNI");

    let mut agents = router
        .lookup(&hostname)
        .await
        .ok_or_else(|| anyhow::anyhow!("no route for hostname: {hostname}"))?;

    if agents.len() > 1 {
        let mut scored: Vec<(EndpointAddr, (u32, u64))> = Vec::with_capacity(agents.len());
        for addr in agents.drain(..) {
            let h = get_health(&health, addr.id).await;
            scored.push((addr, h.score()));
        }
        scored.sort_by_key(|(_, score)| *score);
        agents = scored.into_iter().map(|(addr, _)| addr).collect();
    }

    let agent_addr = agents
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("agent list empty for hostname: {hostname}"))?;

    let agent_id = agent_addr.id;

    let span = info_span!("conn",
        %hostname,
        peer = %peer_addr,
        agent = %agent_id.fmt_short(),
    );

    let agent_health_state = get_health(&health, agent_id).await;

    async {
        let stream_result = open_agent_stream(&endpoint, &pool, agent_addr).await;
        let (mut send_stream, mut recv_stream) = match stream_result {
            Ok(pair) => {
                agent_health_state.record_success();
                pair
            }
            Err(e) => {
                agent_health_state.record_failure();
                return Err(e);
            }
        };

        write_hostname_header(&mut send_stream, &hostname).await?;

        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        let client_to_agent = async {
            let res = tokio::io::copy(&mut tcp_read, &mut send_stream).await;
            let _ = send_stream.finish(); // signal EOF to agent
            res
        };

        let agent_to_client = async {
            let res = tokio::io::copy(&mut recv_stream, &mut tcp_write).await;
            let _ = tcp_write.shutdown().await; // graceful TCP close
            res
        };

        let (c2a, a2c) = tokio::join!(client_to_agent, agent_to_client);
        let bytes_in = c2a.as_ref().copied().unwrap_or(0);
        let bytes_out = a2c.as_ref().copied().unwrap_or(0);

        if let Err(e) = &c2a {
            debug!("client->agent: {e}");
        }
        if let Err(e) = &a2c {
            debug!("agent->client: {e}");
        }

        metrics.total_bytes_in.inc_by(bytes_in);
        metrics.total_bytes_out.inc_by(bytes_out);

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
