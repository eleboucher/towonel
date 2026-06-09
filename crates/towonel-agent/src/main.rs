mod config;
mod edge_session;
mod hub_client;
mod k8s_autodiscover;
mod metrics;
mod publish_tls;
mod retry;
mod stateless;
mod tunnel;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use clap::Parser;
use iroh::{
    Endpoint, EndpointAddr, RelayMode,
    address_lookup::MemoryLookup,
    endpoint::{PortmapperConfig, presets::Minimal},
};
use prometheus::{Encoder, TextEncoder};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::metrics::AgentMetrics;

#[derive(Parser)]
#[command(
    name = "towonel-agent",
    about = "towonel agent -- runs in your network, tunnels traffic from edges. Services come from TOWONEL_AGENT_SERVICES; identity from TOWONEL_INVITE_TOKEN."
)]
struct Cli {
    /// Write the iroh `EndpointId` (hex) to this path once the endpoint is bound.
    #[arg(long)]
    node_id_out: Option<PathBuf>,

    /// Write the agent's bound socket addresses (one per line) to this path.
    #[arg(long)]
    addr_out: Option<PathBuf>,

    /// Listen address for the built-in HTTP server exposing `GET /healthz`
    /// and `GET /metrics`. Defaults to loopback so metrics are not exposed to
    /// the LAN under `--network host`. Set `0.0.0.0:9090` (or pass
    /// `TOWONEL_AGENT_HEALTH_LISTEN_ADDR`) to expose externally.
    #[arg(
        long,
        env = "TOWONEL_AGENT_HEALTH_LISTEN_ADDR",
        default_value = "127.0.0.1:9090"
    )]
    health_listen_addr: SocketAddr,
}

#[expect(
    clippy::large_futures,
    reason = "top-level main future is large; boxing it provides no benefit"
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ring provider install only fails if another provider is already installed,
    // which is a programming error and should panic at startup.
    #[expect(
        clippy::expect_used,
        reason = "duplicate CryptoProvider install is a startup-time programmer error"
    )]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring CryptoProvider");

    let _telemetry = towonel_common::telemetry::init("towonel-agent", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();
    run_agent(cli).await
}

/// How often the agent re-queries the hub for the current trusted-edge set.
const TOPOLOGY_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
/// Base delay between agent-lifecycle attempts (bring-up + serve). A hub that
/// stays unreachable escalates this up to [`LIFECYCLE_MAX_DELAY`].
const LIFECYCLE_BASE_DELAY: Duration = Duration::from_secs(10);
/// Cap on the lifecycle restart backoff under a sustained outage.
const LIFECYCLE_MAX_DELAY: Duration = Duration::from_mins(1);
/// After the agent has been connected, losing all edge sessions for this long
/// means the iroh endpoint is likely wedged (a prolonged WAN outage can leave
/// magicsock unable to recover on the same endpoint). Serve returns so the
/// lifecycle supervisor rebuilds with a fresh endpoint.
const NO_SESSION_REBUILD_TIMEOUT: Duration = Duration::from_mins(5);

/// Bound on the graceful endpoint close at shutdown so a stuck close can't hang
/// process exit past the orchestrator's grace period.
const ENDPOINT_CLOSE_TIMEOUT: Duration = Duration::from_secs(3);

/// A live agent: stable endpoint + supervisor pool, built once and kept for the
/// process lifetime (no identity churn after the first successful bring-up).
struct BroughtUp {
    ctx: Arc<stateless::BootstrapContext>,
    endpoint: Endpoint,
    cred_refresh: tokio::task::JoinHandle<()>,
    pool: edge_session::SupervisorPool,
}

#[expect(
    clippy::large_futures,
    reason = "top-level orchestration future is large; boxing it provides no benefit"
)]
async fn run_agent(cli: Cli) -> anyhow::Result<()> {
    let metrics = Arc::new(AgentMetrics::new());
    metrics.set_info(env!("CARGO_PKG_VERSION"));

    let token = stateless::token_from_env()?;
    let agent_config = config::AgentConfig::load()?;

    // Derived from static env config, not the hub: built once for the process.
    let service_map = Arc::new(
        tunnel::ServiceMap::from_config(
            &agent_config.services,
            &agent_config.tcp_services,
            &agent_config.udp_services,
        )
        .await?,
    );
    service_map.spawn_dns_refresher();

    let desired_tcp_bindings: Vec<(String, u16)> = agent_config
        .tcp_services
        .iter()
        .map(|s| (s.name.clone(), s.listen_port))
        .collect();
    let desired_udp_bindings: Vec<(String, u16)> = agent_config
        .udp_services
        .iter()
        .map(|s| (s.name.clone(), s.listen_port))
        .collect();

    let health_handle = tokio::spawn(serve_http(cli.health_listen_addr, metrics.clone()));

    // Fired on SIGINT/SIGTERM; supervisors are child tokens of it.
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            towonel_common::shutdown::shutdown_signal().await;
            shutdown.cancel();
        }
    });

    // The whole lifecycle — bring up a fresh endpoint, serve, tear down — is one
    // supervised activity: serve returning (wedged endpoint) or bring-up failing
    // (hub unreachable) both restart it, rebuilding from scratch.
    // Holds the current lifecycle's endpoint so shutdown can close it even if
    // the lifecycle future is dropped mid-serve by the supervisor.
    let shutdown_endpoint: Arc<tokio::sync::Mutex<Option<Endpoint>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    retry::supervise(
        "agent-lifecycle",
        &shutdown,
        LIFECYCLE_BASE_DELAY,
        LIFECYCLE_MAX_DELAY,
        || {
            run_lifecycle(
                &cli,
                &token,
                &agent_config,
                &service_map,
                &metrics,
                &desired_tcp_bindings,
                &desired_udp_bindings,
                &shutdown,
                &shutdown_endpoint,
            )
        },
    )
    .await;

    // Graceful close on shutdown: if the lifecycle tore itself down cleanly this
    // is a no-op (close is idempotent); if it was cancelled mid-serve, this is
    // what flushes CONNECTION_CLOSE to the edges.
    let endpoint = shutdown_endpoint.lock().await.take();
    if let Some(endpoint) = endpoint
        && tokio::time::timeout(ENDPOINT_CLOSE_TIMEOUT, endpoint.close())
            .await
            .is_err()
    {
        warn!("endpoint close timed out during shutdown");
    }

    health_handle.abort();
    info!("towonel-agent stopped");
    Ok(())
}

/// One full pass of the agent lifecycle: bring up a fresh iroh endpoint, serve
/// until shutdown or the endpoint goes dark, then tear everything down. Returns
/// `Ok(())` on graceful shutdown and `Err` when the caller should rebuild (hub
/// unreachable at bring-up, or no edge sessions for too long).
#[expect(
    clippy::too_many_arguments,
    reason = "process-wide state passed by ref to the supervised lifecycle"
)]
#[expect(
    clippy::large_futures,
    reason = "lifecycle future is large; boxing it provides no benefit"
)]
async fn run_lifecycle(
    cli: &Cli,
    token: &str,
    agent_config: &config::AgentConfig,
    service_map: &Arc<tunnel::ServiceMap>,
    metrics: &Arc<AgentMetrics>,
    desired_tcp_bindings: &[(String, u16)],
    desired_udp_bindings: &[(String, u16)],
    shutdown: &CancellationToken,
    shutdown_endpoint: &Arc<tokio::sync::Mutex<Option<Endpoint>>>,
) -> anyhow::Result<()> {
    let BroughtUp {
        ctx,
        endpoint,
        cred_refresh,
        mut pool,
    } = try_bring_up(
        cli,
        token,
        agent_config,
        service_map,
        metrics,
        desired_tcp_bindings,
        desired_udp_bindings,
        shutdown,
    )
    .await?;

    // Stash the live endpoint so a SIGTERM that cancels this future mid-serve
    // (dropping it before the teardown below) can still close it from
    // `run_agent`, sending CONNECTION_CLOSE instead of leaving edges to route
    // to a dead agent until QUIC idle timeout.
    *shutdown_endpoint.lock().await = Some(endpoint.clone());

    info!(
        interval_secs = TOPOLOGY_REFRESH_INTERVAL.as_secs(),
        "agent up; serving"
    );
    let outcome = serve(token, &ctx, &mut pool, metrics, shutdown).await;

    // Always tear down before returning: the next lifecycle attempt binds a new
    // endpoint, and a fixed iroh port would clash with a leaked one.
    pool.shutdown().await;
    cred_refresh.abort();
    endpoint.close().await;
    outcome
}

/// Steady state: poll the hub and reconcile the supervisor pool, and watch for
/// the agent going dark. Returns `Ok(())` on shutdown, or `Err` once the agent
/// has had zero edge sessions for [`NO_SESSION_REBUILD_TIMEOUT`] after having
/// been connected — the signal that the endpoint is wedged and must be rebuilt.
async fn serve(
    token: &str,
    ctx: &stateless::BootstrapContext,
    pool: &mut edge_session::SupervisorPool,
    metrics: &AgentMetrics,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    // Arms only after the first session, so an agent still waiting for edges to
    // come online is never torn down — only a regression from connected to dark.
    let mut armed = false;
    let mut dark_since: Option<Instant> = None;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(TOPOLOGY_REFRESH_INTERVAL) => {
                match stateless::refresh_edge_contacts(token, ctx).await {
                    Ok(contacts) => pool.reconcile(&contacts),
                    Err(e) => warn!(error = %e, "topology refresh failed; keeping current edge set"),
                }

                if metrics.active_edge_sessions() > 0 {
                    armed = true;
                    dark_since = None;
                } else if armed {
                    let since = *dark_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= NO_SESSION_REBUILD_TIMEOUT {
                        return Err(anyhow!(
                            "no edge sessions for {}s after being connected; rebuilding endpoint",
                            since.elapsed().as_secs()
                        ));
                    }
                }
            }
        }
    }
}

/// Bootstrap, bind the iroh endpoint, register, publish, and start a supervisor
/// pool reconciled to the initial edge set. `Err` if the agent can't be brought
/// up (hub unreachable, registration rejected) — the caller retries.
#[expect(
    clippy::too_many_lines,
    reason = "boot sequence is intentionally linear so the order of operations is auditable"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "process-wide state passed by ref"
)]
#[expect(
    clippy::large_futures,
    reason = "boot sequence future is large; boxing it provides no benefit"
)]
async fn try_bring_up(
    cli: &Cli,
    token: &str,
    agent_config: &config::AgentConfig,
    service_map: &Arc<tunnel::ServiceMap>,
    metrics: &Arc<AgentMetrics>,
    desired_tcp_bindings: &[(String, u16)],
    desired_udp_bindings: &[(String, u16)],
    shutdown: &CancellationToken,
) -> anyhow::Result<BroughtUp> {
    let ctx = Arc::new(stateless::bootstrap(token).await?);

    // Env override wins over the hub-advertised relay; either may be absent.
    let (relay_url_str, relay_source) = std::env::var("TOWONEL_AGENT_RELAY_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map_or_else(
            || (ctx.relay_url.clone(), "hub bootstrap"),
            |url| (Some(url), "TOWONEL_AGENT_RELAY_URL"),
        );
    let relay_mode = relay_url_str.as_deref().map_or(RelayMode::Disabled, |url| {
        towonel_common::relay::relay_mode_from_url(url, relay_source)
    });
    // Attached to each edge's EndpointAddr as relay fallback paths.
    let relay_urls = relay_url_str
        .as_deref()
        .map(|url| towonel_common::relay::relay_urls_from_str(url, relay_source))
        .unwrap_or_default();

    if relay_urls.is_empty() && ctx.edge_contacts.iter().all(|c| c.addrs.is_empty()) {
        warn!(
            "no edge advertised an iroh address and no relay is configured; waiting for \
             an edge to come online. Set TOWONEL_EDGE_IROH_PORT on the hub so it can \
             advertise a reachable endpoint, or configure a relay."
        );
    }
    // Seed an empty lookup with the known edge ids so iroh's RemoteStateActor
    // doesn't warn "No address lookup configured" — addrs come from connect().
    let edge_lookup = MemoryLookup::new();
    for contact in &ctx.edge_contacts {
        edge_lookup.add_endpoint_info(EndpointAddr::new(contact.id));
    }

    let mut endpoint_builder = Endpoint::builder(Minimal)
        .secret_key(ctx.iroh_secret_key())
        .relay_mode(relay_mode)
        .ca_roots_config(iroh::tls::CaRootsConfig::insecure_skip_verify())
        .address_lookup(edge_lookup)
        .portmapper_config(PortmapperConfig::Disabled);
    let iroh_port: u16 = match std::env::var("TOWONEL_AGENT_IROH_PORT") {
        Ok(v) => v
            .parse()
            .with_context(|| format!("TOWONEL_AGENT_IROH_PORT must be a u16, got {v:?}"))?,
        Err(_) => 0,
    };
    if iroh_port != 0 {
        endpoint_builder = endpoint_builder
            .clear_ip_transports()
            .bind_addr(format!("0.0.0.0:{iroh_port}"))
            .map_err(|e| anyhow::anyhow!("invalid IPv4 iroh bind addr: {e}"))?
            .bind_addr(format!("[::]:{iroh_port}"))
            .map_err(|e| anyhow::anyhow!("invalid IPv6 iroh bind addr: {e}"))?;
    }
    for addr in towonel_common::relay::parse_extra_local_addrs("TOWONEL_AGENT_EXTRA_LOCAL_ADDRS") {
        info!(%addr, "advertising extra local address from env");
        endpoint_builder = endpoint_builder.external_addr(addr);
    }
    for addr in k8s_autodiscover::discover().await {
        info!(%addr, "advertising k8s-discovered address");
        endpoint_builder = endpoint_builder.external_addr(addr);
    }
    let endpoint = endpoint_builder
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let node_id = endpoint.id();
    info!(%node_id, "agent iroh endpoint ready");

    let bound_sockets = endpoint.bound_sockets();
    for addr in &bound_sockets {
        info!(addr = %addr, "agent listening on");
    }

    // Out-files, register, and publish run once. On failure the caller retries
    // the whole bring-up, so close the endpoint first to avoid leaking it.
    let setup = async {
        if let Some(path) = cli.node_id_out.as_ref() {
            write_atomic(path, node_id.to_string().as_bytes())
                .with_context(|| format!("failed to write node id to {}", path.display()))?;
        }
        if let Some(path) = cli.addr_out.as_ref() {
            let joined = bound_sockets
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            write_atomic(path, joined.as_bytes())
                .with_context(|| format!("failed to write addresses to {}", path.display()))?;
        }
        stateless::register(&ctx).await?;
        stateless::publish_hostnames(&ctx).await?;
        stateless::publish_tcp_services(&ctx, desired_tcp_bindings).await?;
        stateless::publish_udp_services(&ctx, desired_udp_bindings).await?;
        anyhow::Ok(())
    };
    if let Err(e) = setup.await {
        endpoint.close().await;
        return Err(e);
    }

    if ctx.trusted_edges.is_empty() {
        warn!("no trusted edges yet; the topology-refresh loop will dial them once provisioned");
    }

    if !agent_config.services.is_empty() {
        let result = publish_tls::publish(
            &ctx.client,
            &ctx.hub_url,
            &ctx.tenant_kp,
            &agent_config.services,
        )
        .await;
        if let Err(e) = result {
            warn!(error = %e, "TLS policy publish failed; edge will use passthrough defaults");
        }
    }

    let cred_refresh = stateless::spawn_edge_cred_refresh(ctx.clone());

    let mut pool = edge_session::SupervisorPool::new(
        &endpoint,
        service_map,
        metrics,
        &ctx.edge_cred,
        relay_urls,
        shutdown,
    );
    info!(edges = ctx.edge_contacts.len(), "starting edge supervisors");
    pool.reconcile(&ctx.edge_contacts);

    Ok(BroughtUp {
        ctx,
        endpoint,
        cred_refresh,
        pool,
    })
}

async fn serve_http(addr: SocketAddr, metrics: Arc<AgentMetrics>) {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(%addr, error = %e, "failed to bind health listener");
            return;
        }
    };
    info!(%addr, "health + metrics listening");
    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "health server error");
    }
}

async fn readyz_handler(State(metrics): State<Arc<AgentMetrics>>) -> Response {
    // The agent is "ready" once at least one edge session is established.
    // K8s rolling deploys use this to delay traffic on the next pod until
    // the QUIC tunnel is actually up.
    if metrics.active_edge_sessions() > 0 {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no active edge sessions").into_response()
    }
}

async fn metrics_handler(State(metrics): State<Arc<AgentMetrics>>) -> Response {
    let mut buf = Vec::new();
    if let Err(e) = TextEncoder::new().encode(&metrics.registry().gather(), &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encoding failed: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buf,
    )
        .into_response()
}

/// Write `data` to `path` atomically: write to a PID-tagged temp file, then
/// rename. Readers polling for a non-empty file never observe a partial write.
fn write_atomic(path: &std::path::Path, data: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_file_name(format!(
        "{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("out"),
        std::process::id(),
    ));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
