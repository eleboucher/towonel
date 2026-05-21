mod config;
mod edge_session;
mod hub_client;
mod metrics;
mod publish_tls;
mod stateless;
mod tunnel;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use clap::Parser;
use iroh::{
    Endpoint, RelayMode,
    endpoint::presets::{Minimal, N0},
};
use prometheus::{Encoder, TextEncoder};
use tokio_util::sync::CancellationToken;
use towonel_common::protocol::ALPN_TUNNEL;
use tracing::{error, info, warn};

/// Truthy values switch the agent to reverse-dial mode (dials each
/// trusted edge instead of accepting); disables relay since the edge is
/// publicly addressable.
const DIAL_EDGE_ENV: &str = "TOWONEL_AGENT_DIAL_EDGE";

fn dial_edge_enabled() -> bool {
    std::env::var(DIAL_EDGE_ENV).is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
}

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

    /// INSECURE. Accept iroh connections from any peer, not just those in
    /// `trusted_edges`. For local testing and e2e only.
    #[arg(long, default_value_t = false)]
    allow_any_edge: bool,

    /// Port for the built-in HTTP server exposing `GET /healthz` and
    /// `GET /metrics`. Used by k8s liveness/readiness probes.
    #[arg(long, default_value_t = 9090)]
    health_port: u16,
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

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    run_agent(cli).await
}

#[expect(
    clippy::large_futures,
    reason = "top-level orchestration future is large; boxing it provides no benefit"
)]
#[expect(
    clippy::too_many_lines,
    reason = "boot sequence is intentionally linear so the order of operations is auditable"
)]
async fn run_agent(cli: Cli) -> anyhow::Result<()> {
    let metrics = Arc::new(AgentMetrics::new());
    metrics.set_info(env!("CARGO_PKG_VERSION"));

    let token = stateless::token_from_env()?;
    let ctx = Arc::new(stateless::bootstrap(&token).await?);

    let agent_config = config::AgentConfig::load()?;

    let service_map = Arc::new(
        tunnel::ServiceMap::from_config(
            &agent_config.services,
            &agent_config.tcp_services,
            &agent_config.udp_services,
        )
        .await?,
    );
    service_map.spawn_dns_refresher();

    let dial_edge = dial_edge_enabled() && ctx.edge_contacts.iter().any(|c| !c.addrs.is_empty());
    if std::env::var(DIAL_EDGE_ENV).is_ok() && !dial_edge {
        warn!(
            "{DIAL_EDGE_ENV} set but no edge has advertised addresses; falling back to accept-mode"
        );
    }

    let endpoint = if dial_edge {
        Endpoint::builder(Minimal)
            .secret_key(ctx.iroh_secret_key())
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
    } else {
        Endpoint::builder(N0)
            .secret_key(ctx.iroh_secret_key())
            .alpns(vec![ALPN_TUNNEL.to_vec()])
            .relay_mode(towonel_common::relay::relay_mode_from_env()?)
            .bind()
            .await
    }
    .context("failed to create iroh endpoint")?;

    let node_id = endpoint.id();
    info!(%node_id, "agent iroh endpoint ready");

    let bound_sockets = endpoint.bound_sockets();
    for addr in &bound_sockets {
        info!(addr = %addr, "agent listening on");
    }

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

    if ctx.trusted_edges.is_empty() && !cli.allow_any_edge {
        anyhow::bail!(
            "no trusted edges available. Provision an edge (`towonel-cli edge-invite ...`) or \
             pass --allow-any-edge for local testing (NOT for production)."
        );
    }

    stateless::register(&ctx).await?;
    stateless::publish_hostnames(&ctx).await?;
    let desired_tcp_bindings: Vec<(String, u16)> = agent_config
        .tcp_services
        .iter()
        .map(|s| (s.name.clone(), s.listen_port))
        .collect();
    stateless::publish_tcp_services(&ctx, &desired_tcp_bindings).await?;
    let desired_udp_bindings: Vec<(String, u16)> = agent_config
        .udp_services
        .iter()
        .map(|s| (s.name.clone(), s.listen_port))
        .collect();
    stateless::publish_udp_services(&ctx, &desired_udp_bindings).await?;
    stateless::reconcile_agents(&ctx).await?;
    let heartbeat = stateless::spawn_heartbeat(ctx.clone(), metrics.clone());

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

    let allow_any = cli.allow_any_edge;
    let trusted_edges = ctx.trusted_edges.clone();

    let health_handle = tokio::spawn(serve_http(cli.health_port, metrics.clone()));

    if dial_edge {
        info!(
            edges = ctx.edge_contacts.len(),
            "dial-edge mode active; spawning reverse-dial supervisors (relay disabled)"
        );
        let shutdown = CancellationToken::new();
        let mut supervisors = edge_session::spawn(
            &endpoint,
            &ctx.edge_contacts,
            &service_map,
            &metrics,
            &shutdown,
        );
        tokio::select! {
            () = towonel_common::shutdown::shutdown_signal() => {}
            // Supervisors retry forever; exit here is catastrophic — let
            // the container restart policy take over.
            r = supervisors.join_next() => {
                error!(?r, "edge supervisor exited unexpectedly; shutting down");
            }
        }
        shutdown.cancel();
        supervisors.shutdown().await;
        heartbeat.abort();
        health_handle.abort();
        endpoint.close().await;
        info!("towonel-agent stopped");
        return Ok(());
    }

    let relay_watchdog = towonel_common::relay_watchdog::spawn(endpoint.clone());

    tokio::select! {
        res = tunnel::run(&endpoint, service_map, trusted_edges, allow_any, metrics.clone()) => {
            if let Err(e) = res {
                error!("tunnel error: {e}");
            }
        }
        () = towonel_common::shutdown::shutdown_signal() => {}
    }

    heartbeat.abort();
    health_handle.abort();
    relay_watchdog.abort();
    endpoint.close().await;
    info!("towonel-agent stopped");
    Ok(())
}

async fn serve_http(port: u16, metrics: Arc<AgentMetrics>) {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port, error = %e, "failed to bind health listener");
            return;
        }
    };
    info!(port, "health + metrics listening");
    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "health server error");
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
