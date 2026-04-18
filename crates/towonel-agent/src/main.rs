mod config;
mod hub_client;
mod publish_tls;
mod stateless;
mod tunnel;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::routing::get;
use clap::Parser;
use iroh::{Endpoint, endpoint::presets::N0};
use towonel_common::protocol::ALPN_TUNNEL;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "towonel-agent",
    about = "towonel agent -- runs in your network, tunnels traffic from edges"
)]
struct Cli {
    /// Path to the agent config file. Defaults to `./agent.toml`. The
    /// config only carries service routing (hostname → origin); identity
    /// lives in `TOWONEL_INVITE_TOKEN`.
    #[arg(short, long)]
    config: Option<PathBuf>,

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

    /// Bind a minimal HTTP server on this port with `GET /healthz`.
    /// Useful for k8s liveness/readiness probes.
    #[arg(long)]
    health_port: Option<u16>,
}

#[allow(clippy::large_futures)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ring provider install only fails if another provider is already installed,
    // which is a programming error and should panic at startup.
    #[allow(clippy::expect_used)]
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

#[allow(clippy::large_futures)]
async fn run_agent(cli: Cli) -> anyhow::Result<()> {
    let token = stateless::token_from_env()?;
    let ctx = Arc::new(stateless::bootstrap(&token).await?);

    let agent_config = if let Some(path) = resolve_config_path(cli.config.as_deref()) {
        info!(path = %path.display(), "loading agent config");
        config::AgentConfig::load(&path)?
    } else {
        info!("no agent config found, using empty service list");
        config::AgentConfig::default()
    };

    let service_map = Arc::new(tunnel::ServiceMap::from_config(&agent_config.services).await);
    service_map.spawn_dns_refresher();

    let endpoint = Endpoint::builder(N0)
        .secret_key(ctx.iroh_secret_key())
        .alpns(vec![ALPN_TUNNEL.to_vec()])
        .bind()
        .await
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
    let heartbeat = stateless::spawn_heartbeat(ctx.clone());

    if !agent_config.services.is_empty() {
        #[allow(clippy::large_futures)]
        let result =
            publish_tls::publish(&ctx.hub_url, &ctx.tenant_kp, &agent_config.services).await;
        if let Err(e) = result {
            warn!(error = %e, "TLS policy publish failed; edge will use passthrough defaults");
        }
    }

    let allow_any = cli.allow_any_edge;
    let trusted_edges = ctx.trusted_edges.clone();

    let health_handle = cli
        .health_port
        .map(|port| tokio::spawn(serve_healthz(port)));

    tokio::select! {
        res = tunnel::run(&endpoint, service_map, trusted_edges, allow_any) => {
            if let Err(e) = res {
                error!("tunnel error: {e}");
            }
        }
        () = towonel_common::shutdown::shutdown_signal() => {}
    }

    heartbeat.abort();
    if let Some(h) = health_handle {
        h.abort();
    }
    endpoint.close().await;
    info!("towonel-agent stopped");
    Ok(())
}

/// Minimal HTTP server for health probes.
async fn serve_healthz(port: u16) {
    let app = Router::new().route("/healthz", get(|| async { "ok" }));
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port, error = %e, "failed to bind healthz listener");
            return;
        }
    };
    info!(port, "healthz listening");
    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "healthz server error");
    }
}

/// Look up the agent config path: explicit --config, else ./agent.toml, else None.
fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let cwd = PathBuf::from("agent.toml");
    if cwd.exists() { Some(cwd) } else { None }
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
