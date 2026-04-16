mod add_agent;
mod config;
mod init;
mod tunnel;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::{Endpoint, EndpointId};
use tracing::{error, info, warn};
use turbo_common::client_state::{ClientState, DefaultPaths};
use turbo_common::protocol::ALPN_TUNNEL;

#[derive(Parser)]
#[command(
    name = "turbo-agent",
    about = "turbo-tunnel agent -- runs in your network, tunnels traffic from edges"
)]
struct Cli {
    /// Path to the agent config file. Defaults to `./agent.toml`, then
    /// `~/.turbo-tunnel/agent.toml`, then an empty in-memory config.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Write the iroh EndpointId (hex) to this path once the endpoint is bound.
    /// Intended for orchestration (docker-compose, systemd, scripts) that need
    /// to learn the agent's identity without scraping logs.
    #[arg(long)]
    node_id_out: Option<PathBuf>,

    /// Write the agent's bound socket addresses (one per line) to this path
    /// once the endpoint is bound. Used by orchestrators that need to point
    /// edges directly at the agent when relay discovery is unavailable.
    #[arg(long)]
    addr_out: Option<PathBuf>,

    /// INSECURE. Accept iroh connections from any peer, not just those in
    /// `trusted_edges`. For local testing and e2e only. Production deployments
    /// MUST NOT set this (protocol §6.2).
    #[arg(long, default_value_t = false)]
    allow_any_edge: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a new tenant identity by redeeming an invite token.
    /// Generates keys, submits initial config entries, and writes
    /// `~/.turbo-tunnel/state.toml` + `~/.turbo-tunnel/agent.toml`.
    Init {
        /// The invite token handed out by the operator (`tt_inv_1_...`).
        #[arg(long)]
        invite: String,

        /// Where to write the agent config. Defaults to
        /// `~/.turbo-tunnel/agent.toml`.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Authorize a new agent for an existing tenant (user-stories §4).
    /// The tenant's signing key must already exist at `--tenant-key` --
    /// copy it from your first machine over a trusted channel first.
    AddAgent {
        /// Path to the tenant signing key (32-byte Ed25519 seed).
        #[arg(long)]
        tenant_key: PathBuf,

        /// Hub URL (same as your existing agent's hub).
        #[arg(long)]
        hub: String,

        /// Where to save the new agent key. Defaults to
        /// `~/.turbo-tunnel/agent.key`. Fails if the file already exists
        /// so you don't clobber the first agent's identity.
        #[arg(long)]
        agent_key: Option<PathBuf>,

        /// Where to write the new agent config. Defaults to
        /// `~/.turbo-tunnel/agent.toml`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init { invite, out }) => {
            return init::run(&invite, out.as_deref()).await;
        }
        Some(Command::AddAgent {
            ref tenant_key,
            ref hub,
            ref agent_key,
            ref out,
        }) => {
            return add_agent::run(tenant_key, agent_key.as_deref(), hub, out.as_deref()).await;
        }
        None => {}
    }

    run_agent(cli).await
}

async fn run_agent(cli: Cli) -> anyhow::Result<()> {
    let defaults = DefaultPaths::from_env();

    let agent_config = match resolve_config_path(cli.config.as_deref(), &defaults) {
        Some(path) => {
            info!(path = %path.display(), "loading agent config");
            config::AgentConfig::load(&path)?
        }
        None => {
            info!("no agent config found, using state.toml + defaults");
            config::AgentConfig::default()
        }
    };

    let state = ClientState::load(&defaults.state_file).with_context(|| {
        format!(
            "failed to load state file {}",
            defaults.state_file.display()
        )
    })?;

    let resolved = agent_config.resolve(&state)?;

    info!(services = resolved.services.len(), "turbo-agent starting");

    let service_map = Arc::new(tunnel::ServiceMap::from_config(&resolved.services));

    let secret_key = turbo_common::identity::load_or_generate_secret_key(&resolved.key_path)
        .context("failed to load or generate agent identity key")?;
    info!(node_id = %secret_key.public(), "loaded agent identity");

    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN_TUNNEL.to_vec()])
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let node_id = endpoint.id();
    info!(%node_id, "agent iroh endpoint ready -- give this NodeId to your edge operator");

    let bound_sockets = endpoint.bound_sockets();
    for addr in &bound_sockets {
        info!(addr = %addr, "agent listening on");
    }

    if let Some(path) = cli.node_id_out.as_ref() {
        write_atomic(path, node_id.to_string().as_bytes())
            .with_context(|| format!("failed to write node id to {}", path.display()))?;
        info!(path = %path.display(), "wrote node id");
    }
    if let Some(path) = cli.addr_out.as_ref() {
        let joined = bound_sockets
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        write_atomic(path, joined.as_bytes())
            .with_context(|| format!("failed to write addresses to {}", path.display()))?;
        info!(path = %path.display(), "wrote bound addresses");
    }

    let trusted_edges: HashSet<EndpointId> = resolved
        .trusted_edges
        .iter()
        .filter_map(|s| {
            s.parse::<EndpointId>()
                .inspect_err(|e| warn!(%s, error = %e, "skipping invalid trusted_edges entry"))
                .ok()
        })
        .collect();

    if trusted_edges.is_empty() && !cli.allow_any_edge {
        anyhow::bail!(
            "no trusted_edges configured. Run `turbo-agent init --invite <token>` to \
             bootstrap, add entries manually to ~/.turbo-tunnel/state.toml, or pass \
             --allow-any-edge for local testing (NOT for production)."
        );
    }

    tokio::select! {
        res = tunnel::run(&endpoint, service_map, trusted_edges, cli.allow_any_edge) => {
            if let Err(e) = res {
                error!("tunnel error: {e}");
            }
        }
        _ = turbo_common::shutdown::shutdown_signal() => {}
    }

    endpoint.close().await;
    info!("turbo-agent stopped");
    Ok(())
}

/// Look up the agent config path: explicit --config, else ./agent.toml,
/// else ~/.turbo-tunnel/agent.toml, else None.
fn resolve_config_path(explicit: Option<&Path>, defaults: &DefaultPaths) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let cwd = PathBuf::from("agent.toml");
    if cwd.exists() {
        return Some(cwd);
    }
    if defaults.agent_config.exists() {
        return Some(defaults.agent_config.clone());
    }
    None
}

/// Write `data` to `path` atomically: write to a PID-tagged temp file, then
/// rename. Readers polling for a non-empty file never observe a partial write.
/// The PID suffix prevents collisions if two processes race on the same path.
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
