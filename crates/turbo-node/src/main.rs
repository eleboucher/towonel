mod config;
mod edge;
mod hub;
mod init;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::endpoint::Endpoint;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use turbo_common::identity::TenantId;
use turbo_common::ownership::OwnershipPolicy;
use turbo_common::routing::RouteTable;

use crate::edge::router::Router;
use crate::hub::HubIdentity;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "turbo-node",
    about = "turbo-tunnel node -- runs edge and/or hub on a VPS"
)]
struct Cli {
    /// Path to the node config file (ignored for subcommands).
    #[arg(short, long, default_value = "node.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap an edge node by redeeming an edge-invite token from the hub.
    /// Generates a node key, registers with the hub, and writes a starter
    /// `node.toml` for edge-only mode with the hub's URL for route
    /// subscription.
    Init {
        /// The edge-invite token from the operator (`tt_edge_1_...`).
        #[arg(long)]
        edge_invite: String,
        /// Where to write the generated node.toml.
        /// Defaults to `/etc/turbo-tunnel/node.toml`.
        #[arg(long)]
        config_out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    if let Some(Command::Init {
        edge_invite,
        config_out,
    }) = cli.command
    {
        return init::run(&edge_invite, config_out.as_deref()).await;
    }

    let config = config::NodeConfig::load(&cli.config)?;

    let secret_key = turbo_common::identity::load_or_generate_secret_key(&config.identity.key_path)
        .context("failed to load or generate node identity key")?;
    let node_id = secret_key.public();
    info!(%node_id, "loaded node identity");

    info!(
        hub = config.hub.enabled,
        edge = config.edge.enabled,
        tenants = config.tenants.len(),
        "turbo-node starting"
    );

    match (config.hub.enabled, config.edge.enabled) {
        (true, true) => {
            let policy = build_ownership_policy(&config.tenants)?;
            let operator_api_key =
                hub::load_or_generate_operator_key(&config.hub.operator_api_key_path)?;
            let public_url = default_public_url(&config.hub);
            let (route_tx, route_rx) = broadcast::channel::<RouteTable>(64);
            let hub_secret_key = iroh::SecretKey::from(secret_key.to_bytes());
            let (router, edge, edge_node_id, edge_addresses) =
                build_edge(secret_key, &config.tenants, &config.edge).await?;

            let public_addresses = if config.edge.public_addresses.is_empty() {
                edge_addresses
            } else {
                config.edge.public_addresses.clone()
            };

            let identity = HubIdentity {
                node_id: node_id.to_string(),
                edge_node_id: Some(edge_node_id),
                edge_addresses: public_addresses,
                software_version: SOFTWARE_VERSION,
            };
            let peer_urls: Vec<String> = config.hub.peers.iter().map(|p| p.url.clone()).collect();
            let hub = hub::Hub::new(hub::HubParams {
                listen_addr: config.hub.listen_addr.clone(),
                db_path: config.hub.db_path.clone(),
                route_tx,
                static_policy: policy,
                identity,
                operator_api_key,
                public_url,
                peer_urls,
                secret_key: hub_secret_key,
                dns_webhook_url: config.hub.dns_webhook_url.clone(),
            });

            tokio::spawn(route_sync_task(route_rx, router));

            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                res = edge.run() => {
                    if let Err(e) = res { error!("edge error: {e}"); }
                }
                _ = turbo_common::shutdown::shutdown_signal() => {}
            }
        }
        (true, false) => {
            let policy = build_ownership_policy(&config.tenants)?;
            let operator_api_key =
                hub::load_or_generate_operator_key(&config.hub.operator_api_key_path)?;
            let public_url = default_public_url(&config.hub);
            let (route_tx, _) = broadcast::channel::<RouteTable>(64);
            let identity = HubIdentity {
                node_id: node_id.to_string(),
                edge_node_id: None,
                edge_addresses: Vec::new(),
                software_version: SOFTWARE_VERSION,
            };
            let peer_urls: Vec<String> = config.hub.peers.iter().map(|p| p.url.clone()).collect();
            let hub = hub::Hub::new(hub::HubParams {
                listen_addr: config.hub.listen_addr.clone(),
                db_path: config.hub.db_path.clone(),
                route_tx,
                static_policy: policy,
                identity,
                operator_api_key,
                public_url,
                peer_urls,
                secret_key,
                dns_webhook_url: config.hub.dns_webhook_url.clone(),
            });
            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                _ = turbo_common::shutdown::shutdown_signal() => {}
            }
        }
        (false, true) => {
            let subscriber_key = iroh::SecretKey::from(secret_key.to_bytes());
            let (router, edge, _edge_node_id, _edge_addresses) =
                build_edge(secret_key, &config.tenants, &config.edge).await?;

            if let Some(hub_url) = config.edge.hub_url.clone() {
                let router_for_sub = Arc::clone(&router);
                tokio::spawn(async move {
                    if let Err(e) =
                        edge::subscribe::run(hub_url, subscriber_key, router_for_sub).await
                    {
                        error!("route subscriber exited: {e}");
                    }
                });
            }

            tokio::select! {
                res = edge.run() => {
                    if let Err(e) = res { error!("edge error: {e}"); }
                }
                _ = turbo_common::shutdown::shutdown_signal() => {}
            }
        }
        (false, false) => {
            anyhow::bail!("both hub and edge are disabled -- nothing to run");
        }
    }

    info!("turbo-node stopped");
    Ok(())
}

/// Derive the public URL embedded into invite tokens. Operators should
/// override via `[hub].public_url` when running behind a reverse proxy.
fn default_public_url(hub: &config::HubConfig) -> String {
    hub.public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", hub.listen_addr))
}

/// Build the `OwnershipPolicy` from the operator's tenant allowlist in config.
/// Only called when the hub is enabled -- edge-only mode doesn't need a policy.
///
/// Validates at startup that each entry's `pq_public_key` hashes to the
/// configured `id`. A mismatch here almost always means the operator
/// copy-pasted one tenant's key against another's id: fail loudly, don't
/// let the hub come up with broken crypto bindings.
fn build_ownership_policy(tenants: &[config::TenantEntry]) -> anyhow::Result<OwnershipPolicy> {
    let mut policy = OwnershipPolicy::new();
    for tenant in tenants {
        let tenant_id: TenantId = tenant.id.parse().with_context(|| {
            format!(
                "invalid tenant id '{}' for tenant '{}'",
                tenant.id, tenant.name
            )
        })?;
        let pq_public_key: turbo_common::identity::PqPublicKey =
            tenant.pq_public_key.parse().with_context(|| {
                format!(
                    "invalid pq_public_key for tenant '{}' (expected unpadded base64url of {} bytes)",
                    tenant.name,
                    turbo_common::identity::PQ_PUB_KEY_LEN
                )
            })?;
        if TenantId::derive(&pq_public_key) != tenant_id {
            anyhow::bail!(
                "tenant '{}': pq_public_key does not hash to id. \
                 The hex id must equal sha256(decode_base64url(pq_public_key)). \
                 Check for a copy-paste mismatch between tenants.",
                tenant.name
            );
        }
        policy.register_tenant(&tenant_id, pq_public_key, tenant.hostnames.iter().cloned());
    }
    Ok(policy)
}

/// Create an iroh Endpoint, build the Router from tenant config, and
/// construct the Edge. Returns the Router (for dynamic updates), the Edge,
/// the edge's EndpointId (hex), and its bound socket addresses (as strings).
///
/// The edge endpoint has no ALPNs because it only makes outbound connections
/// to agents -- it never accepts inbound iroh connections.
async fn build_edge(
    secret_key: iroh::SecretKey,
    tenants: &[config::TenantEntry],
    edge_config: &config::EdgeConfig,
) -> anyhow::Result<(Arc<edge::router::Router>, edge::Edge, String, Vec<String>)> {
    let ep = Endpoint::builder().secret_key(secret_key).bind().await?;

    let edge_node_id = ep.id().to_string();
    let edge_addresses: Vec<String> = ep.bound_sockets().iter().map(|s| s.to_string()).collect();

    info!(
        endpoint_id = %ep.addr().id.fmt_short(),
        "iroh endpoint bound for edge (outbound-only)"
    );

    let router = Arc::new(edge::router::Router::load_from_config(tenants)?);

    let mut edge = edge::Edge::new(
        Arc::clone(&router),
        Arc::new(ep),
        edge_config.listen_addr.clone(),
        edge_config.health_listen_addr.clone(),
    );

    if let Some(tls) = &edge_config.tls {
        let cert_store = edge::tls::CertStore::new(&tls.cert_dir)?;

        let acme = if let Some(email) = tls.acme_email.clone() {
            let tokens: edge::acme::ChallengeTokens = Default::default();

            // HTTP-01 challenge server on :80 (or wherever `http_listen_addr` points).
            let http_addr = tls.http_listen_addr.clone();
            let tokens_for_http = tokens.clone();
            tokio::spawn(async move {
                if let Err(e) = edge::acme::run_http01_server(&http_addr, tokens_for_http).await {
                    tracing::error!(error = %e, "ACME HTTP-01 server exited");
                }
            });

            let coordinator = edge::acme::AcmeCoordinator::new(
                cert_store.clone(),
                tokens,
                email,
                tls.acme_staging,
            )
            .await?;
            Some(Arc::new(coordinator))
        } else {
            info!("TLS termination enabled without ACME; certs must be user-provided");
            None
        };

        edge = edge.with_tls(cert_store, acme);
    }

    Ok((router, edge, edge_node_id, edge_addresses))
}

/// Background task: receives materialized route tables from the hub's broadcast
/// channel and applies them to the edge's router.
async fn route_sync_task(mut route_rx: broadcast::Receiver<RouteTable>, router: Arc<Router>) {
    loop {
        match route_rx.recv().await {
            Ok(new_table) => {
                let count = new_table.len();
                router.replace(new_table).await;
                info!(hostnames = count, "dynamic route update applied");
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "route sync lagged, waiting for next update");
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("route broadcast channel closed, stopping sync task");
                break;
            }
        }
    }
}
