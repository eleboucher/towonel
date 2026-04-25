mod admin;
mod config;
mod edge;
mod hub;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::endpoint::{Endpoint, presets::N0};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use towonel_common::identity::TenantId;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;

use crate::edge::router::Router;
use crate::hub::HubIdentity;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "towonel",
    version,
    about = "turbo-tunnel: run an edge / hub node, or manage one from the CLI.\n\
             \n\
             With no subcommand (or `serve`), the binary runs the node -- edge \
             and/or hub, configured via TOWONEL_* env vars. Other subcommands \
             are operator-facing management tools that talk to a running hub."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node (hub and/or edge) -- same as invoking the binary with
    /// no subcommand. Kept for scripts that want an explicit verb.
    Serve,
    /// Manage tenant keypairs.
    Tenant {
        #[command(subcommand)]
        action: TenantAction,
    },
    /// Manage signed config entries on a hub.
    Entry {
        #[command(subcommand)]
        action: EntryAction,
    },
    /// Manage agent keypairs (for static tenant allowlists -- stateless
    /// agents derive their key from the invite seed and don't need this).
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Operator-only: manage tenant invite tokens.
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },
    /// Operator-only: manage edge-node invite tokens (`tt_edge_2_...`).
    /// The node boots by reading the token from `TOWONEL_EDGE_INVITE_TOKEN`.
    EdgeInvite {
        #[command(subcommand)]
        action: EdgeInviteAction,
    },
}

#[derive(Subcommand)]
enum TenantAction {
    /// Generate a new ML-DSA-65 (post-quantum) tenant keypair and save to disk.
    Init {
        #[arg(long, default_value = "tenant.key")]
        key_path: PathBuf,
    },
    /// Voluntarily leave: submit `DeleteHostname` + `RevokeAgent` entries and
    /// print a confirmation. The operator may additionally drop the tenant
    /// from their allowlist.
    Leave {
        /// Path to the tenant key file.
        #[arg(long)]
        key_path: Option<PathBuf>,
        /// Hub URL. Defaults to `TOWONEL_HUB_URL`.
        #[arg(long)]
        hub_url: Option<String>,
    },
    /// Operator-only: evict a tenant from the hub's allowlist. Existing
    /// signed entries stay in the DB (signatures remain valid) but the
    /// route table stops surfacing them.
    Remove {
        #[arg(long)]
        hub_url: Option<String>,
        /// Operator API key. Defaults to $`TOWONEL_OPERATOR_KEY`.
        #[arg(long)]
        api_key: Option<String>,
        /// Hex-encoded tenant public key (64 chars).
        #[arg(long)]
        tenant_id: String,
    },
    /// Export the tenant key as a passphrase-encrypted string. Print the
    /// result to stdout -- copy it to a safe place (password manager, paper
    /// backup). Uses AES-256-GCM + argon2id.
    ExportKey {
        /// Path to the tenant key file.
        #[arg(long)]
        key_path: Option<PathBuf>,
        /// Passphrase for encryption. Prompted interactively if omitted.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Import a tenant key from a previously exported encrypted string.
    /// Decrypts the backup and writes the seed to disk.
    ImportKey {
        /// Where to write the recovered key file.
        #[arg(long, default_value = "tenant.key")]
        key_path: PathBuf,
        /// The `towonel-key-v1:...` backup string (from export-key).
        #[arg(long)]
        backup: String,
        /// Passphrase used during export.
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum EntryAction {
    /// Sign and submit a config entry to a hub.
    Submit {
        /// Defaults to `TOWONEL_HUB_URL`.
        #[arg(long)]
        hub_url: Option<String>,
        /// Path to the tenant key file.
        #[arg(long)]
        key_path: Option<PathBuf>,
        /// Operation: upsert-hostname, delete-hostname, upsert-agent, revoke-agent
        #[arg(long)]
        op: String,
        #[arg(long)]
        hostname: Option<String>,
        /// Hex-encoded agent public key (for agent ops).
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// List all config entries for the current tenant.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        key_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Generate a new agent keypair and save to disk.
    Init {
        #[arg(long, default_value = "agent.key")]
        key_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum InviteAction {
    /// Create a new invite token. Operator-only.
    Create {
        #[arg(long)]
        hub_url: Option<String>,
        /// Operator API key. Defaults to $`TOWONEL_OPERATOR_KEY`.
        #[arg(long)]
        api_key: Option<String>,
        /// Human-readable tenant name. Random if omitted.
        #[arg(long)]
        name: Option<String>,
        /// Comma-separated hostname patterns to pre-approve.
        #[arg(long, value_delimiter = ',')]
        hostnames: Vec<String>,
        /// Token validity, e.g. "48h", "7d", "never". Defaults to `never`
        /// so stateless K8s deployments don't need rotation on every
        /// Secret cycle.
        #[arg(long, default_value = "never")]
        expires: String,
    },
    /// List invites on the hub. Operator-only.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Revoke a pending invite. Operator-only.
    Revoke {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// The `invite_id` as printed by `invite list` (base64url).
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum EdgeInviteAction {
    /// Create a new edge-node invite token. Edge tokens never expire;
    /// revoke with `edge-invite revoke` when the edge should lose access.
    Create {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// Human-readable edge name (e.g. "charlie-fra1"). Random if omitted.
        #[arg(long)]
        name: Option<String>,
    },
    /// List edge-node invites on the hub.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Revoke a pending edge invite.
    Revoke {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        id: String,
    },
}

#[allow(clippy::large_futures)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The ring provider install only fails if another provider was already installed.
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

    match cli.command {
        None | Some(Command::Serve) => run_node().await,
        Some(Command::Tenant { action }) => match action {
            TenantAction::Init { key_path } => {
                admin::tenant::cmd_keypair_init(&key_path, admin::tenant::KeypairKind::Tenant).await
            }
            TenantAction::Leave { key_path, hub_url } => {
                admin::tenant::cmd_tenant_leave(key_path, hub_url).await
            }
            TenantAction::Remove {
                hub_url,
                api_key,
                tenant_id,
            } => admin::tenant::cmd_tenant_remove(hub_url, api_key, tenant_id).await,
            TenantAction::ExportKey {
                key_path,
                passphrase,
            } => admin::tenant::cmd_tenant_export_key(key_path, passphrase),
            TenantAction::ImportKey {
                key_path,
                backup,
                passphrase,
            } => admin::tenant::cmd_tenant_import_key(key_path, backup, passphrase),
        },
        Some(Command::Entry { action }) => match action {
            EntryAction::Submit {
                hub_url,
                key_path,
                op,
                hostname,
                agent_id,
            } => admin::entry::cmd_entry_submit(hub_url, key_path, &op, hostname, agent_id).await,
            EntryAction::List { hub_url, key_path } => {
                admin::entry::cmd_entry_list(hub_url, key_path).await
            }
        },
        Some(Command::Agent { action }) => match action {
            AgentAction::Init { key_path } => {
                admin::tenant::cmd_keypair_init(&key_path, admin::tenant::KeypairKind::Agent).await
            }
        },
        Some(Command::Invite { action }) => match action {
            InviteAction::Create {
                hub_url,
                api_key,
                name,
                hostnames,
                expires,
            } => admin::invite::cmd_invite_create(hub_url, api_key, name, hostnames, expires).await,
            InviteAction::List { hub_url, api_key } => {
                admin::invite::cmd_invite_list(hub_url, api_key).await
            }
            InviteAction::Revoke {
                hub_url,
                api_key,
                id,
            } => admin::invite::cmd_invite_revoke(hub_url, api_key, id).await,
        },
        Some(Command::EdgeInvite { action }) => match action {
            EdgeInviteAction::Create {
                hub_url,
                api_key,
                name,
            } => admin::invite::cmd_edge_invite_create(hub_url, api_key, name).await,
            EdgeInviteAction::List { hub_url, api_key } => {
                admin::invite::cmd_edge_invite_list(hub_url, api_key).await
            }
            EdgeInviteAction::Revoke {
                hub_url,
                api_key,
                id,
            } => admin::invite::cmd_edge_invite_revoke(hub_url, api_key, id).await,
        },
    }
}

async fn run_node() -> anyhow::Result<()> {
    let config = config::NodeConfig::load()?;

    let secret_key = config
        .identity
        .load_secret_key_async()
        .await
        .context("failed to load node identity")?;
    let node_id = secret_key.public();
    info!(%node_id, "loaded node identity");

    info!(
        hub = config.hub.enabled,
        edge = config.edge.enabled,
        tenants = config.tenants.len(),
        "towonel starting"
    );

    match (config.hub.enabled, config.edge.enabled) {
        (true, true) => {
            let (route_tx, route_rx) = broadcast::channel::<RouteTable>(64);
            let (router, edge, edge_node_id, edge_addresses) =
                build_edge(secret_key, &config.tenants, &config.edge).await?;

            let edge = configure_hub_self_route(edge, &config.hub);

            let public_addresses = if config.edge.public_addresses.is_empty() {
                edge_addresses
            } else {
                config.edge.public_addresses.clone()
            };

            let identity = HubIdentity {
                node_id,
                edge_node_id: Some(edge_node_id),
                edge_addresses: public_addresses,
                software_version: SOFTWARE_VERSION,
            };
            let hub = hub::Hub::new(build_hub_params(&config, identity, route_tx).await?);

            tokio::spawn(route_sync_task(route_rx, router));

            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                res = edge.run() => {
                    if let Err(e) = res { error!("edge error: {e}"); }
                }
                () = towonel_common::shutdown::shutdown_signal() => {}
            }
        }
        (true, false) => {
            let (route_tx, _) = broadcast::channel::<RouteTable>(64);
            let identity = HubIdentity {
                node_id,
                edge_node_id: None,
                edge_addresses: Vec::new(),
                software_version: SOFTWARE_VERSION,
            };
            drop(secret_key);
            let hub = hub::Hub::new(build_hub_params(&config, identity, route_tx).await?);
            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                () = towonel_common::shutdown::shutdown_signal() => {}
            }
        }
        (false, true) => {
            let subscriber_key = secret_key.clone();
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
                () = towonel_common::shutdown::shutdown_signal() => {}
            }
        }
        (false, false) => {
            anyhow::bail!("both hub and edge are disabled -- nothing to run");
        }
    }

    info!("towonel stopped");
    Ok(())
}

/// Derive the public URL embedded into invite tokens. Operators should
/// override via `[hub].public_url` when running behind a reverse proxy.
fn default_public_url(hub: &config::HubConfig) -> String {
    hub.public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", hub.listen_addr))
}

fn host_from_url(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(str::to_lowercase)
}

fn configure_hub_self_route(edge: edge::Edge, hub: &config::HubConfig) -> edge::Edge {
    let public_url = default_public_url(hub);
    let Some(host) = host_from_url(&public_url) else {
        return edge;
    };
    let edge = edge.with_hub_self_route(edge::HubSelfRoute {
        hostname: host.clone(),
        local_addr: hub.listen_addr.clone(),
    });
    if let Some(acme) = edge.acme() {
        tokio::spawn(async move {
            if let Err(e) = acme.ensure_cert(&host).await {
                warn!(error = %e, %host, "initial hub cert request failed; will retry on first connection");
            }
        });
    }
    edge
}

/// Build [`hub::HubParams`] from the node config and an identity.
///
/// Shared between the hub+edge and hub-only match arms so the field
/// wiring isn't duplicated.
async fn build_hub_params(
    config: &config::NodeConfig,
    identity: HubIdentity,
    route_tx: broadcast::Sender<RouteTable>,
) -> anyhow::Result<hub::HubParams> {
    let policy = build_ownership_policy(&config.tenants)?;
    let operator_api_key =
        hub::load_or_generate_operator_key(&config.hub.operator_api_key_path).await?;
    let invite_hash_key = config
        .hub
        .invite_hash_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("invite_hash_key was not loaded during config"))?;
    let public_url = default_public_url(&config.hub);
    Ok(hub::HubParams {
        listen_addr: config.hub.listen_addr.clone(),
        health_listen_addr: config.hub.health_listen_addr.clone(),
        database: config.hub.database.clone(),
        route_tx,
        static_policy: policy,
        identity,
        operator_api_key,
        invite_hash_key,
        public_url,
    })
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
        let pq_public_key: towonel_common::identity::PqPublicKey =
            tenant.pq_public_key.parse().with_context(|| {
                format!(
                    "invalid pq_public_key for tenant '{}' (expected unpadded base64url of {} bytes)",
                    tenant.name,
                    towonel_common::identity::PQ_PUB_KEY_LEN
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
/// the edge's `EndpointId` (hex), and its bound socket addresses (as strings).
///
/// The edge endpoint has no ALPNs because it only makes outbound connections
/// to agents -- it never accepts inbound iroh connections.
async fn build_edge(
    secret_key: iroh::SecretKey,
    tenants: &[config::TenantEntry],
    edge_config: &config::EdgeConfig,
) -> anyhow::Result<(
    Arc<edge::router::Router>,
    edge::Edge,
    iroh::EndpointId,
    Vec<String>,
)> {
    let ep = Endpoint::builder(N0).secret_key(secret_key).bind().await?;

    let edge_node_id = ep.id();
    let edge_addresses: Vec<String> = ep
        .bound_sockets()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

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
    )
    .with_listen_workers(edge_config.listen_workers);

    if let Some(tls) = &edge_config.tls {
        let cert_store = edge::tls::CertStore::new(&tls.cert_dir)?;

        let acme = tls.acme_email.clone().map_or_else(
            || {
                info!("TLS termination enabled without ACME; certs must be user-provided");
                None
            },
            |email| {
                let tokens: edge::acme::ChallengeTokens = Arc::default();

                // HTTP-01 challenge server on :80 (or wherever `http_listen_addr` points).
                let http_addr = tls.http_listen_addr.clone();
                let tokens_for_http = tokens.clone();
                tokio::spawn(async move {
                    if let Err(e) = edge::acme::run_http01_server(&http_addr, tokens_for_http).await
                    {
                        tracing::error!(error = %e, "ACME HTTP-01 server exited");
                    }
                });

                let coordinator = edge::acme::AcmeCoordinator::new(
                    cert_store.clone(),
                    tokens,
                    email,
                    tls.acme_staging,
                );
                Some(Arc::new(coordinator))
            },
        );

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
                router.replace(new_table);
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
