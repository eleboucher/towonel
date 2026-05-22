mod admin;
mod config;
mod edge;
mod hub;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::RelayMode;
use iroh::endpoint::{Endpoint, presets::Minimal};
use tokio::sync::broadcast;
use tracing::{error, info};

use towonel_common::identity::TenantId;
use towonel_common::ownership::OwnershipPolicy;
use towonel_common::routing::RouteTable;

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

#[expect(
    clippy::large_futures,
    reason = "top-level main future is large; boxing it provides no benefit"
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

#[expect(
    clippy::too_many_lines,
    reason = "linear boot orchestration — splitting the hub/edge/edge-only arms fragments the flow"
)]
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
            let (route_tx, _) = broadcast::channel::<RouteTable>(64);
            let hub_client = Arc::new(edge::hub_client::InProcessHubClient::new(route_tx.clone()));
            let BuiltEdge {
                edge,
                edge_node_id,
                bound_socket_strings,
                iroh_port,
                endpoint,
                ..
            } = build_edge(secret_key, &config.tenants, &config.edge).await?;

            let edge = configure_hub_self_route(edge, &config.hub).with_hub_client(hub_client);

            let public_addresses = if config.edge.public_addresses.is_empty() {
                bound_socket_strings.clone()
            } else {
                config.edge.public_addresses.clone()
            };
            let edge_iroh_addresses =
                derive_edge_iroh_addresses(&public_addresses, iroh_port, &bound_socket_strings);

            let identity = HubIdentity {
                node_id,
                edge_node_id: Some(edge_node_id),
                edge_addresses: public_addresses,
                edge_iroh_addresses,
                software_version: SOFTWARE_VERSION,
            };
            let hub = hub::Hub::new(build_hub_params(&config, identity, route_tx).await?);

            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                res = edge.run() => {
                    if let Err(e) = res { error!("edge error: {e}"); }
                }
                () = towonel_common::shutdown::shutdown_signal() => {}
            }
            endpoint.close().await;
        }
        (true, false) => {
            let (route_tx, _) = broadcast::channel::<RouteTable>(64);
            let identity = HubIdentity {
                node_id,
                edge_node_id: None,
                edge_addresses: Vec::new(),
                edge_iroh_addresses: Vec::new(),
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
            let BuiltEdge {
                router,
                edge,
                endpoint,
                ..
            } = build_edge(secret_key, &config.tenants, &config.edge).await?;

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
            endpoint.close().await;
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
        acme.trigger_obtain(&host);
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
    let kek = config
        .hub
        .hub_kek
        .clone()
        .ok_or_else(|| anyhow::anyhow!("hub_kek was not loaded during config"))?;
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
        kek,
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

struct BuiltEdge {
    router: Arc<edge::router::Router>,
    edge: edge::Edge,
    edge_node_id: iroh::EndpointId,
    bound_socket_strings: Vec<String>,
    iroh_port: u16,
    endpoint: Arc<Endpoint>,
}

/// Create an iroh Endpoint, build the Router from tenant config, and
/// construct the Edge.
///
/// The endpoint registers `ALPN_TUNNEL` for inbound agent connections.
/// It never dials, so Pkarr discovery and relays are disabled.
async fn build_edge(
    secret_key: iroh::SecretKey,
    tenants: &[config::TenantEntry],
    edge_config: &config::EdgeConfig,
) -> anyhow::Result<BuiltEdge> {
    let port = edge_config.iroh_port;
    // clear_ip_transports drops the default unspecified binds so we
    // don't end up with three sockets after our two explicit binds.
    let ep = Endpoint::builder(Minimal)
        .secret_key(secret_key)
        .alpns(vec![towonel_common::protocol::ALPN_TUNNEL.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr(format!("0.0.0.0:{port}"))
        .map_err(|e| anyhow::anyhow!("invalid IPv4 iroh bind addr: {e}"))?
        .bind_addr(format!("[::]:{port}"))
        .map_err(|e| anyhow::anyhow!("invalid IPv6 iroh bind addr: {e}"))?
        .bind()
        .await?;

    let edge_node_id = ep.id();
    let bound_socket_strings: Vec<String> = ep
        .bound_sockets()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    info!(
        endpoint_id = %ep.addr().id.fmt_short(),
        "iroh endpoint bound for edge"
    );

    let endpoint = Arc::new(ep);
    let router = Arc::new(edge::router::Router::load_from_config(tenants)?);

    let mut edge = edge::Edge::new(
        Arc::clone(&router),
        Arc::clone(&endpoint),
        edge_config.listen_addr.clone(),
        edge_config.health_listen_addr.clone(),
    )
    .with_listen_workers(edge_config.listen_workers)
    .with_proxy_protocol(edge_config.proxy_protocol.clone());

    if let Some(tls) = &edge_config.tls {
        let email = tls.acme_email.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "TLS termination requires TOWONEL_EDGE_TLS_ACME_EMAIL (ACME-managed certs only)"
            )
        })?;
        let manager = edge::acme::AcmeManager::new(&tls.cert_dir, email, tls.acme_staging)?;
        edge = edge.with_tls(manager);
    }

    Ok(BuiltEdge {
        router,
        edge,
        edge_node_id,
        bound_socket_strings,
        iroh_port: port,
        endpoint,
    })
}

/// For each operator-advertised `host:port`, swap in `iroh_port`. Falls
/// back to bound sockets filtered to routable addresses when no
/// hostnames are advertised.
fn derive_edge_iroh_addresses(
    public_addresses: &[String],
    iroh_port: u16,
    bound_socket_strings: &[String],
) -> Vec<String> {
    let derived: Vec<String> = public_addresses
        .iter()
        .filter_map(|entry| {
            // rsplit_once so IPv6 `[::1]:443` strips only the trailing port.
            let host = entry.rsplit_once(':').map_or(entry.as_str(), |(h, _)| h);
            (!host.is_empty()).then(|| format!("{host}:{iroh_port}"))
        })
        .collect();
    if !derived.is_empty() {
        return derived;
    }
    bound_socket_strings
        .iter()
        .filter_map(|s| {
            let addr: std::net::SocketAddr = s.parse().ok()?;
            (!addr.ip().is_unspecified() && !addr.ip().is_loopback()).then(|| addr.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::derive_edge_iroh_addresses;

    #[test]
    fn derives_from_advertised_hostnames() {
        let got = derive_edge_iroh_addresses(
            &["tunnel.example.com:443".to_string()],
            51820,
            &["0.0.0.0:51820".to_string()],
        );
        assert_eq!(got, vec!["tunnel.example.com:51820"]);
    }

    #[test]
    fn derives_per_advertised_entry() {
        let got = derive_edge_iroh_addresses(
            &[
                "a.example.com:443".to_string(),
                "b.example.com:443".to_string(),
            ],
            51820,
            &[],
        );
        assert_eq!(got, vec!["a.example.com:51820", "b.example.com:51820"]);
    }

    #[test]
    fn falls_back_to_routable_bound_sockets() {
        let got = derive_edge_iroh_addresses(
            &[],
            51820,
            &[
                "0.0.0.0:51820".to_string(),
                "127.0.0.1:51820".to_string(),
                "203.0.113.4:51820".to_string(),
            ],
        );
        assert_eq!(got, vec!["203.0.113.4:51820"]);
    }

    #[test]
    fn empty_when_no_routable_addresses() {
        let got = derive_edge_iroh_addresses(
            &[],
            51820,
            &["0.0.0.0:51820".to_string(), "127.0.0.1:51820".to_string()],
        );
        assert!(got.is_empty());
    }
}
