mod admin;
mod config;
mod edge;
mod hub;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::endpoint::{Endpoint, presets::Minimal};
use tokio::sync::broadcast;
use tracing::{error, info};

use towonel_common::edge_link::EdgeCapabilities;
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
    /// Operator-only: manage hub user accounts (web frontend).
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Operator-only: create signup invite codes for the web frontend.
    SignupInvite {
        #[command(subcommand)]
        action: SignupInviteAction,
    },
    /// Operator-only: manage per-tenant TCP/UDP port reservations.
    Port {
        #[command(subcommand)]
        action: PortAction,
    },
    /// Operator-only: inspect ACME state (account URI for CAA pinning).
    Acme {
        #[command(subcommand)]
        action: AcmeAction,
    },
    /// Operator-only: list the edges registered with the hub.
    Edge {
        #[command(subcommand)]
        action: EdgeAction,
    },
    /// Operator-only: inspect and update hub-wide settings.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
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
enum UserAction {
    /// Create a hub user account. Writes directly to the hub DB, so this
    /// must run on the hub host (or with `TOWONEL_HUB_DB_*` pointing at it).
    Create {
        /// Account email.
        #[arg(long)]
        email: String,
        /// `user` or `operator`.
        #[arg(long, default_value = "user")]
        role: String,
        /// Password. Prompted interactively if omitted.
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum PortAction {
    /// Reserve a TCP/UDP port slot for a tenant on the shared IP.
    Reserve {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// Tenant the port is being reserved for.
        #[arg(long)]
        tenant_id: String,
        /// `tcp` or `udp`.
        #[arg(long)]
        proto: String,
        /// Specific port. Omit to let the hub auto-pick.
        #[arg(long)]
        port: Option<u16>,
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Release a port reservation.
    Release {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        proto: String,
        #[arg(long)]
        port: u16,
    },
    /// List a tenant's port reservations.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        tenant_id: String,
    },
    /// List all port reservations across every tenant. Operator-only.
    ListAll {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Show a page of free ports in the auto-pick range.
    Available {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// `tcp` or `udp`.
        #[arg(long)]
        proto: String,
        /// How many free ports to return (1..=200, default 20).
        #[arg(long)]
        count: Option<u16>,
    },
}

#[derive(Subcommand)]
enum AcmeAction {
    Account,
}

#[derive(Subcommand)]
enum EdgeAction {
    /// List the edges registered with the hub.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Show the per-user port quota.
    GetPortQuota {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Set the per-user port quota.
    SetPortQuota {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// New quota value (>= 0).
        #[arg(long)]
        value: i64,
    },
}

#[derive(Subcommand)]
enum SignupInviteAction {
    /// Create a new signup code and print it to stdout.
    Create {
        /// Role granted on redemption: `user` or `operator`.
        #[arg(long, default_value = "user")]
        role: String,
        /// Days until the code expires. Omit for non-expiring.
        #[arg(long)]
        expires_in_days: Option<u32>,
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
        /// Attach the tunnel to an existing hub user (email).
        #[arg(long)]
        owner_email: Option<String>,
        /// Region the agent belongs to. Defaults to `EU` at the hub when
        /// omitted; the agent is handed only edges serving this region.
        #[arg(long)]
        region: Option<String>,
        /// Extra regions whose edges the agent should also dial for failover.
        #[arg(long, value_delimiter = ',')]
        failover_regions: Vec<String>,
    },
    /// List invites on the hub. Operator-only.
    List {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Show a single invite's details. Operator-only.
    Get {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// The `invite_id` as printed by `invite list` (base64url).
        #[arg(long)]
        id: String,
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
    /// Add hostname patterns to an existing invite. Operator-only.
    AddHostnames {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// The `invite_id` as printed by `invite list` (base64url).
        #[arg(long)]
        id: String,
        /// Comma-separated hostname patterns to add.
        #[arg(long, value_delimiter = ',')]
        hostnames: Vec<String>,
    },
    /// Remove a hostname pattern from an existing invite. Operator-only.
    RemoveHostname {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// The `invite_id` as printed by `invite list` (base64url).
        #[arg(long)]
        id: String,
        /// The hostname pattern to remove.
        #[arg(long)]
        hostname: String,
    },
}

#[expect(
    clippy::large_futures,
    reason = "top-level run future is large; the bin entrypoint boxes it"
)]
#[expect(
    clippy::too_many_lines,
    reason = "subcommand dispatch is a flat lookup; splitting it hides the routing table"
)]
pub async fn run() -> anyhow::Result<()> {
    #[expect(
        clippy::expect_used,
        reason = "duplicate CryptoProvider install is a startup-time programmer error"
    )]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring CryptoProvider");

    let _telemetry = towonel_common::telemetry::init("towonel", SOFTWARE_VERSION);

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
                owner_email,
                region,
                failover_regions,
            } => {
                admin::invite::cmd_invite_create(
                    hub_url,
                    api_key,
                    name,
                    hostnames,
                    expires,
                    owner_email,
                    region,
                    failover_regions,
                )
                .await
            }
            InviteAction::List { hub_url, api_key } => {
                admin::invite::cmd_invite_list(hub_url, api_key).await
            }
            InviteAction::Get {
                hub_url,
                api_key,
                id,
            } => admin::invite::cmd_invite_get(hub_url, api_key, id).await,
            InviteAction::Revoke {
                hub_url,
                api_key,
                id,
            } => admin::invite::cmd_invite_revoke(hub_url, api_key, id).await,
            InviteAction::AddHostnames {
                hub_url,
                api_key,
                id,
                hostnames,
            } => admin::invite::cmd_invite_add_hostnames(hub_url, api_key, id, hostnames).await,
            InviteAction::RemoveHostname {
                hub_url,
                api_key,
                id,
                hostname,
            } => admin::invite::cmd_invite_remove_hostname(hub_url, api_key, id, hostname).await,
        },
        Some(Command::User { action }) => match action {
            UserAction::Create {
                email,
                role,
                password,
            } => admin::user::cmd_user_create(email, role, password).await,
        },
        Some(Command::SignupInvite { action }) => match action {
            SignupInviteAction::Create {
                role,
                expires_in_days,
            } => admin::signup_invite::cmd_signup_invite_create(role, expires_in_days).await,
        },
        Some(Command::Port { action }) => match action {
            PortAction::Reserve {
                hub_url,
                api_key,
                tenant_id,
                proto,
                port,
                label,
            } => {
                admin::port::cmd_port_reserve(hub_url, api_key, tenant_id, proto, port, label).await
            }
            PortAction::Release {
                hub_url,
                api_key,
                tenant_id,
                proto,
                port,
            } => admin::port::cmd_port_release(hub_url, api_key, tenant_id, proto, port).await,
            PortAction::List {
                hub_url,
                api_key,
                tenant_id,
            } => admin::port::cmd_port_list(hub_url, api_key, tenant_id).await,
            PortAction::ListAll { hub_url, api_key } => {
                admin::port::cmd_port_list_all(hub_url, api_key).await
            }
            PortAction::Available {
                hub_url,
                api_key,
                proto,
                count,
            } => admin::port::cmd_port_available(hub_url, api_key, proto, count).await,
        },
        Some(Command::Acme { action }) => match action {
            AcmeAction::Account => admin::acme::cmd_acme_account().await,
        },
        Some(Command::Edge { action }) => match action {
            EdgeAction::List { hub_url, api_key } => {
                admin::edge::cmd_edge_list(hub_url, api_key).await
            }
        },
        Some(Command::Settings { action }) => match action {
            SettingsAction::GetPortQuota { hub_url, api_key } => {
                admin::settings::cmd_get_port_quota(hub_url, api_key).await
            }
            SettingsAction::SetPortQuota {
                hub_url,
                api_key,
                value,
            } => admin::settings::cmd_set_port_quota(hub_url, api_key, value).await,
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
            let control_handler: edge::hub_client::ControlHandlerCell =
                Arc::new(std::sync::OnceLock::new());
            let live_agents_sink: edge::hub_client::LiveAgentSinkCell =
                Arc::new(std::sync::OnceLock::new());
            let hub_client = Arc::new(edge::hub_client::InProcessHubClient::new(
                route_tx.clone(),
                Arc::clone(&control_handler),
                Arc::clone(&live_agents_sink),
            ));
            let BuiltEdge {
                edge,
                edge_node_id,
                bound_socket_strings,
                iroh_port,
                endpoint,
                ..
            } = build_edge(secret_key, &config.tenants, &config.edge).await?;

            let edge = edge.with_hub_client(hub_client);

            let (public_addresses, edge_iroh_addresses, edge_public_ips) =
                edge_advertised_addresses(&config.edge, &bound_socket_strings, iroh_port);

            let identity = HubIdentity {
                node_id,
                edge_node_id: Some(edge_node_id),
                edge_addresses: public_addresses.clone(),
                edge_iroh_addresses,
                edge_public_ips,
                edge_region: Some(config.edge.region.clone()),
                relay_url: std::env::var("TOWONEL_HUB_RELAY_URL")
                    .ok()
                    .filter(|v| !v.is_empty()),
                software_version: SOFTWARE_VERSION,
            };
            let hub = hub::Hub::new(build_hub_params(&config, identity, route_tx).await?)
                .with_control_handler_cell(control_handler)
                .with_live_agents_sink_cell(live_agents_sink);

            // edge.run() runs as a task so it always drains: on SIGTERM or a
            // hub exit we cancel the token and await it, rather than dropping
            // its future mid-flight (which would skip the drain).
            let edge_shutdown = tokio_util::sync::CancellationToken::new();
            let mut edge_handle = tokio::spawn({
                let shutdown = edge_shutdown.clone();
                async move { edge.run(shutdown).await }
            });
            tokio::select! {
                res = hub.run() => {
                    if let Err(e) = res { error!("hub error: {e}"); }
                }
                res = &mut edge_handle => {
                    if let Ok(Err(e)) = &res { error!("edge error: {e}"); }
                }
                () = towonel_common::shutdown::shutdown_signal() => {}
            }
            edge_shutdown.cancel();
            if !edge_handle.is_finished()
                && let Err(e) = edge_handle.await
            {
                tracing::warn!("edge task join error: {e}");
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
                edge_public_ips: Vec::new(),
                edge_region: None,
                relay_url: std::env::var("TOWONEL_HUB_RELAY_URL")
                    .ok()
                    .filter(|v| !v.is_empty()),
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
            let BuiltEdge {
                edge,
                edge_node_id,
                bound_socket_strings,
                iroh_port,
                endpoint,
                ..
            } = build_edge(secret_key, &config.tenants, &config.edge).await?;

            let (Some(link_addr), Some(link_psk)) = (
                config.edge.hub_link_addr.clone(),
                config.edge.hub_link_psk.clone(),
            ) else {
                anyhow::bail!(
                    "edge-only mode requires TOWONEL_EDGE_HUB_LINK_ADDR and \
                     TOWONEL_EDGE_HUB_LINK_PSK"
                );
            };
            let handle = edge::hub_link::HubLinkHandle::new(64).with_sessions(edge.sessions());
            let (_public_addresses, iroh_endpoints, public_ips) =
                edge_advertised_addresses(&config.edge, &bound_socket_strings, iroh_port);
            let cfg = edge::hub_link::HubLinkConfig {
                addr: link_addr,
                psk: link_psk,
                edge_id: *edge_node_id.as_bytes(),
                iroh_endpoints,
                software_version: SOFTWARE_VERSION.to_string(),
                capabilities: EdgeCapabilities {
                    tcp_services: config.edge.tcp_services,
                    udp_services: config.edge.udp_services,
                },
                public_ips,
                region: config.edge.region.clone(),
            };
            let hub_client: Arc<dyn edge::hub_client::HubClient> =
                Arc::new(edge::hub_client::RemoteHubClient::new(handle.clone()));
            let edge = edge.with_hub_client(hub_client);

            let link_shutdown = tokio_util::sync::CancellationToken::new();
            let link_task = {
                let shutdown = link_shutdown.clone();
                tokio::spawn(async move {
                    edge::hub_link::run_supervisor(cfg, handle, shutdown).await;
                })
            };

            // SIGTERM cancels the token; edge.run() drains before returning
            // instead of dropping connections.
            let edge_shutdown = tokio_util::sync::CancellationToken::new();
            {
                let shutdown = edge_shutdown.clone();
                tokio::spawn(async move {
                    towonel_common::shutdown::shutdown_signal().await;
                    shutdown.cancel();
                });
            }
            if let Err(e) = edge.run(edge_shutdown).await {
                error!("edge error: {e}");
            }
            link_shutdown.cancel();
            if let Err(e) = link_task.await {
                tracing::debug!(error = %e, "hub_link supervisor join error");
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
    let operator_api_key = hub::load_or_generate_operator_key(
        config.hub.operator_api_key.as_deref(),
        &config.hub.operator_api_key_path,
    )
    .await?;
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
    let mailer = build_mailer(&config.hub, &public_url)?;
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
        link_listen_addr: config.hub.link_listen_addr.clone(),
        link_psk: config.hub.link_psk.clone(),
        tls: config.hub.tls.clone(),
        web_enabled: config.hub.web_enabled,
        ports_require_reservation: config.hub.ports_require_reservation,
        leader_election: config.hub.leader_election,
        leader_db_dsn: config.hub.leader_db_dsn.clone(),
        oidc: config.hub.oidc.clone(),
        mailer,
        webauthn_rp_id: config.hub.webauthn_rp_id.clone(),
    })
}

fn build_mailer(
    hub: &config::HubConfig,
    public_url: &str,
) -> anyhow::Result<Option<hub::mail::SharedMailer>> {
    let Some(mail) = hub.mail.as_ref() else {
        return Ok(None);
    };
    let link_base = hub.console_url.as_ref().map_or_else(
        || hub::mail::LinkBase::Hub(public_url.to_string()),
        |url| hub::mail::LinkBase::Console(url.clone()),
    );
    let settings = hub::mail::MailjetSettings {
        api_key: mail.api_key.clone(),
        api_secret: mail.api_secret.clone(),
        from_email: mail.from_email.clone(),
        from_name: mail.from_name.clone(),
        link_base,
        sandbox: mail.sandbox,
    };
    let mailer = hub::mail::MailjetMailer::new(settings)?;
    Ok(Some(std::sync::Arc::new(mailer)))
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
/// Pkarr discovery is disabled; one or more relays (comma-separated) can be
/// opted into via `TOWONEL_EDGE_RELAY_URL`.
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
        .transport_config(towonel_common::protocol::tunnel_transport_config())
        .relay_mode(towonel_common::relay::relay_mode_from_env(
            "TOWONEL_EDGE_RELAY_URL",
        ))
        .ca_roots_config(iroh::tls::CaRootsConfig::insecure_skip_verify())
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

    let edge = edge::Edge::new(
        router,
        Arc::clone(&endpoint),
        edge_config.listen_addr.clone(),
        edge_config.health_listen_addr.clone(),
        edge_config.max_connections_per_tenant,
    )
    .with_listen_workers(edge_config.listen_workers)
    .with_http_listen_addr(edge_config.http_listen_addr.clone())
    .with_proxy_protocol(edge_config.proxy_protocol.clone())
    .with_tcp_services(edge_config.tcp_services)
    .with_udp_services(edge_config.udp_services);

    Ok(BuiltEdge {
        edge,
        edge_node_id,
        bound_socket_strings,
        iroh_port: port,
        endpoint,
    })
}

/// For each operator-advertised `host:port`, swap in `iroh_port`. Falls
/// back to bound sockets filtered to routable addresses when no
/// Resolve the addresses an edge advertises, shared by the hub+edge and
/// edge-only run arms so both derive identical topology: public addresses
/// (falling back to the bound sockets), the derived iroh addresses, and the
/// public IPs (falling back to hosts extracted from the public addresses).
fn edge_advertised_addresses(
    edge_cfg: &crate::config::EdgeConfig,
    bound_socket_strings: &[String],
    iroh_port: u16,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let public_addresses = if edge_cfg.public_addresses.is_empty() {
        bound_socket_strings.to_vec()
    } else {
        edge_cfg.public_addresses.clone()
    };
    let iroh_addresses =
        derive_edge_iroh_addresses(&public_addresses, iroh_port, bound_socket_strings);
    let public_ips = if edge_cfg.public_ips.is_empty() {
        extract_hosts_from_addresses(&public_addresses)
    } else {
        edge_cfg.public_ips.clone()
    };
    (public_addresses, iroh_addresses, public_ips)
}

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

/// Extract host/IP portions from a list of `host:port` addresses.
/// Strips the port and any bracket-wrapping around IPv6 literals.
fn extract_hosts_from_addresses(addresses: &[String]) -> Vec<String> {
    addresses
        .iter()
        .filter_map(|entry| {
            let host = entry.rsplit_once(':').map_or(entry.as_str(), |(h, _)| h);
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            (!host.is_empty()).then(|| host.to_string())
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
