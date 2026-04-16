mod entry_cmds;
mod invite_cmds;
mod tenant_cmds;

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use turbo_common::client_state::{ClientState, DefaultPaths};
use turbo_common::identity::write_key_file;

pub(crate) const CBOR_CONTENT_TYPE: &str = "application/cbor";
pub(crate) const JSON_CONTENT_TYPE: &str = "application/json";
const OPERATOR_KEY_ENV: &str = "TURBO_OPERATOR_KEY";
const HUB_URL_ENV: &str = "TURBO_HUB_URL";

#[derive(Parser)]
#[command(name = "turbo-cli", about = "turbo-tunnel management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage tenant keypairs.
    Tenant {
        #[command(subcommand)]
        action: TenantAction,
    },
    /// Manage config entries on a hub.
    Entry {
        #[command(subcommand)]
        action: EntryAction,
    },
    /// Manage agent keypairs.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Operator-only: manage invite tokens.
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },
    /// Operator-only: manage edge-node invite tokens (`tt_edge_1_...`).
    /// Redeemed by `turbo-node init --edge-invite`.
    EdgeInvite {
        #[command(subcommand)]
        action: EdgeInviteAction,
    },
}

#[derive(Subcommand)]
enum TenantAction {
    /// Generate a new Ed25519 tenant keypair and save to disk.
    Init {
        #[arg(long, default_value = "tenant.key")]
        key_path: PathBuf,
    },
    /// Voluntarily leave: submit DeleteHostname + RevokeAgent entries and
    /// print a confirmation. The operator may additionally drop the tenant
    /// from their allowlist.
    Leave {
        /// Path to the tenant key. Defaults to the value in state.toml.
        #[arg(long)]
        key_path: Option<PathBuf>,
        /// Hub URL. Defaults to state.toml / TURBO_HUB_URL.
        #[arg(long)]
        hub_url: Option<String>,
    },
    /// Operator-only: evict a tenant from the hub's allowlist. Existing
    /// signed entries stay in the DB (signatures remain valid) but the
    /// route table stops surfacing them.
    Remove {
        #[arg(long)]
        hub_url: Option<String>,
        /// Operator API key. Defaults to $TURBO_OPERATOR_KEY.
        #[arg(long)]
        api_key: Option<String>,
        /// Hex-encoded tenant public key (64 chars).
        #[arg(long)]
        tenant_id: String,
    },
    /// Export the tenant key as a passphrase-encrypted string. Print the
    /// result to stdout — copy it to a safe place (password manager, paper
    /// backup). Uses AES-256-GCM + argon2id.
    ExportKey {
        /// Path to the tenant key file. Defaults to state.toml.
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
        /// The `turbo-key-v1:...` backup string (from export-key).
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
        /// Defaults to state.toml / TURBO_HUB_URL.
        #[arg(long)]
        hub_url: Option<String>,
        /// Defaults to state.toml's tenant_key_path.
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
    /// Generate a new Ed25519 agent keypair and save to disk.
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
        /// Operator API key. Defaults to $TURBO_OPERATOR_KEY.
        #[arg(long)]
        api_key: Option<String>,
        /// Human-readable tenant name.
        #[arg(long)]
        name: String,
        /// Comma-separated hostname patterns to pre-approve.
        #[arg(long, value_delimiter = ',')]
        hostnames: Vec<String>,
        /// Token validity, e.g. "48h", "7d". Default 48h.
        #[arg(long, default_value = "48h")]
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
        /// The invite_id as printed by `invite list` (base64url).
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum EdgeInviteAction {
    /// Create a new edge-node invite token.
    Create {
        #[arg(long)]
        hub_url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// Human-readable edge name (e.g. "charlie-fra1").
        #[arg(long)]
        name: String,
        /// Token validity, e.g. "24h", "7d". Default 24h.
        #[arg(long, default_value = "24h")]
        expires: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Tenant { action } => match action {
            TenantAction::Init { key_path } => {
                tenant_cmds::cmd_keypair_init(&key_path, "tenant").await
            }
            TenantAction::Leave { key_path, hub_url } => {
                tenant_cmds::cmd_tenant_leave(key_path, hub_url).await
            }
            TenantAction::Remove {
                hub_url,
                api_key,
                tenant_id,
            } => tenant_cmds::cmd_tenant_remove(hub_url, api_key, tenant_id).await,
            TenantAction::ExportKey {
                key_path,
                passphrase,
            } => tenant_cmds::cmd_tenant_export_key(key_path, passphrase),
            TenantAction::ImportKey {
                key_path,
                backup,
                passphrase,
            } => tenant_cmds::cmd_tenant_import_key(key_path, backup, passphrase),
        },
        Command::Entry { action } => match action {
            EntryAction::Submit {
                hub_url,
                key_path,
                op,
                hostname,
                agent_id,
            } => entry_cmds::cmd_entry_submit(hub_url, key_path, &op, hostname, agent_id).await,
            EntryAction::List { hub_url, key_path } => {
                entry_cmds::cmd_entry_list(hub_url, key_path).await
            }
        },
        Command::Agent { action } => match action {
            AgentAction::Init { key_path } => {
                tenant_cmds::cmd_keypair_init(&key_path, "agent").await
            }
        },
        Command::Invite { action } => match action {
            InviteAction::Create {
                hub_url,
                api_key,
                name,
                hostnames,
                expires,
            } => invite_cmds::cmd_invite_create(hub_url, api_key, name, hostnames, expires).await,
            InviteAction::List { hub_url, api_key } => {
                invite_cmds::cmd_invite_list(hub_url, api_key).await
            }
            InviteAction::Revoke {
                hub_url,
                api_key,
                id,
            } => invite_cmds::cmd_invite_revoke(hub_url, api_key, id).await,
        },
        Command::EdgeInvite { action } => match action {
            EdgeInviteAction::Create {
                hub_url,
                api_key,
                name,
                expires,
            } => invite_cmds::cmd_edge_invite_create(hub_url, api_key, name, expires).await,
            EdgeInviteAction::List { hub_url, api_key } => {
                invite_cmds::cmd_edge_invite_list(hub_url, api_key).await
            }
            EdgeInviteAction::Revoke {
                hub_url,
                api_key,
                id,
            } => invite_cmds::cmd_edge_invite_revoke(hub_url, api_key, id).await,
        },
    }
}

fn load_state() -> ClientState {
    let paths = DefaultPaths::from_env();
    ClientState::load(&paths.state_file).unwrap_or_default()
}

pub(crate) fn resolve_hub_url(flag: Option<String>) -> anyhow::Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(HUB_URL_ENV) {
        return Ok(v);
    }
    if let Some(v) = load_state().hub_url {
        return Ok(v);
    }
    Err(anyhow!(
        "--hub-url not provided. Set it on the command line, or via ${HUB_URL_ENV}, \
         or run `turbo-agent init --invite <token>` to populate state.toml."
    ))
}

pub(crate) fn resolve_tenant_key_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Some(v) = load_state().tenant_key_path {
        return Ok(v);
    }
    Err(anyhow!(
        "--key-path not provided and state.toml has no tenant_key_path. \
         Run `turbo-agent init --invite <token>` to bootstrap, or create a \
         tenant key with `turbo-cli tenant init`."
    ))
}

pub(crate) fn resolve_operator_key(flag: Option<String>) -> anyhow::Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    std::env::var(OPERATOR_KEY_ENV).map_err(|_| {
        anyhow!(
            "no operator API key available. Pass --api-key <key> or export \
             ${OPERATOR_KEY_ENV}. The key is generated by turbo-node on first \
             run at the path configured in node.toml (default: ./operator.key)."
        )
    })
}

pub(crate) fn generate_and_save_agent_key(path: &Path) -> anyhow::Result<SigningKey> {
    let mut key_bytes = [0u8; 32];
    getrandom::fill(&mut key_bytes).expect("OS RNG failed");
    let key = SigningKey::from_bytes(&key_bytes);
    write_key_file(path, &key.to_bytes())
        .with_context(|| format!("failed to write key file: {}", path.display()))?;
    Ok(key)
}

pub(crate) fn short(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
