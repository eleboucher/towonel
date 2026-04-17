use std::path::PathBuf;

use anyhow::{Context, anyhow};
use towonel_common::config_entry::ConfigOp;
use towonel_common::identity::{AgentId, load_tenant_keypair, write_key_file};

use super::entry_cmds::{fetch_entries, submit_payload};
use super::{check_response, resolve_hub_url, resolve_operator_key, resolve_tenant_key_path};

const KEY_BACKUP_PREFIX: &str = "towonel-key-v1:";
const ARGON2_SALT_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;

fn read_passphrase(prompt: &str) -> anyhow::Result<String> {
    let passphrase = rpassword::prompt_password_stderr(prompt)
        .context("failed to read passphrase from terminal")?;
    if passphrase.trim().is_empty() {
        return Err(anyhow!("passphrase must not be empty"));
    }
    Ok(passphrase)
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon2::Argon2::default()
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

// No await inside but matches the async interface of the other command handlers.
#[allow(clippy::unused_async)]
pub async fn cmd_keypair_init(key_path: &std::path::Path, kind: &str) -> anyhow::Result<()> {
    match kind {
        "tenant" => {
            if key_path.exists() {
                return Err(anyhow!(
                    "tenant key file {} already exists; refusing to overwrite",
                    key_path.display()
                ));
            }
            let kp = towonel_common::identity::load_or_generate_tenant_keypair(key_path)
                .with_context(|| {
                    format!("failed to generate tenant key at {}", key_path.display())
                })?;
            println!("Generated tenant keypair");
            println!("  Private key:    {}", key_path.display());
            println!("  Tenant ID:      {}", kp.id());
            println!("  PQ public key:  {}", kp.public_key());
            println!();
            println!("Paste the two lines above into your operator's node.toml as:");
            println!();
            println!("  [[tenants]]");
            println!("  id = \"{}\"", kp.id());
            println!("  pq_public_key = \"{}\"", kp.public_key());
        }
        "agent" => {
            let key = super::generate_and_save_agent_key(key_path)?;
            let kp = towonel_common::identity::AgentKeypair::from_signing_key(key);
            println!("Generated agent keypair");
            println!("  Private key: {}", key_path.display());
            println!("  Agent ID:    {}", kp.id());
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub async fn cmd_tenant_leave(
    key_path: Option<PathBuf>,
    hub_url: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let key_path = resolve_tenant_key_path(key_path)?;
    let keypair = load_tenant_keypair(&key_path)?;
    let tenant_id = keypair.id();
    let pq_pubkey = keypair.public_key();

    let entries = fetch_entries(&hub_url, &tenant_id).await?;
    let mut latest_seq = 0u64;
    let mut owned_hostnames: std::collections::HashSet<String> =
        std::collections::HashSet::default();
    let mut authorized_agents: std::collections::HashSet<AgentId> =
        std::collections::HashSet::default();

    for entry in &entries {
        let Ok(payload) = entry.verify(pq_pubkey) else {
            continue;
        };
        latest_seq = latest_seq.max(payload.sequence);
        match payload.op {
            ConfigOp::UpsertHostname { hostname } => {
                owned_hostnames.insert(hostname);
            }
            ConfigOp::DeleteHostname { hostname } => {
                owned_hostnames.remove(&hostname);
            }
            ConfigOp::UpsertAgent { agent_id } => {
                authorized_agents.insert(agent_id);
            }
            ConfigOp::RevokeAgent { agent_id } => {
                authorized_agents.remove(&agent_id);
            }
            ConfigOp::SetHostnameTls { .. } => {}
        }
    }

    if owned_hostnames.is_empty() && authorized_agents.is_empty() {
        println!("No hostnames or agents to release for tenant {tenant_id}.");
        return Ok(());
    }

    println!("This will:");
    for h in &owned_hostnames {
        println!("  - DeleteHostname {h}");
    }
    for a in &authorized_agents {
        println!("  - RevokeAgent {a}");
    }

    let mut seq = latest_seq;
    for h in owned_hostnames {
        seq += 1;
        submit_payload(
            &hub_url,
            &keypair,
            seq,
            ConfigOp::DeleteHostname {
                hostname: h.clone(),
            },
        )
        .await?;
        println!("✓ DeleteHostname {h} (seq {seq})");
    }
    for a in authorized_agents {
        seq += 1;
        submit_payload(
            &hub_url,
            &keypair,
            seq,
            ConfigOp::RevokeAgent {
                agent_id: a.clone(),
            },
        )
        .await?;
        println!("✓ RevokeAgent {a} (seq {seq})");
    }

    println!();
    println!("Done. You may now delete ~/.towonel/ on this machine.");
    Ok(())
}

pub async fn cmd_tenant_remove(
    hub_url: Option<String>,
    api_key: Option<String>,
    tenant_id: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let tenant: towonel_common::identity::TenantId = tenant_id
        .parse()
        .with_context(|| format!("invalid tenant_id: {tenant_id}"))?;

    let url = format!("{}/v1/tenants/{tenant}", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .delete(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to DELETE {url}"))?;

    check_response(resp).await?;
    println!("Removed tenant {tenant}");
    println!("  Their signed entries remain in the database but are no longer routed.");
    Ok(())
}

pub fn cmd_tenant_export_key(
    key_path: Option<PathBuf>,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    let key_path = resolve_tenant_key_path(key_path)?;
    let keypair = load_tenant_keypair(&key_path)?;
    let seed = keypair.seed();

    let passphrase = match passphrase {
        Some(p) => p,
        None => read_passphrase("Passphrase: ")?,
    };

    let mut salt = [0u8; ARGON2_SALT_LEN];
    // OS RNG failures are unrecoverable on any supported platform.
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut salt).expect("OS RNG failed");

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut nonce_bytes).expect("OS RNG failed");

    let enc_key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(enc_key.as_slice())
        .map_err(|e| anyhow!("AES-256-GCM init failed: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + AES_GCM_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let encoded = format!("{KEY_BACKUP_PREFIX}{}", B64.encode(&blob));

    println!("Encrypted tenant key backup (store this securely):\n");
    println!("  {encoded}");
    println!();
    println!("Tenant ID: {}", keypair.id());
    println!(
        "Restore with: towonel-cli tenant import-key --backup '{encoded}' --key-path tenant.key"
    );
    Ok(())
}

pub fn cmd_tenant_import_key(
    key_path: PathBuf,
    backup: String,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    #![allow(clippy::needless_pass_by_value)]
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    if key_path.exists() {
        return Err(anyhow!(
            "key file {} already exists; refusing to overwrite",
            key_path.display()
        ));
    }

    let encoded = backup
        .strip_prefix(KEY_BACKUP_PREFIX)
        .ok_or_else(|| anyhow!("backup string must start with `{KEY_BACKUP_PREFIX}`"))?;

    let blob = B64
        .decode(encoded.trim())
        .context("invalid base64 in backup string")?;

    let min_len = ARGON2_SALT_LEN + AES_GCM_NONCE_LEN + 32 + 16; // seed + tag
    if blob.len() < min_len {
        return Err(anyhow!(
            "backup blob too short ({} bytes, expected at least {min_len})",
            blob.len()
        ));
    }

    let salt = &blob[..ARGON2_SALT_LEN];
    let nonce_bytes = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + AES_GCM_NONCE_LEN];
    let ciphertext = &blob[ARGON2_SALT_LEN + AES_GCM_NONCE_LEN..];

    let passphrase = match passphrase {
        Some(p) => p,
        None => read_passphrase("Passphrase: ")?,
    };

    let enc_key = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new_from_slice(enc_key.as_slice())
        .map_err(|e| anyhow!("AES-256-GCM init failed: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let seed_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed -- wrong passphrase?"))?;

    if seed_bytes.len() != 32 {
        return Err(anyhow!(
            "decrypted seed has wrong length ({}, expected 32)",
            seed_bytes.len()
        ));
    }

    write_key_file(&key_path, &seed_bytes)
        .with_context(|| format!("failed to write key to {}", key_path.display()))?;

    // SAFETY: we verified seed_bytes.len() == 32 above, so try_into() is infallible.
    #[allow(clippy::unwrap_used)]
    let seed: [u8; 32] = seed_bytes.try_into().unwrap();
    let kp = towonel_common::identity::TenantKeypair::from_seed(seed);
    println!("Restored tenant key to {}", key_path.display());
    println!("  Tenant ID:     {}", kp.id());
    println!("  PQ public key: {}", kp.public_key());
    Ok(())
}
