//! `turbo-agent add-agent`: authorize a new agent for an existing tenant.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use turbo_common::client_state::DefaultPaths;
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::{AgentId, AgentKeypair, PqPublicKey, TenantId};

use crate::init::{submit_entry, write_agent_config_template};

pub async fn run(
    tenant_key_path: &Path,
    agent_key_path: Option<&Path>,
    hub_url: &str,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let defaults = DefaultPaths::from_env();

    let tenant_kp = turbo_common::identity::load_tenant_keypair(tenant_key_path).context(
        "copy the seed from your first machine (scp / USB / whatever you trust) \
             before running add-agent",
    )?;
    let tenant_id = tenant_kp.id();

    let agent_key_path: PathBuf = agent_key_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| defaults.agent_key.clone());
    if agent_key_path.exists() {
        return Err(anyhow!(
            "agent key file {} already exists. Pass --agent-key to a fresh \
             path so you don't clobber the existing agent's identity.",
            agent_key_path.display()
        ));
    }
    if let Some(parent) = agent_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let agent_signing_key = turbo_common::identity::load_or_generate_signing_key(&agent_key_path)
        .with_context(|| {
        format!("failed to create agent key at {}", agent_key_path.display())
    })?;
    let agent_kp = AgentKeypair::from_signing_key(agent_signing_key);
    let agent_id = agent_kp.id();

    println!("Generated agent keypair:");
    println!("  Agent ID:  {agent_id}");
    println!("  Key saved: {} (0600)", agent_key_path.display());
    println!();

    let client = reqwest::Client::new();
    let existing = fetch_entries(&client, hub_url, &tenant_id).await?;

    let pq_pubkey = tenant_kp.public_key();
    let latest_seq = existing
        .iter()
        .filter_map(|e| e.verify(pq_pubkey).ok())
        .map(|p| p.sequence)
        .max()
        .unwrap_or(0);

    let hostnames = materialized_hostnames(&existing, pq_pubkey);

    let payload = ConfigPayload {
        version: 1,
        tenant_id,
        sequence: latest_seq + 1,
        timestamp: turbo_common::time::now_ms(),
        op: ConfigOp::UpsertAgent {
            agent_id: AgentId::from_key(*agent_kp.id().as_key()),
        },
    };
    submit_entry(&client, hub_url, &tenant_kp, payload).await?;

    println!("Submitting UpsertAgent entry...");
    println!("✓ Agent authorized (sequence {})", latest_seq + 1);
    println!();

    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| defaults.agent_config.clone());
    write_agent_config_template(&out_path, &hostnames, &[])?;
    println!("Config: {}", out_path.display());
    println!(
        "Next:   edit the [[services]] block and run `turbo-agent --config {}`.",
        out_path.display()
    );
    Ok(())
}

/// Fetch all signed entries the hub has for `tenant_id`. Empty list if the
/// tenant is unknown (same as `/v1/tenants/{id}/entries` §4.4).
async fn fetch_entries(
    client: &reqwest::Client,
    hub_url: &str,
    tenant_id: &TenantId,
) -> anyhow::Result<Vec<SignedConfigEntry>> {
    let url = format!(
        "{}/v1/tenants/{tenant_id}/entries",
        hub_url.trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/cbor")
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = crate::init::check_response(resp).await?;

    let entries: Vec<SignedConfigEntry> = ciborium::from_reader(body.as_ref())
        .with_context(|| format!("hub returned invalid CBOR at {url}"))?;
    Ok(entries)
}

/// Replay the tenant's entries to find hostnames currently claimed. Used
/// to pre-populate the starter config. `pq_pubkey` is the tenant's own
/// key (the entries are always ours, since the hub filters by tenant_id).
fn materialized_hostnames(entries: &[SignedConfigEntry], pq_pubkey: &PqPublicKey) -> Vec<String> {
    let mut claimed: std::collections::BTreeSet<String> = Default::default();
    for entry in entries {
        let Ok(payload) = entry.verify(pq_pubkey) else {
            continue;
        };
        match payload.op {
            ConfigOp::UpsertHostname { hostname } => {
                claimed.insert(hostname);
            }
            ConfigOp::DeleteHostname { hostname } => {
                claimed.remove(&hostname);
            }
            _ => {}
        }
    }
    claimed.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use turbo_common::identity::TenantKeypair;

    fn sign(kp: &TenantKeypair, seq: u64, op: ConfigOp) -> SignedConfigEntry {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: kp.id(),
            sequence: seq,
            timestamp: 1_700_000_000_000 + seq,
            op,
        };
        SignedConfigEntry::sign(&payload, kp).unwrap()
    }

    #[test]
    fn materialized_hostnames_replays_upserts_and_deletes() {
        let kp = TenantKeypair::generate();

        let entries = vec![
            sign(
                &kp,
                1,
                ConfigOp::UpsertHostname {
                    hostname: "a.test".into(),
                },
            ),
            sign(
                &kp,
                2,
                ConfigOp::UpsertHostname {
                    hostname: "b.test".into(),
                },
            ),
            sign(
                &kp,
                3,
                ConfigOp::DeleteHostname {
                    hostname: "a.test".into(),
                },
            ),
            // Non-hostname ops are ignored.
            sign(
                &kp,
                4,
                ConfigOp::UpsertAgent {
                    agent_id: AgentKeypair::generate().id(),
                },
            ),
            sign(
                &kp,
                5,
                ConfigOp::UpsertHostname {
                    hostname: "c.test".into(),
                },
            ),
        ];

        let result = materialized_hostnames(&entries, kp.public_key());
        assert_eq!(result, vec!["b.test".to_string(), "c.test".to_string()]);
    }

    #[test]
    fn materialized_hostnames_empty_input() {
        let kp = TenantKeypair::from_seed([7u8; 32]);
        assert!(materialized_hostnames(&[], kp.public_key()).is_empty());
    }
}
