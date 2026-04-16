use std::path::PathBuf;

use anyhow::{Context, anyhow};
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::{AgentId, TenantKeypair, load_tenant_keypair};

use turbo_common::time::now_ms;

use super::{CBOR_CONTENT_TYPE, resolve_hub_url, resolve_tenant_key_path};

pub(crate) async fn fetch_entries(
    hub_url: &str,
    tenant_id: &turbo_common::identity::TenantId,
) -> anyhow::Result<Vec<SignedConfigEntry>> {
    let url = format!(
        "{}/v1/tenants/{tenant_id}/entries",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .header(reqwest::header::ACCEPT, CBOR_CONTENT_TYPE)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let status = resp.status();
    let body = resp.bytes().await?;

    if !status.is_success() {
        let err: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        return Err(anyhow!(
            "hub returned {status}: {}",
            serde_json::to_string_pretty(&err)?
        ));
    }

    let entries: Vec<SignedConfigEntry> = ciborium::from_reader(body.as_ref())
        .with_context(|| format!("hub returned invalid CBOR at {url}"))?;
    Ok(entries)
}

pub(crate) async fn submit_payload(
    hub_url: &str,
    keypair: &TenantKeypair,
    sequence: u64,
    op: ConfigOp,
) -> anyhow::Result<()> {
    let payload = ConfigPayload {
        version: 1,
        tenant_id: keypair.id(),
        sequence,
        timestamp: now_ms(),
        op,
    };

    let entry = SignedConfigEntry::sign(&payload, keypair)?;
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body)?;

    let post_url = format!("{}/v1/entries", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&post_url)
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to POST {post_url}"))?;

    let status = resp.status();
    let resp_body = resp.bytes().await?;
    if !status.is_success() {
        let err: serde_json::Value = serde_json::from_slice(&resp_body).unwrap_or_default();
        return Err(anyhow!(
            "hub returned {status}: {}",
            serde_json::to_string_pretty(&err)?
        ));
    }
    Ok(())
}

pub(crate) async fn cmd_entry_submit(
    hub_url: Option<String>,
    key_path: Option<PathBuf>,
    op_str: &str,
    hostname: Option<String>,
    agent_id_hex: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let key_path = resolve_tenant_key_path(key_path)?;
    let keypair = load_tenant_keypair(&key_path)?;
    let tenant_id = keypair.id();
    let pq_pubkey = keypair.public_key();

    let latest_seq = fetch_entries(&hub_url, &tenant_id)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry.verify(pq_pubkey).ok())
        .map(|payload| payload.sequence)
        .max()
        .unwrap_or(0);

    let op = match op_str {
        "upsert-hostname" => ConfigOp::UpsertHostname {
            hostname: hostname.context("--hostname is required for upsert-hostname")?,
        },
        "delete-hostname" => ConfigOp::DeleteHostname {
            hostname: hostname.context("--hostname is required for delete-hostname")?,
        },
        "upsert-agent" => {
            let id_str = agent_id_hex.context("--agent-id is required for upsert-agent")?;
            let id: AgentId = id_str
                .parse()
                .with_context(|| format!("invalid agent id: {id_str}"))?;
            ConfigOp::UpsertAgent { agent_id: id }
        }
        "revoke-agent" => {
            let id_str = agent_id_hex.context("--agent-id is required for revoke-agent")?;
            let id: AgentId = id_str
                .parse()
                .with_context(|| format!("invalid agent id: {id_str}"))?;
            ConfigOp::RevokeAgent { agent_id: id }
        }
        other => {
            return Err(anyhow!(
                "unknown op: {other}. expected: upsert-hostname, delete-hostname, upsert-agent, revoke-agent"
            ));
        }
    };

    submit_payload(&hub_url, &keypair, latest_seq + 1, op).await?;
    println!("Entry submitted successfully (sequence {})", latest_seq + 1);
    Ok(())
}

pub(crate) async fn cmd_entry_list(
    hub_url: Option<String>,
    key_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let key_path = resolve_tenant_key_path(key_path)?;
    let keypair = load_tenant_keypair(&key_path)?;
    let tenant_id = keypair.id();
    let pq_pubkey = keypair.public_key();

    let entries = fetch_entries(&hub_url, &tenant_id).await?;

    if entries.is_empty() {
        println!("No entries found for tenant {tenant_id}");
        return Ok(());
    }

    for entry in &entries {
        match entry.verify(pq_pubkey) {
            Ok(payload) => println!(
                "  seq={} ts={} op={:?}",
                payload.sequence, payload.timestamp, payload.op
            ),
            Err(e) => println!("  (unverifiable entry: {e})"),
        }
    }

    Ok(())
}
