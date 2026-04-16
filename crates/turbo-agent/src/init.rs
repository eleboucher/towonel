use std::path::Path;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use turbo_common::client_state::{ClientState, DefaultPaths};
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::{AgentId, AgentKeypair, TenantKeypair};
use turbo_common::invite::InviteToken;

const CBOR_CONTENT_TYPE: &str = "application/cbor";

pub async fn run(invite_str: &str, out: Option<&Path>) -> anyhow::Result<()> {
    let token = InviteToken::decode(invite_str).context("invalid invite token")?;
    println!("Contacting hub at {}...", token.hub_url);

    let defaults = DefaultPaths::from_env();
    std::fs::create_dir_all(&defaults.state_dir)?;

    let tenant_kp = load_or_generate_tenant_keypair(&defaults.tenant_key)?;
    let agent_kp = load_or_generate_agent_keypair(&defaults.agent_key)?;
    let tenant_id = tenant_kp.id();
    let agent_id = agent_kp.id();

    println!();
    println!("Generated keypairs:");
    println!("  Tenant ID: {tenant_id}");
    println!("  Agent ID:  {agent_id}");
    println!("  Keys:      {} (0600)", defaults.state_dir.display());
    println!();

    let client = reqwest::Client::new();

    let redeem_req = RedeemRequest {
        invite_id: B64.encode(token.invite_id),
        invite_secret: B64.encode(token.invite_secret),
        tenant_pq_public_key: tenant_kp.public_key().to_string(),
        agent_node_id: agent_id.to_string(),
    };
    let redeem_url = format!("{}/v1/invites/redeem", token.hub_url.trim_end_matches('/'));
    let resp = client
        .post(&redeem_url)
        .json(&redeem_req)
        .send()
        .await
        .with_context(|| format!("failed to POST {redeem_url}"))?;

    let status = resp.status();
    let body = resp.bytes().await?;
    if !status.is_success() {
        let err: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        return Err(anyhow!(
            "hub returned {status}: {}",
            serde_json::to_string_pretty(&err)?
        ));
    }
    let redeemed: RedeemResponse =
        serde_json::from_slice(&body).context("hub returned malformed redemption response")?;

    println!("Registered as tenant {}", redeemed.tenant_id);
    println!("Pre-approved hostnames:");
    for h in &redeemed.hostnames {
        println!("  - {h}");
    }
    println!(
        "Edge node id: {}",
        redeemed.edge_node_id.as_deref().unwrap_or("(none)")
    );
    println!();

    let mut seq = 0;
    for hostname in &redeemed.hostnames {
        seq += 1;
        let payload = make_payload(
            &tenant_kp,
            seq,
            ConfigOp::UpsertHostname {
                hostname: hostname.clone(),
            },
        );
        submit_entry(&client, &token.hub_url, &tenant_kp, payload).await?;
        println!("✓ UpsertHostname `{hostname}` (seq {seq})");
    }
    seq += 1;
    let payload = make_payload(
        &tenant_kp,
        seq,
        ConfigOp::UpsertAgent {
            agent_id: AgentId::from_key(*agent_kp.id().as_key()),
        },
    );
    submit_entry(&client, &token.hub_url, &tenant_kp, payload).await?;
    println!("✓ UpsertAgent {agent_id} (seq {seq})");
    println!();

    let state = ClientState {
        hub_url: Some(token.hub_url.clone()),
        tenant_key_path: Some(defaults.tenant_key.clone()),
        agent_key_path: Some(defaults.agent_key.clone()),
        trusted_edges: redeemed.edge_node_id.iter().cloned().collect(),
        tenant_id: Some(tenant_id.to_string()),
    };
    state.save(&defaults.state_file)?;
    println!("State:  {}", defaults.state_file.display());

    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or(defaults.agent_config.clone());
    write_agent_config_template(&out_path, &redeemed.hostnames, &redeemed.edge_addresses)?;
    println!("Config: {}", out_path.display());

    println!();
    println!("Next steps:");
    println!(
        "  1. Edit {} and add your services under [[services]].",
        out_path.display()
    );
    println!("  2. Point DNS for your hostname(s) at an edge IP:");
    for addr in &redeemed.edge_addresses {
        println!("       {addr}");
    }
    println!("  3. Start the agent: turbo-agent");
    Ok(())
}

fn load_or_generate_tenant_keypair(path: &Path) -> anyhow::Result<TenantKeypair> {
    turbo_common::identity::load_or_generate_tenant_keypair(path)
}

fn load_or_generate_agent_keypair(path: &Path) -> anyhow::Result<AgentKeypair> {
    let signing_key = turbo_common::identity::load_or_generate_signing_key(path)?;
    Ok(AgentKeypair::from_signing_key(signing_key))
}

fn make_payload(kp: &TenantKeypair, seq: u64, op: ConfigOp) -> ConfigPayload {
    ConfigPayload {
        version: 1,
        tenant_id: kp.id(),
        sequence: seq,
        timestamp: turbo_common::time::now_ms(),
        op,
    }
}

pub(super) async fn submit_entry(
    client: &reqwest::Client,
    hub_url: &str,
    kp: &TenantKeypair,
    payload: ConfigPayload,
) -> anyhow::Result<()> {
    let entry = SignedConfigEntry::sign(&payload, kp)?;
    let mut body = Vec::new();
    ciborium::into_writer(&entry, &mut body)?;

    let url = format!("{}/v1/entries", hub_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

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

pub(super) fn write_agent_config_template(
    path: &Path,
    hostnames: &[String],
    edge_addrs: &[String],
) -> anyhow::Result<()> {
    if path.exists() {
        // Never overwrite a user's edits.
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut content = String::new();
    content.push_str("# Auto-generated by `turbo-agent init`. The fields needed to run\n");
    content.push_str("# (keys, trusted edges, hub URL) live in ~/.turbo-tunnel/state.toml.\n");
    content.push_str("# Add your services below and run `turbo-agent` to start.\n\n");
    for h in hostnames {
        content.push_str("# [[services]]\n");
        content.push_str(&format!("# hostname = \"{h}\"\n"));
        content.push_str("# origin = \"127.0.0.1:8080\"\n\n");
    }
    if !edge_addrs.is_empty() {
        content.push_str("# Edge addresses (for reference, DNS target):\n");
        for addr in edge_addrs {
            content.push_str(&format!("# - {addr}\n"));
        }
    }
    std::fs::write(path, content)?;
    Ok(())
}

#[derive(Serialize)]
struct RedeemRequest {
    invite_id: String,
    invite_secret: String,
    /// Base64url-encoded ML-DSA-65 public key. The hub derives the tenant_id
    /// from this (see `POST /v1/invites/redeem`).
    tenant_pq_public_key: String,
    agent_node_id: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RedeemResponse {
    status: String,
    tenant_id: String,
    hostnames: Vec<String>,
    hub_node_id: String,
    edge_node_id: Option<String>,
    edge_addresses: Vec<String>,
}
