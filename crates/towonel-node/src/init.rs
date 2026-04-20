use std::path::PathBuf;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::invite::EdgeInviteToken;

const DEFAULT_NODE_KEY: &str = "/var/lib/towonel/node.key";

pub async fn run(invite_str: &str) -> anyhow::Result<()> {
    let token = EdgeInviteToken::decode(invite_str).context("invalid edge invite token")?;
    println!("Contacting hub at {}...", token.hub_url);

    let key_path = PathBuf::from(DEFAULT_NODE_KEY);

    let secret_key = towonel_common::identity::load_or_generate_secret_key(&key_path)
        .with_context(|| format!("failed to load/generate node key at {}", key_path.display()))?;
    let node_id = secret_key.public();

    println!();
    println!("Generated node keypair:");
    println!("  Node ID:   {node_id}");
    println!("  Key saved: {} (0600)", key_path.display());
    println!();

    let redeem_url = format!(
        "{}/v1/edge-invites/redeem",
        token.hub_url.trim_end_matches('/')
    );
    let req = RedeemRequest {
        invite_id: B64.encode(token.invite_id),
        invite_secret: B64.encode(token.invite_secret),
        edge_node_id: node_id.to_string(),
    };
    let resp = reqwest::Client::new()
        .post(&redeem_url)
        .json(&req)
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
    println!("Registered as edge node \"{}\".", redeemed.name);
    println!();
    print_env(&key_path, &token.hub_url);
    Ok(())
}

fn print_env(key_path: &std::path::Path, hub_url: &str) {
    let hub_url = hub_url.trim_end_matches('/');
    println!("Set these environment variables to run the edge:");
    println!();
    println!("  TOWONEL_IDENTITY_KEY_PATH={}", key_path.display());
    println!("  TOWONEL_HUB_ENABLED=false");
    println!("  TOWONEL_EDGE_ENABLED=true");
    println!("  TOWONEL_EDGE_LISTEN_ADDR=0.0.0.0:443");
    println!("  TOWONEL_EDGE_HUB_URLS={hub_url}");
    println!();
    println!("Start the edge:");
    println!("  towonel-node");
}

#[derive(Serialize)]
struct RedeemRequest {
    invite_id: String,
    invite_secret: String,
    edge_node_id: String,
}

#[derive(Deserialize)]
struct RedeemResponse {
    name: String,
}
