use anyhow::Context;
use tabled::{Table, Tabled, settings::Style};

use super::{check_response, resolve_hub_url, resolve_operator_key};

#[derive(serde::Deserialize)]
struct ListEdgesResp {
    edges: Vec<EdgeItem>,
}

#[derive(serde::Deserialize)]
struct EdgeItem {
    node_id: String,
    addresses: Vec<String>,
}

#[derive(Tabled)]
struct EdgeRow<'a> {
    #[tabled(rename = "NODE_ID")]
    node_id: &'a str,
    #[tabled(rename = "ADDRESSES")]
    addresses: String,
}

pub async fn cmd_edge_list(hub_url: Option<String>, api_key: Option<String>) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/edges", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = check_response(resp).await?;
    let parsed: ListEdgesResp = serde_json::from_slice(&body)?;

    if parsed.edges.is_empty() {
        println!("No edges registered.");
        return Ok(());
    }

    let table = Table::new(parsed.edges.iter().map(|e| EdgeRow {
        node_id: &e.node_id,
        addresses: if e.addresses.is_empty() {
            "-".to_string()
        } else {
            e.addresses.join(", ")
        },
    }))
    .with(Style::blank())
    .to_string();
    println!("{table}");
    Ok(())
}
