use anyhow::Context;
use tabled::{Table, Tabled, settings::Style};

use super::{JSON_CONTENT_TYPE, check_response, resolve_hub_url, resolve_operator_key};

#[derive(serde::Serialize)]
struct ReserveReq<'a> {
    protocol: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct ReserveResp {
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
}

pub async fn cmd_port_reserve(
    hub_url: Option<String>,
    api_key: Option<String>,
    tenant_id: String,
    protocol: String,
    port: Option<u16>,
    label: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!(
        "{}/v1/tenants/{tenant_id}/ports",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .json(&ReserveReq {
            protocol: &protocol,
            preferred: port,
            label: label.as_deref(),
        })
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

    let body = check_response(resp).await?;
    let parsed: ReserveResp = serde_json::from_slice(&body)?;

    println!("Reserved {} port {}", parsed.protocol, parsed.port);
    if let Some(ip) = parsed.ip {
        println!("  IP:    {ip}");
    } else {
        println!("  IP:    (shared)");
    }
    if let Some(label) = parsed.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_port_release(
    hub_url: Option<String>,
    api_key: Option<String>,
    tenant_id: String,
    protocol: String,
    port: u16,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!(
        "{}/v1/tenants/{tenant_id}/ports/{protocol}/{port}",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .delete(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to DELETE {url}"))?;

    check_response(resp).await?;
    println!("Released {protocol} port {port}");
    Ok(())
}

#[derive(serde::Deserialize)]
struct ListResp {
    ports: Vec<PortItem>,
}

#[derive(serde::Deserialize)]
struct PortItem {
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
    claimed_at_ms: u64,
}

#[derive(Tabled)]
struct PortRow<'a> {
    #[tabled(rename = "PROTO")]
    protocol: &'a str,
    #[tabled(rename = "PORT")]
    port: u16,
    #[tabled(rename = "IP")]
    ip: &'a str,
    #[tabled(rename = "LABEL")]
    label: &'a str,
    #[tabled(rename = "CLAIMED_AT_MS")]
    claimed_at_ms: u64,
}

pub async fn cmd_port_list(
    hub_url: Option<String>,
    api_key: Option<String>,
    tenant_id: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!(
        "{}/v1/tenants/{tenant_id}/ports",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = check_response(resp).await?;
    let parsed: ListResp = serde_json::from_slice(&body)?;

    if parsed.ports.is_empty() {
        println!("No port reservations.");
        return Ok(());
    }

    let table = Table::new(parsed.ports.iter().map(|p| PortRow {
        protocol: &p.protocol,
        port: p.port,
        ip: p.ip.as_deref().unwrap_or("(shared)"),
        label: p.label.as_deref().unwrap_or(""),
        claimed_at_ms: p.claimed_at_ms,
    }))
    .with(Style::blank())
    .to_string();
    println!("{table}");
    Ok(())
}
