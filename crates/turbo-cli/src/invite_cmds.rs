use anyhow::{Context, anyhow};

use super::{JSON_CONTENT_TYPE, check_response, resolve_hub_url, resolve_operator_key, short};

#[derive(serde::Serialize)]
struct CreateInviteReq<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    hostnames: &'a [String],
    expires_in_secs: u64,
}

#[derive(serde::Deserialize)]
struct CreateInviteResp {
    token: String,
    invite_id: String,
    name: String,
    expires_at_ms: u64,
}

pub async fn cmd_invite_create(
    hub_url: Option<String>,
    api_key: Option<String>,
    name: Option<String>,
    hostnames: Vec<String>,
    expires: String,
) -> anyhow::Result<()> {
    if hostnames.is_empty() {
        return Err(anyhow!("--hostnames must have at least one entry"));
    }
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;
    let dur: std::time::Duration = humantime::parse_duration(&expires)
        .with_context(|| format!("invalid duration `{expires}` (examples: 24h, 48h, 7d)"))?;
    let expires_in_secs = dur.as_secs();
    if expires_in_secs == 0 {
        return Err(anyhow!("--expires must be > 0"));
    }

    let url = format!("{}/v1/invites", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .json(&CreateInviteReq {
            name: name.as_deref(),
            hostnames: &hostnames,
            expires_in_secs,
        })
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

    let body = check_response(resp).await?;
    let parsed: CreateInviteResp = serde_json::from_slice(&body)?;

    println!("Created invite for \"{}\"", parsed.name);
    println!("  Invite ID: {}", parsed.invite_id);
    println!("  Hostnames: {}", hostnames.join(", "));
    println!("  Expires:   {} (in {expires})", parsed.expires_at_ms);
    println!();
    println!("Send this token to the recipient (one-time use, keep it secret):");
    println!();
    println!("  {}", parsed.token);
    Ok(())
}

#[derive(serde::Deserialize)]
struct ListInvitesResp {
    invites: Vec<InviteItem>,
}

#[derive(serde::Deserialize)]
#[allow(clippy::struct_field_names)]
struct InviteItem {
    invite_id: String,
    name: String,
    status: String,
    expires_at_ms: u64,
}

pub async fn cmd_invite_list(
    hub_url: Option<String>,
    api_key: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/invites", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = check_response(resp).await?;
    let parsed: ListInvitesResp = serde_json::from_slice(&body)?;

    if parsed.invites.is_empty() {
        println!("No invites.");
        return Ok(());
    }
    println!("{:<24} {:<16} {:<10} EXPIRES_AT_MS", "ID", "NAME", "STATUS");
    for inv in parsed.invites {
        println!(
            "{:<24} {:<16} {:<10} {}",
            short(&inv.invite_id, 20),
            short(&inv.name, 14),
            inv.status,
            inv.expires_at_ms
        );
    }
    Ok(())
}

pub async fn cmd_invite_revoke(
    hub_url: Option<String>,
    api_key: Option<String>,
    id: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/invites/{id}", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .delete(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to DELETE {url}"))?;

    check_response(resp).await?;
    println!("Revoked invite {id}");
    Ok(())
}

#[derive(serde::Serialize)]
struct CreateEdgeInviteReq<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    expires_in_secs: u64,
}

#[derive(serde::Deserialize)]
struct CreateEdgeInviteResp {
    token: String,
    invite_id: String,
    name: String,
    expires_at_ms: u64,
}

#[derive(serde::Deserialize)]
struct ListEdgeInvitesResp {
    invites: Vec<EdgeInviteItem>,
}

#[derive(serde::Deserialize)]
#[allow(clippy::struct_field_names)]
struct EdgeInviteItem {
    invite_id: String,
    name: String,
    status: String,
    expires_at_ms: u64,
}

pub async fn cmd_edge_invite_create(
    hub_url: Option<String>,
    api_key: Option<String>,
    name: Option<String>,
    expires: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;
    let dur = humantime::parse_duration(&expires)
        .with_context(|| format!("invalid duration `{expires}`"))?;
    let expires_in_secs = dur.as_secs();
    if expires_in_secs == 0 {
        return Err(anyhow!("--expires must be > 0"));
    }

    let url = format!("{}/v1/edge-invites", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .json(&CreateEdgeInviteReq {
            name: name.as_deref(),
            expires_in_secs,
        })
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

    let body = check_response(resp).await?;
    let parsed: CreateEdgeInviteResp = serde_json::from_slice(&body)?;

    println!("Created edge invite for \"{}\"", parsed.name);
    println!("  Invite ID: {}", parsed.invite_id);
    println!("  Expires:   {} (in {expires})", parsed.expires_at_ms);
    println!();
    println!("Send this token to the VPS operator (one-time use):");
    println!();
    println!("  {}", parsed.token);
    Ok(())
}

pub async fn cmd_edge_invite_list(
    hub_url: Option<String>,
    api_key: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/edge-invites", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = check_response(resp).await?;
    let parsed: ListEdgeInvitesResp = serde_json::from_slice(&body)?;

    if parsed.invites.is_empty() {
        println!("No edge invites.");
        return Ok(());
    }
    println!("{:<24} {:<20} {:<10} EXPIRES_AT_MS", "ID", "NAME", "STATUS");
    for inv in &parsed.invites {
        println!(
            "{:<24} {:<20} {:<10} {}",
            short(&inv.invite_id, 20),
            short(&inv.name, 18),
            inv.status,
            inv.expires_at_ms
        );
    }
    Ok(())
}

pub async fn cmd_edge_invite_revoke(
    hub_url: Option<String>,
    api_key: Option<String>,
    id: String,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url)?;
    let api_key = resolve_operator_key(api_key)?;

    let url = format!("{}/v1/edge-invites/{id}", hub_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .delete(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to DELETE {url}"))?;

    check_response(resp).await?;
    println!("Revoked edge invite {id}");
    Ok(())
}
