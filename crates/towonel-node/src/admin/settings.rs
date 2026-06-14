use anyhow::Context;

use super::{JSON_CONTENT_TYPE, check_response, resolve_hub_url, resolve_operator_key};

#[derive(serde::Deserialize)]
struct QuotaResp {
    value: i64,
}

#[derive(serde::Serialize)]
struct UpdateQuotaReq {
    value: i64,
}

pub async fn cmd_get_port_quota(
    hub_url: Option<String>,
    api_key: Option<String>,
) -> anyhow::Result<()> {
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!(
        "{}/v1/settings/user-port-quota",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&api_key)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;

    let body = check_response(resp).await?;
    let parsed: QuotaResp = serde_json::from_slice(&body)?;

    println!("User port quota: {}", parsed.value);
    Ok(())
}

pub async fn cmd_set_port_quota(
    hub_url: Option<String>,
    api_key: Option<String>,
    value: i64,
) -> anyhow::Result<()> {
    if value < 0 {
        return Err(anyhow::anyhow!("--value must be >= 0"));
    }
    let hub_url = resolve_hub_url(hub_url);
    let api_key = resolve_operator_key(api_key)?;

    let url = format!(
        "{}/v1/settings/user-port-quota",
        hub_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .put(&url)
        .bearer_auth(&api_key)
        .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .json(&UpdateQuotaReq { value })
        .send()
        .await
        .with_context(|| format!("failed to PUT {url}"))?;

    let body = check_response(resp).await?;
    let parsed: QuotaResp = serde_json::from_slice(&body)?;

    println!("User port quota set to {}", parsed.value);
    Ok(())
}
