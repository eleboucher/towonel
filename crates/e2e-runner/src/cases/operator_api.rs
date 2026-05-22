use anyhow::{Context, Result, anyhow};

use crate::ops_client::OpsClient;

pub async fn run(ops: &OpsClient) -> Result<()> {
    let health = ops.raw_get("/v1/health").await?;
    if !health.status().is_success() {
        return Err(anyhow!("/v1/health returned {}", health.status()));
    }

    let unauth = ops
        .raw_post_unauth(
            "/v1/invites",
            serde_json::json!({"hostnames": ["unauth.e2e.local"]}),
        )
        .await?;
    if unauth.status().is_success() {
        return Err(anyhow!(
            "unauth POST /v1/invites returned {} — operator auth bypass",
            unauth.status()
        ));
    }

    let edges = ops.raw_get("/v1/edges").await?;
    if !edges.status().is_success() {
        return Err(anyhow!("/v1/edges returned {}", edges.status()));
    }
    let bytes = edges.bytes().await?;
    let _: serde_json::Value = serde_json::from_slice(&bytes).context("/v1/edges body")?;

    tracing::info!("operator_api: PASS");
    Ok(())
}
