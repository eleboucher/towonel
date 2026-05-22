use std::time::Duration;

use anyhow::Result;
use towonel_common::config_entry::ConfigOp;

use crate::ops_client::OpsClient;
use crate::poll;

pub async fn run(ops: &OpsClient, tenant_id: &str, expected_hostname: &str) -> Result<()> {
    let target = expected_hostname.to_string();
    let tenant = tenant_id.to_string();

    poll::poll_until(
        Duration::from_millis(500),
        Duration::from_mins(1),
        "agent_registration",
        || {
            let target = target.clone();
            let tenant = tenant.clone();
            async move {
                let resp = ops.list_entries(&tenant).await?;
                let found = resp.entries.iter().any(|e| match &e.op {
                    ConfigOp::UpsertHostname { hostname } => hostname == &target,
                    _ => false,
                });
                Ok(if found { Some(()) } else { None })
            }
        },
    )
    .await?;

    tracing::info!(hostname = %expected_hostname, "agent_registration: PASS");
    Ok(())
}
