use backon::BackoffBuilder;
use towonel_common::config_entry::{ConfigOp, ConfigPayload};
use towonel_common::identity::TenantKeypair;
use tracing::{info, warn};

use crate::config::ServiceConfig;
use crate::hub_client::{
    fetch_latest_sequence, is_rate_limited, is_sequence_conflict, retry_on_rate_limit, submit_entry,
};
use crate::retry::operation_backoff;

/// Publish per-service TLS policy entries so the edge knows which
/// hostnames it should terminate vs pass-through. Sequence numbers are
/// allocated after the agent's own `UpsertAgent` registration.
///
/// Uses the caller's `reqwest::Client` so the connection pool and timeout
/// configuration are shared with the bootstrap and heartbeat paths.
pub async fn publish(
    client: &reqwest::Client,
    hub_url: &str,
    tenant_kp: &TenantKeypair,
    services: &[ServiceConfig],
) -> anyhow::Result<()> {
    if services.is_empty() {
        return Ok(());
    }
    let mut seq = retry_on_rate_limit("fetch_latest_sequence", || {
        fetch_latest_sequence(client, hub_url, tenant_kp)
    })
    .await?;

    for svc in services {
        seq += 1;
        let op = ConfigOp::SetHostnameTls {
            hostname: svc.hostname.clone(),
            mode: svc.tls_mode,
        };
        match submit_tls_entry(client, hub_url, tenant_kp, op, &mut seq).await {
            Ok(()) => info!(
                hostname = %svc.hostname,
                mode = svc.tls_mode.label(),
                seq,
                "published TLS policy to hub",
            ),
            Err(e) => warn!(
                hostname = %svc.hostname,
                seq,
                error = %e,
                "failed to publish TLS policy; edge will fall back to passthrough",
            ),
        }
    }
    Ok(())
}

/// Submit one `SetHostnameTls` entry, retrying on `sequence_conflict` (re-read
/// the latest sequence first) and rate limits — matching the bootstrap publish
/// path, so a single conflict doesn't silently drop the policy and cascade.
async fn submit_tls_entry(
    client: &reqwest::Client,
    hub_url: &str,
    tenant_kp: &TenantKeypair,
    op: ConfigOp,
    seq: &mut u64,
) -> anyhow::Result<()> {
    let mut backoff = operation_backoff().build();
    loop {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: tenant_kp.id(),
            sequence: *seq,
            timestamp: towonel_common::time::now_ms(),
            op: op.clone(),
        };
        match submit_entry(client, hub_url, tenant_kp, payload).await {
            Ok(()) => return Ok(()),
            Err(e) if is_sequence_conflict(&e) || is_rate_limited(&e) => {
                let Some(delay) = backoff.next() else {
                    return Err(e);
                };
                let conflict = is_sequence_conflict(&e);
                warn!(
                    backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    op = "SetHostnameTls",
                    conflict,
                    "hub rejected TLS entry; retrying"
                );
                tokio::time::sleep(delay).await;
                if conflict {
                    *seq = retry_on_rate_limit("fetch_latest_sequence", || {
                        fetch_latest_sequence(client, hub_url, tenant_kp)
                    })
                    .await?
                        + 1;
                }
            }
            Err(e) => return Err(e),
        }
    }
}
