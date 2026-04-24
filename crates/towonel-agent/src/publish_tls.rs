use towonel_common::config_entry::{ConfigOp, ConfigPayload};
use towonel_common::identity::TenantKeypair;
use tracing::{info, warn};

use crate::config::ServiceConfig;
use crate::hub_client::{fetch_latest_sequence, submit_entry};

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
    let mut seq = fetch_latest_sequence(client, hub_url, tenant_kp).await?;

    for svc in services {
        seq += 1;
        let payload = ConfigPayload {
            version: 1,
            tenant_id: tenant_kp.id(),
            sequence: seq,
            timestamp: towonel_common::time::now_ms(),
            op: ConfigOp::SetHostnameTls {
                hostname: svc.hostname.clone(),
                mode: svc.tls_mode,
            },
        };
        match submit_entry(client, hub_url, tenant_kp, payload).await {
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
