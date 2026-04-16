use std::path::Path;

use anyhow::Context;
use tracing::{info, warn};
use turbo_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use turbo_common::identity::TenantKeypair;
use turbo_common::tls_policy::TlsMode;

use crate::config::ServiceConfig;
use crate::init::submit_entry;

pub async fn publish(
    hub_url: &str,
    tenant_key_path: &Path,
    services: &[ServiceConfig],
) -> anyhow::Result<()> {
    if services.is_empty() {
        return Ok(());
    }

    let tenant_kp = turbo_common::identity::load_or_generate_tenant_keypair(tenant_key_path)
        .context("failed to load tenant key for TLS publish")?;

    let client = reqwest::Client::new();
    let mut seq = fetch_latest_sequence(&client, hub_url, &tenant_kp).await?;

    for svc in services {
        seq += 1;
        let payload = ConfigPayload {
            version: 1,
            tenant_id: tenant_kp.id(),
            sequence: seq,
            timestamp: turbo_common::time::now_ms(),
            op: ConfigOp::SetHostnameTls {
                hostname: svc.hostname.clone(),
                mode: svc.tls_mode.clone(),
            },
        };
        match submit_entry(&client, hub_url, &tenant_kp, payload).await {
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

async fn fetch_latest_sequence(
    client: &reqwest::Client,
    hub_url: &str,
    kp: &TenantKeypair,
) -> anyhow::Result<u64> {
    let url = format!(
        "{}/v1/tenants/{}/entries",
        hub_url.trim_end_matches('/'),
        kp.id(),
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    if !resp.status().is_success() {
        return Ok(0);
    }
    let bytes = resp.bytes().await?;
    let entries: Vec<SignedConfigEntry> = ciborium::from_reader(bytes.as_ref())
        .context("hub returned malformed tenant-entries CBOR")?;
    let pq_pubkey = kp.public_key();
    let mut max_seq = 0u64;
    for entry in &entries {
        if let Ok(payload) = entry.verify(pq_pubkey) {
            max_seq = max_seq.max(payload.sequence);
        }
    }
    Ok(max_seq)
}
