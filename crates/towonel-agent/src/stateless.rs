use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use towonel_common::CBOR_CONTENT_TYPE;
use towonel_common::auth::sign_auth_header;
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::{AgentId, AgentKeypair, TenantId, TenantKeypair};
use towonel_common::invite::InviteToken;
use tracing::{info, warn};

use crate::hub_client::{
    check_response, fetch_latest_sequence, is_sequence_conflict, submit_entry,
};
use crate::metrics::{self, AgentMetrics};

/// Env var that carries the `tt_inv_2_...` token. Presence of this var is
/// how we detect "run in stateless mode".
pub const INVITE_TOKEN_ENV: &str = "TOWONEL_INVITE_TOKEN";

/// Overrides the hub-returned allowlist. Escape hatch for local testing
/// or pinning a specific edge during an incident.
pub const TRUSTED_EDGES_ENV: &str = "TOWONEL_AGENT_TRUSTED_EDGES";

/// Heartbeats every 20s; the hub considers an agent live for 90s.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

/// Register retries to tolerate sequence conflicts from sibling replicas.
const REGISTER_MAX_ATTEMPTS: usize = 10;

/// Backoff policy for sequence-conflict retries. Jittered so N replicas
/// booting simultaneously don't re-collide on every retry.
fn retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(50))
        .with_max_delay(Duration::from_secs(2))
        .with_max_times(REGISTER_MAX_ATTEMPTS - 1)
        .with_jitter()
}

/// Boot-time context derived from the invite token + hub bootstrap response.
/// Shared across the register + heartbeat paths and dropped when the agent
/// shuts down.
pub struct BootstrapContext {
    pub tenant_kp: TenantKeypair,
    pub agent_kp: AgentKeypair,
    pub hub_url: String,
    pub tenant_id: TenantId,
    pub trusted_edges: HashSet<EndpointId>,
    pub client: reqwest::Client,
    pub hostnames: Vec<String>,
}

impl BootstrapContext {
    pub fn iroh_secret_key(&self) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&self.agent_kp.signing_key().to_bytes())
    }

    pub fn agent_id(&self) -> AgentId {
        self.agent_kp.id()
    }
}

/// Parse the invite token, fetch trusted-edge metadata from the hub, and
/// return a fresh `BootstrapContext`. Does NOT register the agent yet --
/// callers call [`register`] after binding the iroh endpoint so the
/// `agent_id` in the `UpsertAgent` entry matches the endpoint the edge
/// will actually dial.
pub async fn bootstrap(token_str: &str) -> anyhow::Result<BootstrapContext> {
    let token = InviteToken::decode(token_str).context("invalid TOWONEL_INVITE_TOKEN")?;
    let tenant_kp = TenantKeypair::from_seed(token.tenant_seed);
    let tenant_id = tenant_kp.id();
    let agent_kp = AgentKeypair::generate();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build reqwest client")?;

    let resp = post_bootstrap(&client, &token).await?;

    let returned_tenant_id: TenantId = resp
        .tenant_id
        .parse()
        .context("hub returned malformed tenant_id")?;
    if returned_tenant_id != tenant_id {
        bail!(
            "hub tenant_id {returned_tenant_id} does not match tenant_seed-derived {tenant_id}; \
             token may be tampered or mismatched"
        );
    }

    let mut trusted_edges = parse_trusted_edges_env();
    if trusted_edges.is_empty() {
        if resp.trusted_edges.is_empty() {
            trusted_edges.extend(resp.edge_node_id);
        } else {
            trusted_edges.extend(resp.trusted_edges.iter().copied());
        }
    }

    info!(
        %tenant_id,
        agent_id = %agent_kp.id(),
        hub_url = %token.hub_url,
        edges = trusted_edges.len(),
        "bootstrap complete"
    );

    Ok(BootstrapContext {
        tenant_kp,
        agent_kp,
        hub_url: token.hub_url.clone(),
        tenant_id,
        trusted_edges,
        client,
        hostnames: resp.hostnames,
    })
}

/// Submit an `UpsertAgent` config entry authorizing the ephemeral iroh key
/// under the tenant identity. Retries on `sequence_conflict` up to
/// [`REGISTER_MAX_ATTEMPTS`] times with jittered backoff, so N replicas
/// racing at startup all eventually succeed.
pub async fn register(ctx: &BootstrapContext) -> anyhow::Result<()> {
    let agent_id = ctx.agent_id();
    (|| async {
        let latest = fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp).await?;
        let sequence = latest + 1;
        let payload = ConfigPayload {
            version: 1,
            tenant_id: ctx.tenant_id,
            sequence,
            timestamp: towonel_common::time::now_ms(),
            op: ConfigOp::UpsertAgent {
                agent_id: agent_id.clone(),
            },
        };
        submit_entry(&ctx.client, &ctx.hub_url, &ctx.tenant_kp, payload).await?;
        info!(%agent_id, sequence, "registered agent");
        Ok(())
    })
    .retry(retry_policy())
    .when(is_sequence_conflict)
    .notify(|e, dur| {
        warn!(error = %e, backoff_ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX), "sequence conflict on UpsertAgent, retrying");
    })
    .await
}

/// Submit `UpsertHostname` entries for each hostname from the bootstrap
/// response that isn't already present in the tenant's entry log. Idempotent
/// across restarts.
pub async fn publish_hostnames(ctx: &BootstrapContext) -> anyhow::Result<()> {
    if ctx.hostnames.is_empty() {
        return Ok(());
    }

    let existing = fetch_existing_hostnames(ctx).await?;
    let missing: Vec<&String> = ctx
        .hostnames
        .iter()
        .filter(|h| !existing.contains(&h.to_lowercase()))
        .collect();

    if missing.is_empty() {
        info!(
            count = ctx.hostnames.len(),
            "all hostnames already published"
        );
        return Ok(());
    }

    // Fetch once, then increment locally. On a sequence conflict we re-fetch
    // and retry; the happy path stays O(N) instead of O(N²) round-trips.
    // The per-hostname retry state (mutable `next_seq` and re-fetch on
    // conflict) doesn't fit backon's FnMut closure model cleanly, so we
    // keep the loop manual here.
    let mut next_seq = fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp).await? + 1;
    let policy = retry_policy();

    for hostname in missing {
        let mut backoff_iter = policy.build();
        loop {
            let payload = ConfigPayload {
                version: 1,
                tenant_id: ctx.tenant_id,
                sequence: next_seq,
                timestamp: towonel_common::time::now_ms(),
                op: ConfigOp::UpsertHostname {
                    hostname: hostname.clone(),
                },
            };
            match submit_entry(&ctx.client, &ctx.hub_url, &ctx.tenant_kp, payload).await {
                Ok(()) => {
                    info!(%hostname, sequence = next_seq, "published hostname");
                    next_seq += 1;
                    break;
                }
                Err(e) if is_sequence_conflict(&e) => {
                    let Some(delay) = backoff_iter.next() else {
                        return Err(e);
                    };
                    #[allow(clippy::cast_possible_truncation)]
                    let backoff_ms = delay.as_millis() as u64;
                    warn!(backoff_ms, %hostname, "sequence conflict on UpsertHostname, retrying");
                    tokio::time::sleep(delay).await;
                    next_seq =
                        fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp).await? + 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Replay the tenant's entries to find which hostnames are already active.
async fn fetch_existing_hostnames(ctx: &BootstrapContext) -> anyhow::Result<HashSet<String>> {
    let url = format!(
        "{}/v1/tenants/{}/entries",
        ctx.hub_url.trim_end_matches('/'),
        ctx.tenant_kp.id(),
    );
    let resp = ctx
        .client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    let bytes = check_response(resp).await?;
    let entries: Vec<SignedConfigEntry> =
        ciborium::from_reader(bytes.as_slice()).context("malformed entries CBOR")?;

    let pk = ctx.tenant_kp.public_key();
    let mut hostnames = HashSet::new();
    for entry in &entries {
        if let Ok(payload) = entry.verify(pk) {
            match payload.op {
                ConfigOp::UpsertHostname { hostname } => {
                    hostnames.insert(hostname.to_lowercase());
                }
                ConfigOp::DeleteHostname { hostname } => {
                    hostnames.remove(&hostname.to_lowercase());
                }
                _ => {}
            }
        }
    }
    Ok(hostnames)
}

/// Spawn the heartbeat task. Returns the `JoinHandle` so the caller can
/// abort on shutdown (not strictly necessary -- the hub reaps stale
/// heartbeats -- but keeps shutdown logs clean).
pub fn spawn_heartbeat(ctx: Arc<BootstrapContext>, metrics: Arc<AgentMetrics>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // first tick is immediate -- send one right away
        loop {
            match send_heartbeat(&ctx).await {
                Ok(()) => metrics.record_heartbeat(metrics::heartbeat_outcome::OK),
                Err(e) => {
                    metrics.record_heartbeat(metrics::heartbeat_outcome::ERROR);
                    warn!(error = %e, "heartbeat failed; continuing");
                }
            }
            tick.tick().await;
        }
    })
}

async fn send_heartbeat(ctx: &BootstrapContext) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct Body {
        tenant_id: TenantId,
        agent_id: AgentId,
    }

    let body = Body {
        tenant_id: ctx.tenant_id,
        agent_id: ctx.agent_id(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&body, &mut buf).context("encode heartbeat")?;

    let url = format!("{}/v1/agent/heartbeat", ctx.hub_url.trim_end_matches('/'));
    let auth = sign_auth_header(
        ctx.agent_kp.signing_key(),
        "towonel/agent-heartbeat/v1",
        towonel_common::time::now_ms(),
        &buf,
    );

    let resp = ctx
        .client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(buf)
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;

    check_response(resp).await?;
    Ok(())
}

/// The hub's `/v1/bootstrap` response; we only need the two fields the
/// agent actually uses (`tenant_id` for verification, `edge_node_id` for
/// trusted-edge seeding). Serde ignores unknown fields by default, so new
/// hub fields don't break old agents.
#[derive(Deserialize)]
struct BootstrapResponse {
    tenant_id: String,
    #[serde(default)]
    hostnames: Vec<String>,
    /// Absent on older hubs; default keeps us compatible.
    #[serde(default)]
    trusted_edges: Vec<EndpointId>,
    edge_node_id: Option<EndpointId>,
}

async fn post_bootstrap(
    client: &reqwest::Client,
    token: &InviteToken,
) -> anyhow::Result<BootstrapResponse> {
    #[derive(Serialize)]
    struct BootstrapRequest {
        invite_id: String,
        invite_secret: String,
    }

    let req = BootstrapRequest {
        invite_id: B64.encode(token.invite_id),
        invite_secret: B64.encode(token.invite_secret),
    };
    let url = format!("{}/v1/bootstrap", token.hub_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;
    let body = check_response(resp).await?;
    serde_json::from_slice(&body).context("hub returned malformed bootstrap response")
}

fn parse_trusted_edges_env() -> HashSet<EndpointId> {
    let Ok(raw) = std::env::var(TRUSTED_EDGES_ENV) else {
        return HashSet::new();
    };
    let parsed: Result<Vec<String>, _> = serde_json::from_str(&raw);
    match parsed {
        Ok(list) => list
            .into_iter()
            .filter_map(|s| match s.parse::<EndpointId>() {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!(entry = %s, error = %e, "ignoring invalid TOWONEL_AGENT_TRUSTED_EDGES entry");
                    None
                }
            })
            .collect(),
        Err(e) => {
            warn!(error = %e, "TOWONEL_AGENT_TRUSTED_EDGES is not valid JSON, ignoring");
            HashSet::new()
        }
    }
}

/// Read [`INVITE_TOKEN_ENV`] or return a helpful error.
pub fn token_from_env() -> anyhow::Result<String> {
    std::env::var(INVITE_TOKEN_ENV)
        .map_err(|_| anyhow!("{INVITE_TOKEN_ENV} is not set. Pass a `tt_inv_2_...` token."))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::large_futures)]

    use super::*;

    #[tokio::test]
    async fn bootstrap_fails_clearly_when_hub_unreachable() {
        // Point at a loopback port we never bind; the reqwest connect error
        // must surface as a non-panicking anyhow::Error with a URL-bearing
        // message so operators see what went wrong in the pod logs.
        let token = InviteToken::new("http://127.0.0.1:1", [1u8; 16], [2u8; 32], [3u8; 32]);
        let Err(err) = bootstrap(&token.encode()).await else {
            panic!("unreachable hub must fail");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("127.0.0.1:1") || msg.contains("/v1/bootstrap"),
            "error should mention the failing URL, got: {msg}"
        );
    }

    #[tokio::test]
    async fn invalid_token_fails_bootstrap_at_parse_time() {
        let Err(err) = bootstrap("not-a-real-token").await else {
            panic!("garbage token must not reach the hub");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("TOWONEL_INVITE_TOKEN") || msg.contains("prefix"),
            "error should mention the token parse failure, got: {msg}"
        );
    }
}
