use std::collections::HashSet;
use std::net::SocketAddr;
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
    check_response, fetch_latest_sequence, is_rate_limited, is_sequence_conflict,
    is_unsupported_op, retry_on_rate_limit, submit_entry,
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
pub fn retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(50))
        .with_max_delay(Duration::from_secs(2))
        .with_max_times(REGISTER_MAX_ATTEMPTS - 1)
        .with_jitter()
}

/// One trusted edge. `addrs` may be empty if the hub didn't surface
/// socket addresses for this edge — the supervisor skips those since
/// dialing without an address requires a relay.
#[derive(Clone, Debug)]
pub struct EdgeContact {
    pub id: EndpointId,
    pub addrs: Vec<SocketAddr>,
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
    pub edge_contacts: Vec<EdgeContact>,
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

    let edge_addrs = parse_edge_addresses(&resp.edge_addresses);
    // The hub only surfaces its own edge's addrs in `edge_addresses`;
    // multi-edge clusters need a future hub change to advertise per-edge
    // addrs. Single-edge deployments (the common case) are correct.
    let edge_contacts: Vec<EdgeContact> = trusted_edges
        .iter()
        .map(|id| EdgeContact {
            id: *id,
            addrs: edge_addrs.clone(),
        })
        .collect();

    info!(
        %tenant_id,
        agent_id = %agent_kp.id(),
        hub_url = %token.hub_url,
        edges = trusted_edges.len(),
        dialable_edges = edge_contacts.iter().filter(|c| !c.addrs.is_empty()).count(),
        "bootstrap complete"
    );

    Ok(BootstrapContext {
        tenant_kp,
        agent_kp,
        hub_url: token.hub_url.clone(),
        tenant_id,
        trusted_edges,
        edge_contacts,
        client,
        hostnames: resp.hostnames,
    })
}

fn parse_edge_addresses(raw: &[String]) -> Vec<SocketAddr> {
    raw.iter()
        .filter_map(|s| match s.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!(addr = %s, error = %e, "hub returned unparsable edge address, skipping");
                None
            }
        })
        .collect()
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
    .when(|e| is_sequence_conflict(e) || is_rate_limited(e))
    .notify(|e, dur| {
        warn!(error = %e, backoff_ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX), "retrying UpsertAgent");
    })
    .await
}

pub async fn publish_hostnames(ctx: &BootstrapContext) -> anyhow::Result<()> {
    let existing =
        retry_on_rate_limit("fetch_existing_hostnames", || fetch_existing_hostnames(ctx)).await?;
    let desired: HashSet<String> = ctx.hostnames.iter().map(|h| h.to_lowercase()).collect();

    let missing: Vec<&String> = ctx
        .hostnames
        .iter()
        .filter(|h| !existing.contains(&h.to_lowercase()))
        .collect();
    let stale: Vec<String> = existing
        .iter()
        .filter(|h| !desired.contains(*h))
        .cloned()
        .collect();

    if missing.is_empty() && stale.is_empty() {
        return Ok(());
    }

    let mut next_seq = retry_on_rate_limit("fetch_latest_sequence", || {
        fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp)
    })
    .await?
        + 1;

    for hostname in stale {
        submit_with_retry(
            ctx,
            &mut next_seq,
            ConfigOp::DeleteHostname {
                hostname: hostname.clone(),
            },
            &format!("DeleteHostname {hostname}"),
        )
        .await?;
        info!(%hostname, "removed stale hostname");
    }

    for hostname in missing {
        submit_with_retry(
            ctx,
            &mut next_seq,
            ConfigOp::UpsertHostname {
                hostname: hostname.clone(),
            },
            &format!("UpsertHostname {hostname}"),
        )
        .await?;
        info!(%hostname, "published hostname");
    }
    Ok(())
}

async fn submit_with_retry(
    ctx: &BootstrapContext,
    next_seq: &mut u64,
    op: ConfigOp,
    label: &str,
) -> anyhow::Result<()> {
    // Independent budgets: a 429 storm shouldn't burn the conflict-retry
    // quota and vice versa.
    let mut conflict_backoff = retry_policy().build();
    let mut rate_limit_backoff = retry_policy().build();
    loop {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: ctx.tenant_id,
            sequence: *next_seq,
            timestamp: towonel_common::time::now_ms(),
            op: op.clone(),
        };
        match submit_entry(&ctx.client, &ctx.hub_url, &ctx.tenant_kp, payload).await {
            Ok(()) => {
                *next_seq += 1;
                return Ok(());
            }
            Err(e) if is_sequence_conflict(&e) => {
                let Some(delay) = conflict_backoff.next() else {
                    return Err(e);
                };
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "backoff delay is bounded well under u64::MAX millis"
                )]
                let backoff_ms = delay.as_millis() as u64;
                warn!(backoff_ms, op = label, "sequence conflict, retrying");
                tokio::time::sleep(delay).await;
                *next_seq = retry_on_rate_limit(label, || {
                    fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp)
                })
                .await?
                    + 1;
            }
            Err(e) if is_rate_limited(&e) => {
                let Some(delay) = rate_limit_backoff.next() else {
                    return Err(e);
                };
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "backoff delay is bounded well under u64::MAX millis"
                )]
                let backoff_ms = delay.as_millis() as u64;
                warn!(backoff_ms, op = label, "hub rate-limited, retrying");
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Replay the tenant's entries to find which hostnames are already active.
async fn fetch_existing_hostnames(ctx: &BootstrapContext) -> anyhow::Result<HashSet<String>> {
    let entries = fetch_tenant_entries(ctx).await?;
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

#[derive(Clone, Copy)]
enum ServiceProtocol {
    Tcp,
    Udp,
}

impl ServiceProtocol {
    const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    const fn upsert(self, service: String, listen_port: u16) -> ConfigOp {
        match self {
            Self::Tcp => ConfigOp::UpsertTcpService {
                service,
                listen_port,
            },
            Self::Udp => ConfigOp::UpsertUdpService {
                service,
                listen_port,
            },
        }
    }

    const fn delete(self, service: String) -> ConfigOp {
        match self {
            Self::Tcp => ConfigOp::DeleteTcpService { service },
            Self::Udp => ConfigOp::DeleteUdpService { service },
        }
    }

    /// Pull `(service, port)` out of an Upsert, or `service` out of a Delete,
    /// for this protocol. Returns `None` for any other op so the entry replay
    /// can skip it cleanly.
    fn classify(self, op: ConfigOp) -> Option<ServiceMutation> {
        match (self, op) {
            (
                Self::Tcp,
                ConfigOp::UpsertTcpService {
                    service,
                    listen_port,
                },
            )
            | (
                Self::Udp,
                ConfigOp::UpsertUdpService {
                    service,
                    listen_port,
                },
            ) => Some(ServiceMutation::Upsert {
                service,
                listen_port,
            }),
            (Self::Tcp, ConfigOp::DeleteTcpService { service })
            | (Self::Udp, ConfigOp::DeleteUdpService { service }) => {
                Some(ServiceMutation::Delete { service })
            }
            _ => None,
        }
    }
}

enum ServiceMutation {
    Upsert { service: String, listen_port: u16 },
    Delete { service: String },
}

async fn fetch_existing_service_bindings(
    ctx: &BootstrapContext,
    proto: ServiceProtocol,
) -> anyhow::Result<std::collections::HashMap<String, u16>> {
    let entries = fetch_tenant_entries(ctx).await?;
    let pk = ctx.tenant_kp.public_key();
    let mut bindings: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
    for entry in &entries {
        if let Ok(payload) = entry.verify(pk) {
            match proto.classify(payload.op) {
                Some(ServiceMutation::Upsert {
                    service,
                    listen_port,
                }) => {
                    bindings.insert(service, listen_port);
                }
                Some(ServiceMutation::Delete { service }) => {
                    bindings.remove(&service);
                }
                None => {}
            }
        }
    }
    Ok(bindings)
}

async fn fetch_tenant_entries(ctx: &BootstrapContext) -> anyhow::Result<Vec<SignedConfigEntry>> {
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
    ciborium::from_reader(bytes.as_slice()).context("malformed entries CBOR")
}

async fn publish_services(
    ctx: &BootstrapContext,
    desired: &[(String, u16)],
    proto: ServiceProtocol,
) -> anyhow::Result<()> {
    let existing = retry_on_rate_limit("fetch_existing_service_bindings", || {
        fetch_existing_service_bindings(ctx, proto)
    })
    .await?;
    let desired_names: HashSet<&str> = desired.iter().map(|(n, _)| n.as_str()).collect();

    let to_upsert: Vec<&(String, u16)> = desired
        .iter()
        .filter(|(name, port)| existing.get(name) != Some(port))
        .collect();
    let to_delete: Vec<String> = existing
        .keys()
        .filter(|n| !desired_names.contains(n.as_str()))
        .cloned()
        .collect();

    if to_upsert.is_empty() && to_delete.is_empty() {
        return Ok(());
    }

    let mut next_seq = retry_on_rate_limit("fetch_latest_sequence", || {
        fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp)
    })
    .await?
        + 1;

    // Deletes first so a service renamed onto an in-use port can claim it.
    for service in to_delete {
        let label = format!("Delete{}Service {service}", proto.label());
        match submit_with_retry(ctx, &mut next_seq, proto.delete(service.clone()), &label).await {
            Ok(()) => {
                info!(proto = proto.label(), %service, "removed stale service");
            }
            Err(e) if is_unsupported_op(&e) => {
                warn!(
                    hub_url = %ctx.hub_url,
                    proto = proto.label(),
                    error = %e,
                    "hub does not support delete for this protocol; proceeding with upserts only",
                );
                break;
            }
            Err(e) => return Err(e),
        }
    }

    for (service, listen_port) in to_upsert {
        let label = format!("Upsert{}Service {service}", proto.label());
        match submit_with_retry(
            ctx,
            &mut next_seq,
            proto.upsert(service.clone(), *listen_port),
            &label,
        )
        .await
        {
            Ok(()) => {
                info!(proto = proto.label(), %service, listen_port, "published service");
            }
            Err(e) if is_unsupported_op(&e) => {
                warn!(
                    hub_url = %ctx.hub_url,
                    proto = proto.label(),
                    error = %e,
                    "hub does not support this service protocol; skipping",
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

pub async fn publish_tcp_services(
    ctx: &BootstrapContext,
    desired: &[(String, u16)],
) -> anyhow::Result<()> {
    publish_services(ctx, desired, ServiceProtocol::Tcp).await
}

pub async fn publish_udp_services(
    ctx: &BootstrapContext,
    desired: &[(String, u16)],
) -> anyhow::Result<()> {
    publish_services(ctx, desired, ServiceProtocol::Udp).await
}

/// Must be called after [`register`] so the current agent is in the log
/// before its predecessors are revoked.
pub async fn reconcile_agents(ctx: &BootstrapContext) -> anyhow::Result<()> {
    let existing =
        retry_on_rate_limit("fetch_authorized_agents", || fetch_authorized_agents(ctx)).await?;
    let current = ctx.agent_id();
    let stale: Vec<AgentId> = existing.into_iter().filter(|a| a != &current).collect();

    if stale.is_empty() {
        return Ok(());
    }

    let mut next_seq = retry_on_rate_limit("fetch_latest_sequence", || {
        fetch_latest_sequence(&ctx.client, &ctx.hub_url, &ctx.tenant_kp)
    })
    .await?
        + 1;
    for agent_id in stale {
        let label = format!("RevokeAgent {agent_id}");
        submit_with_retry(
            ctx,
            &mut next_seq,
            ConfigOp::RevokeAgent {
                agent_id: agent_id.clone(),
            },
            &label,
        )
        .await?;
        info!(%agent_id, "revoked stale agent");
    }
    Ok(())
}

async fn fetch_authorized_agents(ctx: &BootstrapContext) -> anyhow::Result<HashSet<AgentId>> {
    let entries = fetch_tenant_entries(ctx).await?;
    let pk = ctx.tenant_kp.public_key();
    let mut agents = HashSet::new();
    for entry in &entries {
        if let Ok(payload) = entry.verify(pk) {
            match payload.op {
                ConfigOp::UpsertAgent { agent_id } => {
                    agents.insert(agent_id);
                }
                ConfigOp::RevokeAgent { agent_id } => {
                    agents.remove(&agent_id);
                }
                _ => {}
            }
        }
    }
    Ok(agents)
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
    /// Absent on older hubs.
    #[serde(default)]
    edge_addresses: Vec<String>,
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
        .map_err(|_e| anyhow!("{INVITE_TOKEN_ENV} is not set. Pass a `tt_inv_2_...` token."))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::large_futures, reason = "test futures are not on the hot path")]

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
