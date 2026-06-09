use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use towonel_common::edge_cred::{EDGE_CRED_NONCE_LEN, EDGE_CRED_VERSION, EdgeCred, Kid};
use towonel_common::identity::AgentId;
use towonel_common::invite::hash_invite_secret;
use tracing::warn;
use zeroize::Zeroizing;

use towonel_common::time::now_ms;

use super::db::InviteStatus;
use super::{
    AppState, constant_time_eq, gone, internal_error, invalid_request, json_ok, parse_invite_id,
    unauthorized,
};

/// 1 h — caps the worst-case revocation lag for an issued `EdgeCred`.
const EDGE_CRED_TTL_MS: u64 = 60 * 60 * 1_000;

#[derive(Debug, Deserialize)]
pub(super) struct BootstrapRequest {
    invite_id: String,
    invite_secret: String,
    /// Hex-encoded agent ed25519 public key.
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct IrohEndpoint {
    node_id: iroh::EndpointId,
    addresses: Vec<String>,
}

/// An edge under consideration at bootstrap, before the region filter.
struct EdgeCandidate {
    node_id: iroh::EndpointId,
    addresses: Vec<String>,
    region: Option<String>,
}

/// Colocated edge first, then port-capable edges, then portless edges as
/// HTTP-only fallback (deduped by node id). Edges lacking the tenant's TCP/UDP
/// capability are kept rather than dropped so HTTP survives when every
/// port-capable edge is down; a portless edge ignores port routes it can't bind.
///
/// The colocated edge is exempt from the capability partition: `HubIdentity`
/// carries no capability flags, and the bundled in-process edge defaults to
/// serving TCP/UDP, so it is always ranked primary.
fn select_edge_candidates(
    colocated: Option<EdgeCandidate>,
    live_edges: Vec<super::super::live_edges::EdgeSnapshot>,
    needs_tcp: bool,
    needs_udp: bool,
) -> Vec<EdgeCandidate> {
    let mut candidates: Vec<EdgeCandidate> = Vec::new();
    let mut fallback: Vec<EdgeCandidate> = Vec::new();
    let mut seen: HashSet<iroh::EndpointId> = HashSet::new();
    if let Some(candidate) = colocated {
        seen.insert(candidate.node_id);
        candidates.push(candidate);
    }
    for (edge_id, addresses, capabilities, _public_ips, region) in live_edges {
        let Ok(node_id) = iroh::EndpointId::from_bytes(&edge_id) else {
            continue;
        };
        if !seen.insert(node_id) {
            continue;
        }
        let candidate = EdgeCandidate {
            node_id,
            addresses,
            region,
        };
        if (needs_tcp && !capabilities.tcp_services) || (needs_udp && !capabilities.udp_services) {
            fallback.push(candidate);
        } else {
            candidates.push(candidate);
        }
    }
    candidates.extend(fallback);
    candidates
}

#[derive(Debug, Serialize)]
pub(super) struct BootstrapResponse {
    status: &'static str,
    tenant_id: String,
    hostnames: Vec<String>,
    hub_node_id: iroh::EndpointId,
    trusted_edges: Vec<iroh::EndpointId>,
    /// Mirror of `trusted_edges.first()`; kept so pre-multi-edge agents still work.
    edge_node_id: Option<iroh::EndpointId>,
    edge_addresses: Vec<String>,
    iroh_endpoints: Vec<IrohEndpoint>,

    /// Operator-configured iroh relay(s), comma-separated, so agents don't need
    /// them in their env.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<Kid>,
    /// base64url-no-pad of the detached ML-DSA-65 signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_cred_sig_b64: Option<String>,
    /// base64url-no-pad of the CBOR-encoded [`EdgeCred`].
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_cred_b64: Option<String>,
}

#[expect(
    clippy::too_many_lines,
    reason = "linear bootstrap pipeline — splitting fragments the auth flow"
)]
pub(super) async fn post_bootstrap(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<BootstrapRequest>,
) -> Response {
    let Some(invite_id) = parse_invite_id(&req.invite_id) else {
        return invalid_request("invite_id is not valid base64url");
    };
    let Ok(invite_secret) = B64.decode(&req.invite_secret).map(Zeroizing::new) else {
        return invalid_request("invite_secret is not valid base64url");
    };

    // Always compute the keyed hash before branching on row existence, so a
    // remote attacker can't distinguish missing-invite from wrong-secret via
    // response latency. The constant-time compare against the row's hash (or
    // an all-zero sentinel when the row is missing) keeps both paths
    // CPU-identical too.
    let presented = hash_invite_secret(&state.invite_hash_key, &invite_secret);
    let invite = match state.db.get_invite(&invite_id).await {
        Ok(row) => row,
        Err(e) => {
            warn!(error = %e, "failed to fetch invite");
            return internal_error();
        }
    };
    let Some(invite) = invite else {
        let sentinel = [0u8; 32];
        let _ = constant_time_eq(&presented, &sentinel);
        return unauthorized("invite_secret is invalid or the invite has been revoked");
    };

    // Return the SAME error for both wrong-secret and revoked-with-right-secret
    // so an attacker who obtains an invite_secret can't distinguish a revoked
    // invite from a mistyped secret. Legitimate clients see the generic message;
    // hub operators can inspect the server log (below) for the real cause.
    let secret_ok = constant_time_eq(&presented, &invite.secret_hash);
    let revoked = matches!(invite.status, InviteStatus::Revoked);
    if !secret_ok || revoked {
        if secret_ok && revoked {
            tracing::info!(
                invite_id = %req.invite_id,
                "bootstrap rejected: invite is revoked (secret was valid)"
            );
        }
        return unauthorized("invite_secret is invalid or the invite has been revoked");
    }

    if invite.expires_at_ms.is_some_and(|e| now_ms() > e) {
        return gone("invite has expired");
    }

    if matches!(invite.status, InviteStatus::Pending)
        && let Err(e) = state.db.mark_invite_claimed(&invite_id).await
    {
        warn!(error = %e, "mark_invite_claimed failed; bootstrap proceeding");
    }

    let policy = state.policy.load_full();
    let Some(pq_pubkey) = policy.pq_public_key(&invite.tenant_id) else {
        warn!(
            tenant = %invite.tenant_id,
            "bootstrap: tenant not found in ownership policy"
        );
        return internal_error();
    };

    let (needs_tcp, needs_udp) = match state
        .db
        .tenant_has_service_bindings(&invite.tenant_id, pq_pubkey)
        .await
    {
        Ok((tcp, udp)) => (tcp, udp),
        Err(e) => {
            warn!(error = %e, "failed to fetch tenant service bindings for bootstrap");
            return internal_error();
        }
    };

    // Candidate edges (colocated first, then remote) after dedup, before the
    // region filter.
    let colocated = state.identity.edge_node_id.map(|node_id| EdgeCandidate {
        node_id,
        addresses: state.identity.edge_iroh_addresses.clone(),
        region: state.identity.edge_region.clone(),
    });
    let candidates =
        select_edge_candidates(colocated, state.live_edges.snapshot(), needs_tcp, needs_udp);

    // Keep only edges in the invite's allowed regions. If that leaves nothing
    // dialable, fall back to every candidate so the agent is never stranded.
    let allowed = invite.allowed_regions();
    let in_region = |c: &EdgeCandidate| {
        allowed.contains(
            c.region
                .as_deref()
                .unwrap_or(towonel_common::DEFAULT_REGION),
        )
    };
    let any_dialable_in_region = candidates
        .iter()
        .any(|c| in_region(c) && !c.addresses.is_empty());
    if !any_dialable_in_region {
        warn!(
            tenant = %invite.tenant_id,
            ?allowed,
            "bootstrap: no dialable edge in the invite's region(s); returning all edges"
        );
    }

    let mut trusted_edges: Vec<iroh::EndpointId> = Vec::new();
    let mut iroh_endpoints: Vec<IrohEndpoint> = Vec::new();
    for c in &candidates {
        if any_dialable_in_region && !in_region(c) {
            continue;
        }
        trusted_edges.push(c.node_id);
        if !c.addresses.is_empty() {
            iroh_endpoints.push(IrohEndpoint {
                node_id: c.node_id,
                addresses: c.addresses.clone(),
            });
        }
    }

    let edge_node_id = trusted_edges.first().copied();

    let (kid, edge_cred_b64, edge_cred_sig_b64) = match req.agent_id.as_deref() {
        Some(hex) => match mint_edge_cred(&state, hex, &invite.tenant_id) {
            Ok((k, c, s)) => (Some(k), Some(c), Some(s)),
            Err(resp) => return *resp,
        },
        None => (None, None, None),
    };

    json_ok(BootstrapResponse {
        status: "ok",
        tenant_id: invite.tenant_id.to_string(),
        hostnames: invite.hostnames,
        hub_node_id: state.identity.node_id,
        trusted_edges,
        edge_node_id,
        edge_addresses: state.identity.edge_addresses.clone(),
        iroh_endpoints,
        relay_url: state.identity.relay_url.clone(),
        kid,
        edge_cred_b64,
        edge_cred_sig_b64,
    })
}

pub(super) fn mint_edge_cred(
    state: &AppState,
    agent_id_hex: &str,
    tenant_id: &towonel_common::identity::TenantId,
) -> Result<(Kid, String, String), Box<Response>> {
    let agent_id: AgentId = agent_id_hex.parse().map_err(|e| {
        Box::new(invalid_request(format!(
            "agent_id is not a valid ed25519 public key: {e}"
        )))
    })?;
    let mut nonce = [0u8; EDGE_CRED_NONCE_LEN];
    if let Err(e) = getrandom::fill(&mut nonce) {
        warn!(error = %e, "OS RNG failure while minting EdgeCred");
        return Err(Box::new(internal_error()));
    }
    let cred = EdgeCred {
        version: EDGE_CRED_VERSION,
        kid: state.signer.kid(),
        agent_id,
        tenant_id: *tenant_id,
        not_after_ms: now_ms() + EDGE_CRED_TTL_MS,
        nonce,
    };
    let (cred_bytes, sig) = state.signer.sign_edge_cred(&cred).map_err(|e| {
        warn!(error = %e, "EdgeCred CBOR encoding failed");
        Box::new(internal_error())
    })?;
    Ok((cred.kid, B64.encode(&cred_bytes), B64.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::edge_link::EdgeCapabilities;

    fn endpoint_id(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from([seed; 32]).public()
    }

    fn caps(tcp: bool, udp: bool) -> EdgeCapabilities {
        EdgeCapabilities {
            tcp_services: tcp,
            udp_services: udp,
        }
    }

    fn snapshot_entry(
        seed: u8,
        capabilities: EdgeCapabilities,
    ) -> super::super::super::live_edges::EdgeSnapshot {
        (
            *endpoint_id(seed).as_bytes(),
            vec!["127.0.0.1:51820".to_string()],
            capabilities,
            vec!["127.0.0.1".to_string()],
            Some(towonel_common::DEFAULT_REGION.to_string()),
        )
    }

    fn ids(candidates: &[EdgeCandidate]) -> Vec<iroh::EndpointId> {
        candidates.iter().map(|c| c.node_id).collect()
    }

    #[test]
    fn portless_edge_kept_as_fallback_after_capable_one() {
        // Tenant needs TCP. A port-capable edge and a portless edge are live.
        let live = vec![
            snapshot_entry(2, caps(false, false)), // portless, listed first
            snapshot_entry(1, caps(true, true)),   // port-capable
        ];
        let got = select_edge_candidates(None, live, true, false);
        // Both kept; the port-capable edge is ordered ahead of the portless one.
        assert_eq!(got.len(), 2);
        assert_eq!(ids(&got), vec![endpoint_id(1), endpoint_id(2)]);
    }

    #[test]
    fn portless_only_still_returned_when_no_capable_edge() {
        // Tenant needs TCP but only a portless edge is live: return it so HTTP
        // still works (degraded — TCP unavailable until a capable edge returns).
        let live = vec![snapshot_entry(2, caps(false, false))];
        let got = select_edge_candidates(None, live, true, false);
        assert_eq!(ids(&got), vec![endpoint_id(2)]);
    }

    #[test]
    fn colocated_edge_leads_and_dedups() {
        let colocated = EdgeCandidate {
            node_id: endpoint_id(1),
            addresses: vec![],
            region: None,
        };
        // Same id appears again in the live set: must not be duplicated.
        let live = vec![
            snapshot_entry(1, caps(true, true)),
            snapshot_entry(2, caps(true, true)),
        ];
        let got = select_edge_candidates(Some(colocated), live, true, true);
        assert_eq!(ids(&got), vec![endpoint_id(1), endpoint_id(2)]);
    }

    #[test]
    fn no_partition_when_tenant_has_no_port_services() {
        // No TCP/UDP need: every edge is a primary candidate, order preserved.
        let live = vec![
            snapshot_entry(1, caps(false, false)),
            snapshot_entry(2, caps(true, true)),
        ];
        let got = select_edge_candidates(None, live, false, false);
        assert_eq!(ids(&got), vec![endpoint_id(1), endpoint_id(2)]);
    }
}
