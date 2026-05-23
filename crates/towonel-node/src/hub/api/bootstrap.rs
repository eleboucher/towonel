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

    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<Kid>,
    /// base64url-no-pad of the detached ML-DSA-65 signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_cred_sig_b64: Option<String>,
    /// base64url-no-pad of the CBOR-encoded [`EdgeCred`].
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_cred_b64: Option<String>,
}

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

    let mut trusted_edges: Vec<iroh::EndpointId> = Vec::new();
    if let Some(self_edge) = state.identity.edge_node_id {
        trusted_edges.push(self_edge);
    }

    let mut iroh_endpoints: Vec<IrohEndpoint> = match (
        state.identity.edge_node_id,
        state.identity.edge_iroh_addresses.as_slice(),
    ) {
        (Some(node_id), addrs) if !addrs.is_empty() => vec![IrohEndpoint {
            node_id,
            addresses: addrs.to_vec(),
        }],
        _ => Vec::new(),
    };

    for (edge_id, addresses) in state.live_edges.snapshot() {
        let Some(node_id) = iroh::EndpointId::from_bytes(&edge_id).ok() else {
            continue;
        };
        if iroh_endpoints
            .iter()
            .any(|existing| existing.node_id == node_id)
        {
            continue;
        }
        iroh_endpoints.push(IrohEndpoint { node_id, addresses });
        if !trusted_edges.contains(&node_id) {
            trusted_edges.push(node_id);
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
