use serde::{Deserialize, Serialize};
use turbo_common::identity::{PqPublicKey, TenantId};
use turbo_common::invite::INVITE_ID_LEN;

/// Fields required to create a pending invite row.
pub struct PendingInvite<'a> {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: &'a str,
    pub hostnames: &'a [String],
    pub secret_hash: [u8; 32],
    pub expires_at_ms: u64,
    pub created_at_ms: u64,
}

/// Fully hydrated invite row, as returned by list/get.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRow {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: String,
    pub hostnames: Vec<String>,
    pub secret_hash: [u8; 32],
    pub expires_at_ms: u64,
    pub status: String,
    pub tenant_id: Option<TenantId>,
    pub redeemed_at_ms: Option<u64>,
    pub created_at_ms: u64,
}

pub struct RedeemedTenant {
    pub tenant_id: TenantId,
    pub hostnames: Vec<String>,
    pub pq_public_key: PqPublicKey,
}

/// A tenant whose registration came from a peer hub via federation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedTenant {
    pub tenant_id: TenantId,
    pub pq_public_key: PqPublicKey,
    pub hostnames: Vec<String>,
    pub registered_at_ms: u64,
}

pub struct PendingEdgeInvite<'a> {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: &'a str,
    pub secret_hash: [u8; 32],
    pub expires_at_ms: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInviteRow {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: String,
    pub secret_hash: [u8; 32],
    pub expires_at_ms: u64,
    pub status: String,
    pub edge_node_id: Option<[u8; 32]>,
    pub redeemed_at_ms: Option<u64>,
    pub created_at_ms: u64,
}
