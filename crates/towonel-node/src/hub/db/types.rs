use std::fmt;

use serde::{Deserialize, Serialize};
use towonel_common::identity::{PqPublicKey, TenantId};
use towonel_common::invite::INVITE_ID_LEN;

/// Status of an invite. v2 invites carry the seed inside the token, so
/// `Pending` is the live state for the whole credential's life and
/// `Revoked` is the only sink. There is no "consumed" / "redeemed"
/// transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteStatus {
    Pending,
    Revoked,
}

impl InviteStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "revoked" => Ok(Self::Revoked),
            other => anyhow::bail!("unknown invite status: {other}"),
        }
    }
}

impl fmt::Display for InviteStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fields required to create a fresh tenant invite row. v2 invites bind the
/// tenant identity at creation time; `tenant_id` + `pq_public_key` are always
/// known here (unlike the old "pending" row that used to wait for redemption).
pub struct PendingInvite<'a> {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: &'a str,
    pub hostnames: &'a [String],
    pub secret_hash: [u8; 32],
    pub tenant_id: TenantId,
    pub pq_public_key: &'a PqPublicKey,
    /// `None` means the token never expires.
    pub expires_at_ms: Option<u64>,
    pub created_at_ms: u64,
}

/// Fully hydrated tenant invite row, as returned by list/get. In v2 the
/// tenant is bound at creation time, so `tenant_id` is always present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRow {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: String,
    pub hostnames: Vec<String>,
    pub secret_hash: [u8; 32],
    /// `None` means the token never expires.
    pub expires_at_ms: Option<u64>,
    pub status: InviteStatus,
    pub tenant_id: TenantId,
    pub created_at_ms: u64,
}

pub struct RedeemedTenant {
    pub tenant_id: TenantId,
    pub hostnames: Vec<String>,
    pub pq_public_key: PqPublicKey,
}

/// `edge_node_id` is derived from the seed in the token and bound at
/// creation time. Edge invites don't carry an expiry: revoke to cut
/// access.
pub struct PendingEdgeInvite<'a> {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: &'a str,
    pub secret_hash: [u8; 32],
    pub edge_node_id: [u8; 32],
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInviteRow {
    pub invite_id: [u8; INVITE_ID_LEN],
    pub name: String,
    pub secret_hash: [u8; 32],
    pub status: InviteStatus,
    pub edge_node_id: [u8; 32],
    pub created_at_ms: u64,
}
