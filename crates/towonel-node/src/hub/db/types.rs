use std::fmt;

use serde::{Deserialize, Serialize};
use towonel_common::identity::{PqPublicKey, TenantId};
use towonel_common::invite::INVITE_ID_LEN;

/// `Claimed` is display-only: the token stays usable, but the UI can tell
/// "never bootstrapped" (`Pending`) apart from "in use". `Revoked` is the
/// only terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteStatus {
    Pending,
    Claimed,
    Revoked,
}

impl InviteStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "claimed" => Ok(Self::Claimed),
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
