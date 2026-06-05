use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use towonel_common::edge_cred::{
    AuthFrame, CONTROL_OPCODE_AUTHENTICATE, EDGE_CRED_VERSION, EdgeCred, verify_edge_cred,
};
use towonel_common::identity::PqPublicKey;
use towonel_common::time::now_ms;
use towonel_common::tunnel::{
    CONTROL_STATUS_INVALID, CONTROL_STATUS_NOT_IMPLEMENTED, CONTROL_STATUS_OK,
};

use crate::edge::hub_client::{ControlFrameHandler, ControlResponse};
use crate::hub::api::AppState;

pub struct HubControlHandler {
    state: Arc<AppState>,
}

impl HubControlHandler {
    pub const fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ControlFrameHandler for HubControlHandler {
    async fn handle(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse> {
        let Some(&opcode) = frame.first() else {
            return Ok((CONTROL_STATUS_INVALID, Vec::new()));
        };
        match opcode {
            CONTROL_OPCODE_AUTHENTICATE => Ok(self.handle_authenticate(&frame)),
            _ => Ok((CONTROL_STATUS_NOT_IMPLEMENTED, Vec::new())),
        }
    }
}

impl HubControlHandler {
    fn handle_authenticate(&self, frame: &[u8]) -> ControlResponse {
        let auth = match AuthFrame::decode(frame) {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "auth frame decode failed");
                return (CONTROL_STATUS_INVALID, Vec::new());
            }
        };
        let cred = match EdgeCred::from_cbor(&auth.cred_cbor) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "EdgeCred CBOR decode failed");
                return (CONTROL_STATUS_INVALID, Vec::new());
            }
        };
        if cred.version != EDGE_CRED_VERSION {
            warn!(
                cred_version = cred.version,
                expected = EDGE_CRED_VERSION,
                "EdgeCred version mismatch"
            );
            return (CONTROL_STATUS_INVALID, Vec::new());
        }
        if cred.kid != auth.kid {
            warn!(
                wire_kid = auth.kid,
                cred_kid = cred.kid,
                "auth frame kid mismatch"
            );
            return (CONTROL_STATUS_INVALID, Vec::new());
        }
        if cred.not_after_ms <= now_ms() {
            warn!(
                agent = %cred.agent_id,
                not_after_ms = cred.not_after_ms,
                "EdgeCred expired"
            );
            return (CONTROL_STATUS_INVALID, Vec::new());
        }
        let Some(pubkey) = self.lookup_signing_pubkey(auth.kid) else {
            warn!(kid = auth.kid, "unknown signing kid");
            return (CONTROL_STATUS_INVALID, Vec::new());
        };
        if !verify_edge_cred(&pubkey, &auth.cred_cbor, &auth.sig) {
            warn!(agent = %cred.agent_id, "EdgeCred signature invalid");
            return (CONTROL_STATUS_INVALID, Vec::new());
        }
        // A removed tenant is dropped from the in-memory policy; its still-valid
        // creds (TTL up to 1h) must not keep authenticating after revocation.
        if !self.state.policy.load().is_known_tenant(&cred.tenant_id) {
            warn!(
                agent = %cred.agent_id,
                tenant = %cred.tenant_id,
                "EdgeCred for unknown or removed tenant"
            );
            return (CONTROL_STATUS_INVALID, Vec::new());
        }
        // No nonce-replay rejection: agents cache a cred for its TTL and
        // re-present it on every edge dial, so repeats are legitimate. A
        // stolen cred is useless anyway — the edge checks `cred.agent_id`
        // against the iroh-authenticated connection before honoring it.
        (CONTROL_STATUS_OK, Vec::new())
    }

    /// Only the active kid is supported today; retired-kid lookup against the
    /// `hub_signing_keys` table can be added once rotation lands.
    fn lookup_signing_pubkey(&self, kid: u32) -> Option<PqPublicKey> {
        let signer = self.state.signer.as_ref();
        (signer.kid() == kid).then(|| signer.public_key().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::edge_cred::EDGE_CRED_NONCE_LEN;
    use towonel_common::identity::{AgentKeypair, TenantId, TenantKeypair};

    use crate::hub::test_helpers::TestHub;

    /// Insert a tenant into the in-memory policy so authenticate's
    /// known-tenant gate passes. `is_known_tenant` only checks key presence,
    /// so the pq key need not relate to `tenant_id`.
    fn register_tenant(state: &AppState, tenant_id: &TenantId) {
        let key = TenantKeypair::generate();
        state.policy_update(|p| {
            p.register_tenant(
                tenant_id,
                key.public_key().clone(),
                std::iter::empty::<String>(),
            );
        });
    }

    fn build_auth(state: &AppState, agent: &AgentKeypair) -> AuthFrame {
        let tenant_id = TenantId::from_bytes(&[1u8; 32]);
        register_tenant(state, &tenant_id);
        let cred = EdgeCred {
            version: EDGE_CRED_VERSION,
            kid: state.signer.kid(),
            agent_id: agent.id(),
            tenant_id,
            not_after_ms: now_ms() + 60_000,
            nonce: [42u8; EDGE_CRED_NONCE_LEN],
        };
        let (cred_cbor, sig) = state.signer.sign_edge_cred(&cred).unwrap();
        AuthFrame {
            kid: state.signer.kid(),
            cred_cbor,
            sig,
        }
    }

    #[tokio::test]
    async fn accepts_valid_cred() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        let frame = build_auth(&hub.state, &agent).encode();
        let (status, _) = handler.handle(frame).await.unwrap();
        assert_eq!(status, CONTROL_STATUS_OK);
    }

    #[tokio::test]
    async fn accepts_represented_cred() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        let frame = build_auth(&hub.state, &agent).encode();
        assert_eq!(
            handler.handle(frame.clone()).await.unwrap().0,
            CONTROL_STATUS_OK
        );
        // The same cached cred must keep authenticating for its whole TTL.
        assert_eq!(handler.handle(frame).await.unwrap().0, CONTROL_STATUS_OK);
    }

    #[tokio::test]
    async fn rejects_expired_cred() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        let cred = EdgeCred {
            version: EDGE_CRED_VERSION,
            kid: hub.state.signer.kid(),
            agent_id: agent.id(),
            tenant_id: towonel_common::identity::TenantId::from_bytes(&[1u8; 32]),
            not_after_ms: now_ms().saturating_sub(1),
            nonce: [7u8; EDGE_CRED_NONCE_LEN],
        };
        let (cred_cbor, sig) = hub.state.signer.sign_edge_cred(&cred).unwrap();
        let frame = AuthFrame {
            kid: hub.state.signer.kid(),
            cred_cbor,
            sig,
        }
        .encode();
        assert_eq!(
            handler.handle(frame).await.unwrap().0,
            CONTROL_STATUS_INVALID
        );
    }

    #[tokio::test]
    async fn rejects_cred_for_unknown_tenant() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        // Valid, unexpired cred whose tenant was never registered (or removed).
        let cred = EdgeCred {
            version: EDGE_CRED_VERSION,
            kid: hub.state.signer.kid(),
            agent_id: agent.id(),
            tenant_id: TenantId::from_bytes(&[2u8; 32]),
            not_after_ms: now_ms() + 60_000,
            nonce: [11u8; EDGE_CRED_NONCE_LEN],
        };
        let (cred_cbor, sig) = hub.state.signer.sign_edge_cred(&cred).unwrap();
        let frame = AuthFrame {
            kid: hub.state.signer.kid(),
            cred_cbor,
            sig,
        }
        .encode();
        assert_eq!(
            handler.handle(frame).await.unwrap().0,
            CONTROL_STATUS_INVALID
        );
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        let mut auth = build_auth(&hub.state, &agent);
        // Wire kid no longer matches cred.kid — the kid-mismatch branch
        // must fire before sig verification.
        auth.kid = 0xDEAD_BEEF;
        let frame = auth.encode();
        assert_eq!(
            handler.handle(frame).await.unwrap().0,
            CONTROL_STATUS_INVALID
        );
    }

    #[tokio::test]
    async fn rejects_tampered_sig() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let agent = AgentKeypair::generate();
        let mut auth = build_auth(&hub.state, &agent);
        // Flip a byte in the sig.
        auth.sig[100] ^= 0x01;
        let frame = auth.encode();
        assert_eq!(
            handler.handle(frame).await.unwrap().0,
            CONTROL_STATUS_INVALID
        );
    }

    #[tokio::test]
    async fn rejects_unknown_opcode() {
        let hub = TestHub::start().await;
        let handler = HubControlHandler::new(Arc::clone(&hub.state));
        let frame = vec![0x99, 0, 0, 0];
        assert_eq!(
            handler.handle(frame).await.unwrap().0,
            CONTROL_STATUS_NOT_IMPLEMENTED
        );
    }
}
