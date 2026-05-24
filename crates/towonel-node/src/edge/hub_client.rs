use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use towonel_common::edge_link::EdgeToHub;
use towonel_common::identity::{AgentId, TenantId};
use towonel_common::routing::RouteTable;
use towonel_common::tunnel::{CONTROL_STATUS_INTERNAL_ERROR, CONTROL_STATUS_NOT_IMPLEMENTED};

use super::hub_link::HubLinkHandle;

const CONTROL_RELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Late-binding handle the hub fills with its `LivenessStore` once
/// `AppState` is built; empty before then.
pub type LivenessCell = Arc<OnceLock<Arc<dyn crate::hub::liveness::LivenessStore>>>;

pub type RouteStream = Pin<Box<dyn Stream<Item = RouteTable> + Send + 'static>>;

/// `(status_byte, response_body)` written back on the same QUIC stream.
pub type ControlResponse = (u8, Vec<u8>);

/// Hub-side handler. Until the cell is set, control frames get
/// `NOT_IMPLEMENTED` — gives the boot sequence room to wire `AppState`
/// after the edge has already started accepting streams.
#[async_trait::async_trait]
pub trait ControlFrameHandler: Send + Sync {
    async fn handle(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse>;
}

pub type ControlHandlerCell = Arc<OnceLock<Arc<dyn ControlFrameHandler>>>;

#[async_trait::async_trait]
pub trait HubClient: Send + Sync {
    fn subscribe_routes(&self) -> RouteStream;

    /// Hub verifies the frame; the edge does not inspect it.
    async fn handle_control_frame(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse>;

    /// Best-effort; the next route rebuild or a reconnect `SessionsSnapshot`
    /// repairs any miss.
    async fn record_session_added(&self, tenant_id: TenantId, agent_id: AgentId);

    async fn record_session_removed(&self, tenant_id: TenantId, agent_id: AgentId);
}

pub struct InProcessHubClient {
    rx: Mutex<Option<broadcast::Receiver<RouteTable>>>,
    tx: broadcast::Sender<RouteTable>,
    control_handler: ControlHandlerCell,
    liveness: LivenessCell,
}

impl InProcessHubClient {
    pub fn new(
        tx: broadcast::Sender<RouteTable>,
        control_handler: ControlHandlerCell,
        liveness: LivenessCell,
    ) -> Self {
        let rx = tx.subscribe();
        Self {
            rx: Mutex::new(Some(rx)),
            tx,
            control_handler,
            liveness,
        }
    }
}

#[async_trait::async_trait]
impl HubClient for InProcessHubClient {
    fn subscribe_routes(&self) -> RouteStream {
        let rx = {
            let mut guard = self
                .rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        }
        .unwrap_or_else(|| self.tx.subscribe());
        Box::pin(BroadcastStream::new(rx).filter_map(|res| match res {
            Ok(table) => Some(table),
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "in-process route stream lagged");
                None
            }
        }))
    }

    async fn handle_control_frame(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse> {
        match self.control_handler.get() {
            Some(handler) => handler.handle(frame).await,
            None => Ok((CONTROL_STATUS_NOT_IMPLEMENTED, Vec::new())),
        }
    }

    async fn record_session_added(&self, tenant_id: TenantId, agent_id: AgentId) {
        let Some(liveness) = self.liveness.get() else {
            return;
        };
        if let Err(e) = liveness
            .bump(&tenant_id, &agent_id, towonel_common::time::now_ms())
            .await
        {
            tracing::warn!(error = %e, "in-process liveness bump failed");
        }
    }

    async fn record_session_removed(&self, _tenant_id: TenantId, _agent_id: AgentId) {
        // Single-hub volatile model: prune loop ages stale rows out.
    }
}

/// `HubClient` over the edge's `hub_link` transport.
pub struct RemoteHubClient {
    link: HubLinkHandle,
}

impl RemoteHubClient {
    #[must_use]
    pub const fn new(link: HubLinkHandle) -> Self {
        Self { link }
    }

    fn forget_pending(&self, request_id: u64) {
        let mut guard = self
            .link
            .pending_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(&request_id);
    }
}

#[async_trait::async_trait]
impl HubClient for RemoteHubClient {
    fn subscribe_routes(&self) -> RouteStream {
        let rx = self.link.route_tx.subscribe();
        Box::pin(BroadcastStream::new(rx).filter_map(|res| match res {
            Ok(table) => Some(table),
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "remote route stream lagged");
                None
            }
        }))
    }

    async fn handle_control_frame(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse> {
        let request_id = self.link.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self
                .link
                .pending_control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.insert(request_id, tx);
        }
        let send_result = self
            .link
            .control_request_tx
            .try_send(EdgeToHub::ControlRequest { request_id, frame });
        if let Err(e) = send_result {
            self.forget_pending(request_id);
            tracing::warn!(error = %e, "hub_link control request queue full or closed");
            return Ok((CONTROL_STATUS_INTERNAL_ERROR, Vec::new()));
        }

        match tokio::time::timeout(CONTROL_RELAY_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                tracing::debug!(request_id, "control relay sender dropped");
                Ok((CONTROL_STATUS_INTERNAL_ERROR, Vec::new()))
            }
            Err(_) => {
                self.forget_pending(request_id);
                tracing::warn!(request_id, "control relay timed out");
                Ok((CONTROL_STATUS_INTERNAL_ERROR, Vec::new()))
            }
        }
    }

    async fn record_session_added(&self, tenant_id: TenantId, agent_id: AgentId) {
        if let Err(e) = self
            .link
            .session_event_tx
            .try_send(EdgeToHub::SessionAdded {
                agent_id,
                tenant_id,
            })
        {
            tracing::warn!(error = %e, "hub_link session event queue full or closed");
        }
    }

    async fn record_session_removed(&self, _tenant_id: TenantId, agent_id: AgentId) {
        if let Err(e) = self
            .link
            .session_event_tx
            .try_send(EdgeToHub::SessionRemoved { agent_id })
        {
            tracing::warn!(error = %e, "hub_link session event queue full or closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replays_pre_subscribe_broadcast() {
        let (tx, _) = broadcast::channel(8);
        let client = InProcessHubClient::new(
            tx.clone(),
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
        );

        tx.send(RouteTable::from_raw(std::collections::HashMap::new()))
            .unwrap();

        let mut stream = client.subscribe_routes();
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap();
        assert!(got.is_some());
    }

    #[tokio::test]
    async fn handle_control_frame_returns_not_implemented_by_default() {
        let (tx, _) = broadcast::channel(8);
        let client =
            InProcessHubClient::new(tx, Arc::new(OnceLock::new()), Arc::new(OnceLock::new()));
        let (status, body) = client
            .handle_control_frame(b"anything".to_vec())
            .await
            .unwrap();
        assert_eq!(status, CONTROL_STATUS_NOT_IMPLEMENTED);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn remote_client_relays_control_frame_round_trip() {
        use towonel_common::edge_link::HubToEdge;

        let handle = HubLinkHandle::new(8);
        let client = RemoteHubClient::new(handle.clone());

        let mut outbound = handle
            .control_request_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("control_request_rx already taken");

        let call =
            tokio::spawn(async move { client.handle_control_frame(vec![9, 9, 9]).await.unwrap() });

        let req = outbound.recv().await.expect("outbound request missing");
        let request_id = match req {
            EdgeToHub::ControlRequest { request_id, frame } => {
                assert_eq!(frame, vec![9, 9, 9]);
                request_id
            }
            other => panic!("expected ControlRequest, got {other:?}"),
        };

        crate::edge::hub_link::deliver_hub_frame_for_test(
            &handle,
            HubToEdge::ControlResponse {
                request_id,
                status: 0,
                body: vec![1, 2, 3],
            },
        );

        let (status, body) = tokio::time::timeout(Duration::from_secs(2), call)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 0);
        assert_eq!(body, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn remote_client_returns_internal_error_when_link_drops_mid_rpc() {
        let handle = HubLinkHandle::new(8);
        let client = RemoteHubClient::new(handle.clone());

        // Simulates `drain_pending_control` on disconnect — same effect on the caller.
        let _outbound = handle
            .control_request_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("control_request_rx already taken");

        let call = tokio::spawn(async move { client.handle_control_frame(vec![1]).await.unwrap() });

        for _ in 0..100 {
            tokio::task::yield_now().await;
            let cleared = {
                let mut guard = handle
                    .pending_control
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if guard.is_empty() {
                    false
                } else {
                    guard.clear();
                    true
                }
            };
            if cleared {
                break;
            }
        }

        let (status, body) = tokio::time::timeout(Duration::from_secs(2), call)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, CONTROL_STATUS_INTERNAL_ERROR);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn second_subscribe_only_sees_new_updates() {
        let (tx, _) = broadcast::channel(8);
        let client = InProcessHubClient::new(
            tx.clone(),
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
        );

        let _consumed = client.subscribe_routes();
        let mut second = client.subscribe_routes();

        tx.send(RouteTable::from_raw(std::collections::HashMap::new()))
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), second.next())
            .await
            .unwrap();
        assert!(got.is_some());
    }
}
