use std::pin::Pin;
use std::sync::Mutex;

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use towonel_common::routing::RouteTable;
use towonel_common::tunnel::CONTROL_STATUS_NOT_IMPLEMENTED;

pub type RouteStream = Pin<Box<dyn Stream<Item = RouteTable> + Send + 'static>>;

/// `(status_byte, response_body)` written back on the same QUIC stream.
pub type ControlResponse = (u8, Vec<u8>);

#[async_trait::async_trait]
pub trait HubClient: Send + Sync {
    fn subscribe_routes(&self) -> RouteStream;

    /// Hub verifies the frame; the edge does not inspect it.
    async fn handle_control_frame(&self, frame: Vec<u8>) -> anyhow::Result<ControlResponse>;
}

pub struct InProcessHubClient {
    rx: Mutex<Option<broadcast::Receiver<RouteTable>>>,
    tx: broadcast::Sender<RouteTable>,
}

impl InProcessHubClient {
    pub fn new(tx: broadcast::Sender<RouteTable>) -> Self {
        let rx = tx.subscribe();
        Self {
            rx: Mutex::new(Some(rx)),
            tx,
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

    async fn handle_control_frame(&self, _frame: Vec<u8>) -> anyhow::Result<ControlResponse> {
        Ok((CONTROL_STATUS_NOT_IMPLEMENTED, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replays_pre_subscribe_broadcast() {
        let (tx, _) = broadcast::channel(8);
        let client = InProcessHubClient::new(tx.clone());

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
        let client = InProcessHubClient::new(tx);
        let (status, body) = client
            .handle_control_frame(b"anything".to_vec())
            .await
            .unwrap();
        assert_eq!(status, CONTROL_STATUS_NOT_IMPLEMENTED);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn second_subscribe_only_sees_new_updates() {
        let (tx, _) = broadcast::channel(8);
        let client = InProcessHubClient::new(tx.clone());

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
