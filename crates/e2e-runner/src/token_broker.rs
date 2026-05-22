use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};

#[derive(Clone)]
pub struct Broker {
    token: Arc<String>,
}

impl Broker {
    pub fn new(token: String) -> Self {
        Self {
            token: Arc::new(token),
        }
    }

    pub async fn serve(self, listen: SocketAddr) -> Result<tokio::task::JoinHandle<()>> {
        let app = Router::new()
            .route("/token", get(get_token))
            .with_state(self);
        let listener = tokio::net::TcpListener::bind(listen).await?;
        Ok(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "broker exited");
            }
        }))
    }
}

async fn get_token(State(b): State<Broker>) -> impl IntoResponse {
    (StatusCode::OK, (*b.token).clone())
}
