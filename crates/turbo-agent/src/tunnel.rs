use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use iroh::EndpointId;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{Instrument, info, info_span, warn};

use turbo_common::tunnel::read_hostname_header;

use crate::config::ServiceConfig;

/// Maps hostname to local origin address (e.g., "127.0.0.1:8080").
pub struct ServiceMap {
    services: HashMap<String, String>,
}

impl ServiceMap {
    pub fn from_config(services: &[ServiceConfig]) -> Self {
        let mut map = HashMap::new();
        for svc in services {
            map.insert(svc.hostname.to_lowercase(), svc.origin.clone());
        }
        Self { services: map }
    }

    pub fn lookup(&self, hostname: &str) -> Option<&str> {
        let lower = hostname.to_lowercase();
        if let Some(origin) = self.services.get(&lower) {
            return Some(origin.as_str());
        }
        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            if let Some(origin) = self.services.get(&wildcard) {
                return Some(origin.as_str());
            }
        }
        None
    }
}

/// Run the agent tunnel: accept incoming connections from edges and forward
/// each stream to the matching local origin service.
///
/// Connections from peers not in `trusted_edges` are rejected, unless
/// `allow_any_edge` is true (insecure, for local testing).
pub async fn run(
    endpoint: &iroh::Endpoint,
    service_map: Arc<ServiceMap>,
    trusted_edges: HashSet<EndpointId>,
    allow_any_edge: bool,
) -> anyhow::Result<()> {
    if allow_any_edge {
        warn!(
            "--allow-any-edge is set: accepting connections from ANY peer on the iroh \
             network. DO NOT USE IN PRODUCTION."
        );
    } else {
        info!(count = trusted_edges.len(), "trusted edge allowlist loaded");
    }

    info!("agent tunnel ready, waiting for connections from edges");

    loop {
        let incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => {
                info!("endpoint closed, shutting down");
                return Ok(());
            }
        };

        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("failed to accept connection: {e}");
                continue;
            }
        };

        let remote_id = conn.remote_id();

        if !allow_any_edge && !trusted_edges.contains(&remote_id) {
            warn!(
                remote = %remote_id.fmt_short(),
                "rejected connection from untrusted edge"
            );
            conn.close(403u32.into(), b"not authorized");
            continue;
        }

        info!(%remote_id, "accepted connection from edge");

        let map = Arc::clone(&service_map);
        tokio::spawn(async move {
            handle_connection(conn, remote_id, map).await;
        });
    }
}

async fn handle_connection(
    conn: iroh::endpoint::Connection,
    remote_id: iroh::EndpointId,
    service_map: Arc<ServiceMap>,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                info!("connection closed: {e}");
                return;
            }
        };

        let map = Arc::clone(&service_map);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &map, remote_id).await {
                warn!("stream error: {e}");
            }
        });
    }
}

async fn handle_stream(
    mut quic_send: iroh::endpoint::SendStream,
    mut quic_recv: iroh::endpoint::RecvStream,
    service_map: &ServiceMap,
    edge_id: iroh::EndpointId,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let hostname = read_hostname_header(&mut quic_recv)
        .await
        .context("failed to read hostname header")?;

    let origin = service_map
        .lookup(&hostname)
        .ok_or_else(|| anyhow::anyhow!("no service configured for hostname {hostname}"))?;

    let span = info_span!("stream",
        %hostname,
        %origin,
        edge = %edge_id.fmt_short(),
    );

    async {
        info!("forwarding to origin");

        let origin_stream = TcpStream::connect(origin)
            .await
            .with_context(|| format!("failed to connect to origin {origin}"))?;

        let (mut origin_read, mut origin_write) = origin_stream.into_split();

        let quic_to_origin = async {
            let res = io::copy(&mut quic_recv, &mut origin_write).await;
            let _ = origin_write.shutdown().await; // close TCP write -> origin sees EOF
            res
        };

        let origin_to_quic = async {
            let res = io::copy(&mut origin_read, &mut quic_send).await;
            let _ = quic_send.finish();
            res
        };

        let (q2o, o2q) = tokio::join!(quic_to_origin, origin_to_quic);

        if let Err(e) = &q2o {
            warn!("edge->origin: {e}");
        }
        if let Err(e) = &o2q {
            warn!("origin->edge: {e}");
        }

        let bytes_in = q2o.unwrap_or(0);
        let bytes_out = o2q.unwrap_or(0);

        info!(
            bytes_in,
            bytes_out,
            duration_ms = start.elapsed().as_millis() as u64,
            "stream closed"
        );
        Ok(())
    }
    .instrument(span)
    .await
}
