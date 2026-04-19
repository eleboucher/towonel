use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::EndpointId;
use rustls::pki_types::ServerName;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::hostname::wildcard_lookup;
use towonel_common::tunnel::{ClientAddrs, read_client_addrs, read_hostname_header};

use crate::config::{ProxyProtocol, ServiceConfig};
use crate::metrics::{self, ActiveStreamGuard, AgentMetrics};

mod proxy_protocol;

const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const COPY_BUF_SIZE: usize = 64 * 1024;

/// Cap on how long we wait for an edge to send the (hostname, client-addrs)
/// handshake bytes. Bounded to stop silent/malicious edges pinning tasks open.
const STREAM_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn write_proxy_header(
    stream: &mut (impl AsyncWrite + Unpin),
    mode: ProxyProtocol,
    addrs: ClientAddrs,
) -> anyhow::Result<()> {
    let bytes = encode_proxy_header(mode, addrs)?;
    if !bytes.is_empty() {
        stream.write_all(&bytes).await?;
    }
    Ok(())
}

fn encode_proxy_header(mode: ProxyProtocol, addrs: ClientAddrs) -> anyhow::Result<Vec<u8>> {
    if mode == ProxyProtocol::V2 {
        proxy_protocol::encode_v2(addrs)
    } else {
        Ok(Vec::new())
    }
}

struct OriginTarget {
    address: String,
    /// Empty means resolution has never succeeded; callers fall back to a
    /// direct `TcpStream::connect(&address)` so a transient DNS outage at
    /// startup doesn't permanently break a service.
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
    /// Precomputed rustls `ServerName` for TLS-wrapped origins. Parsed once
    /// at config load time; cloning at stream open is cheap (owned `DnsName`
    /// wrapper, no extra validation).
    server_name: Option<ServerName<'static>>,
    proxy_protocol: ProxyProtocol,
}

impl OriginTarget {
    async fn connect(&self) -> anyhow::Result<TcpStream> {
        let cached = self.resolved.load();
        if !cached.is_empty() {
            let mut last_err: Option<std::io::Error> = None;
            for addr in cached.iter() {
                match TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = Some(e),
                }
            }
            if let Some(e) = last_err {
                debug!(origin = %self.address, error = %e, "cached addrs exhausted, re-resolving");
            }
        }
        TcpStream::connect(&self.address)
            .await
            .with_context(|| format!("failed to connect to origin {}", self.address))
    }
}

pub struct ServiceMap {
    services: HashMap<String, Arc<OriginTarget>>,
    /// Shared rustls client config for TLS-wrapped origin connections. Built
    /// once at startup from the webpki roots and reused for every stream.
    tls_config: Arc<rustls::ClientConfig>,
}

impl ServiceMap {
    pub async fn from_config(services: &[ServiceConfig]) -> anyhow::Result<Self> {
        let mut map: HashMap<String, Arc<OriginTarget>> = HashMap::new();
        for svc in services {
            let (initial, is_literal) = resolve_origin(&svc.origin).await;
            let server_name = svc
                .origin_server_name
                .as_deref()
                .map(|name| {
                    ServerName::try_from(name.to_string()).map_err(|e| {
                        anyhow::anyhow!(
                            "service {:?}: invalid origin_server_name {name:?}: {e}",
                            svc.hostname
                        )
                    })
                })
                .transpose()?;
            let target = Arc::new(OriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
                server_name,
                proxy_protocol: svc.resolved_proxy_protocol(),
            });
            map.insert(svc.hostname.to_lowercase(), target);
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::in_memory_sessions(1024);
        let tls_config = Arc::new(config);

        Ok(Self {
            services: map,
            tls_config,
        })
    }

    /// Runs for the lifetime of the agent; no handle is returned because
    /// there is no cooperative shutdown path to call it from.
    pub fn spawn_dns_refresher(&self) {
        let targets: Vec<Arc<OriginTarget>> = self
            .services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        if targets.is_empty() {
            return;
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DNS_REFRESH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // tokio interval fires immediately; skip it
            loop {
                ticker.tick().await;
                for target in &targets {
                    match lookup_host(&target.address).await {
                        Ok(iter) => {
                            let addrs: Vec<SocketAddr> = iter.collect();
                            if !addrs.is_empty() {
                                target.resolved.store(Arc::new(addrs));
                            }
                        }
                        Err(e) => {
                            debug!(origin = %target.address, error = %e, "DNS refresh failed");
                        }
                    }
                }
            }
        });
    }

    fn lookup(&self, hostname: &str) -> Option<&Arc<OriginTarget>> {
        wildcard_lookup(hostname, |key| self.services.get(key))
    }
}

async fn resolve_origin(origin: &str) -> (Vec<SocketAddr>, bool) {
    if let Ok(addr) = origin.parse::<SocketAddr>() {
        return (vec![addr], true);
    }
    match lookup_host(origin).await {
        Ok(iter) => (iter.collect(), false),
        Err(e) => {
            warn!(origin, error = %e, "initial DNS resolution failed; will retry on first connect");
            (Vec::new(), false)
        }
    }
}

pub async fn run(
    endpoint: &iroh::Endpoint,
    service_map: Arc<ServiceMap>,
    trusted_edges: HashSet<EndpointId>,
    allow_any_edge: bool,
    metrics: Arc<AgentMetrics>,
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
        let Some(incoming) = endpoint.accept().await else {
            info!("endpoint closed, shutting down");
            return Ok(());
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
            metrics.edge_connections_rejected.inc();
            conn.close(403u32.into(), b"not authorized");
            continue;
        }

        info!(%remote_id, "accepted connection from edge");
        metrics.edge_connections_accepted.inc();

        let map = Arc::clone(&service_map);
        let m = Arc::clone(&metrics);
        tokio::spawn(async move {
            handle_connection(conn, remote_id, map, m).await;
        });
    }
}

async fn handle_connection(
    conn: iroh::endpoint::Connection,
    remote_id: iroh::EndpointId,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
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
        let m = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &map, remote_id, &m).await {
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
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    let start = Instant::now();
    metrics.streams_accepted.inc();
    let _active = ActiveStreamGuard::new(metrics);

    // Bound the pre-forward handshake so a misbehaving or silent edge can't
    // pin a spawned task open forever.
    let handshake = async {
        let hostname = read_hostname_header(&mut quic_recv)
            .await
            .context("failed to read hostname header")?;
        let client_addrs = read_client_addrs(&mut quic_recv)
            .await
            .context("failed to read client-addrs header")?;
        Ok::<_, anyhow::Error>((hostname, client_addrs))
    };
    let (hostname, client_addrs) =
        match tokio::time::timeout(STREAM_HANDSHAKE_TIMEOUT, handshake).await {
            Err(_) => {
                metrics.record_stream_error(metrics::stream_error::HANDSHAKE_TIMEOUT);
                return Err(anyhow::anyhow!("stream handshake timed out"));
            }
            Ok(Err(e)) => {
                metrics.record_stream_error(metrics::stream_error::HANDSHAKE_ERROR);
                return Err(e);
            }
            Ok(Ok(v)) => v,
        };

    let Some(target) = service_map.lookup(&hostname) else {
        metrics.record_stream_error(metrics::stream_error::NO_SERVICE);
        return Err(anyhow::anyhow!(
            "no service configured for hostname {hostname}"
        ));
    };

    let span = info_span!("stream",
        %hostname,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        debug!("forwarding to origin");

        let tcp_stream = match target.connect().await {
            Ok(s) => s,
            Err(e) => {
                metrics.record_stream_error(metrics::stream_error::ORIGIN_CONNECT);
                return Err(e);
            }
        };
        if let Err(e) = tcp_stream.set_nodelay(true) {
            warn!(origin = %target.address, error = %e, "failed to set TCP_NODELAY on origin socket");
        }

        let forward_res = match &target.server_name {
            Some(sni) => {
                forward_tls(
                    tcp_stream,
                    sni.clone(),
                    Arc::clone(&service_map.tls_config),
                    target.proxy_protocol,
                    client_addrs,
                    &mut quic_recv,
                    &mut quic_send,
                    metrics,
                )
                .await
            }
            None => {
                forward_plain(
                    tcp_stream,
                    target.proxy_protocol,
                    client_addrs,
                    &mut quic_recv,
                    &mut quic_send,
                    metrics,
                )
                .await
            }
        };

        if let Err(e) = forward_res {
            metrics.record_stream_error(metrics::stream_error::FORWARD_ERROR);
            return Err(e);
        }

        metrics.streams_completed.inc();
        // truncation is intentional: streams won't last 584 million years
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(duration_ms, "stream closed");
        Ok(())
    }
    .instrument(span)
    .await
}

async fn forward_plain(
    origin: TcpStream,
    proxy: ProxyProtocol,
    addrs: ClientAddrs,
    quic_recv: &mut iroh::endpoint::RecvStream,
    quic_send: &mut iroh::endpoint::SendStream,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    let (origin_read, mut origin_write) = origin.into_split();
    let mut origin_read = io::BufReader::with_capacity(COPY_BUF_SIZE, origin_read);

    let proxy_prefix = encode_proxy_header(proxy, addrs)?;

    let q2o = async {
        let res = forward_quic_to_writer(proxy_prefix, quic_recv, &mut origin_write).await;
        let _ = origin_write.shutdown().await;
        res
    };
    let o2q = async {
        let res = io::copy_buf(&mut origin_read, quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let (r1, r2) = tokio::join!(q2o, o2q);
    match &r1 {
        Ok(n) => metrics.add_bytes(metrics::direction::EDGE_TO_ORIGIN, *n),
        Err(e) => warn!("edge->origin: {e}"),
    }
    match &r2 {
        Ok(n) => metrics.add_bytes(metrics::direction::ORIGIN_TO_EDGE, *n),
        Err(e) => warn!("origin->edge: {e}"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn forward_tls(
    mut origin: TcpStream,
    server_name: ServerName<'static>,
    tls_config: Arc<rustls::ClientConfig>,
    proxy: ProxyProtocol,
    addrs: ClientAddrs,
    quic_recv: &mut iroh::endpoint::RecvStream,
    quic_send: &mut iroh::endpoint::SendStream,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    // PROXY v2 must precede the TLS ClientHello so the origin's TLS layer
    // sees a normal handshake after consuming the header.
    write_proxy_header(&mut origin, proxy, addrs).await?;

    let sni_for_log = format!("{server_name:?}");
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls_stream = connector
        .connect(server_name, origin)
        .await
        .with_context(|| format!("TLS handshake with origin failed (SNI: {sni_for_log})"))?;

    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_read = io::BufReader::with_capacity(COPY_BUF_SIZE, tls_read);

    let q2o = async {
        let res = forward_quic_to_writer(Vec::new(), quic_recv, &mut tls_write).await;
        let _ = tls_write.shutdown().await;
        res
    };
    let o2q = async {
        let res = io::copy_buf(&mut tls_read, quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let (r1, r2) = tokio::join!(q2o, o2q);
    match &r1 {
        Ok(n) => metrics.add_bytes(metrics::direction::EDGE_TO_ORIGIN, *n),
        Err(e) => warn!("edge->origin(tls): {e}"),
    }
    match &r2 {
        Ok(n) => metrics.add_bytes(metrics::direction::ORIGIN_TO_EDGE, *n),
        Err(e) => warn!("origin(tls)->edge: {e}"),
    }
    Ok(())
}

/// Zero-copy forward from a QUIC `RecvStream` to any `AsyncWrite` via
/// `read_chunk` (avoids an intermediate `BufReader` memcpy).
///
/// An optional `prefix` (e.g. a PROXY v2 header) is coalesced with the first
/// QUIC chunk into a single `write_all`, so with `TCP_NODELAY` set the origin
/// sees one segment instead of two back-to-back tiny ones. Pass `Vec::new()`
/// when no prefix is needed.
async fn forward_quic_to_writer<W>(
    mut prefix: Vec<u8>,
    recv: &mut iroh::endpoint::RecvStream,
    writer: &mut W,
) -> std::io::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        match recv.read_chunk(COPY_BUF_SIZE).await {
            Ok(Some(chunk)) => {
                total = total.saturating_add(chunk.bytes.len() as u64);
                if prefix.is_empty() {
                    writer.write_all(&chunk.bytes).await?;
                } else {
                    prefix.extend_from_slice(&chunk.bytes);
                    writer.write_all(&prefix).await?;
                    prefix = Vec::new();
                }
            }
            Ok(None) => {
                if !prefix.is_empty() {
                    writer.write_all(&prefix).await?;
                }
                return Ok(total);
            }
            Err(e) => return Err(std::io::Error::other(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_addrs() -> ClientAddrs {
        ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn no_header_written_when_disabled() {
        let mut buf = Vec::new();
        write_proxy_header(&mut buf, ProxyProtocol::None, v4_addrs())
            .await
            .unwrap();
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn writes_v2_when_enabled() {
        let mut buf = Vec::new();
        write_proxy_header(&mut buf, ProxyProtocol::V2, v4_addrs())
            .await
            .unwrap();
        let header = ppp::v2::Header::try_from(buf.as_slice()).unwrap();
        assert_eq!(header.command, ppp::v2::Command::Proxy);
        assert!(matches!(header.addresses, ppp::v2::Addresses::IPv4(_)));
    }
}
