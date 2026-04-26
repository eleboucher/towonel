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
use towonel_common::metrics::GaugeGuard;
use towonel_common::tunnel::{
    COPY_BUF_SIZE, ClientAddrs, TCP_ROUTE_PREFIX, forward_quic_to_writer, read_handshake,
};

use crate::config::{ProxyProtocol, ServiceConfig, TcpServiceConfig};
use crate::metrics::{self, AgentMetrics};

mod proxy_protocol;

const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

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

/// Like [`OriginTarget`] but without TLS or PROXY-protocol rewriting —
/// TCP services pipe bytes verbatim.
struct TcpOriginTarget {
    address: String,
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
}

impl TcpOriginTarget {
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
                debug!(origin = %self.address, error = %e, "tcp cached addrs exhausted, re-resolving");
            }
        }
        TcpStream::connect(&self.address)
            .await
            .with_context(|| format!("failed to connect to tcp origin {}", self.address))
    }
}

pub struct ServiceMap {
    services: HashMap<String, Arc<OriginTarget>>,
    tcp_services: HashMap<String, Arc<TcpOriginTarget>>,
    /// Shared rustls client config for TLS-wrapped origin connections. Built
    /// once at startup from the webpki roots and reused for every stream.
    tls_config: Arc<rustls::ClientConfig>,
}

impl ServiceMap {
    pub async fn from_config(
        services: &[ServiceConfig],
        tcp_services: &[TcpServiceConfig],
    ) -> anyhow::Result<Self> {
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

        let mut tcp_map: HashMap<String, Arc<TcpOriginTarget>> = HashMap::new();
        for svc in tcp_services {
            let (initial, is_literal) = resolve_origin(&svc.origin).await;
            let target = Arc::new(TcpOriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
            });
            tcp_map.insert(svc.name.clone(), target);
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
            tcp_services: tcp_map,
            tls_config,
        })
    }

    /// Runs for the lifetime of the agent; no handle is returned because
    /// there is no cooperative shutdown path to call it from.
    pub fn spawn_dns_refresher(&self) {
        let hostname_targets: Vec<Arc<OriginTarget>> = self
            .services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        let tcp_targets: Vec<Arc<TcpOriginTarget>> = self
            .tcp_services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        if hostname_targets.is_empty() && tcp_targets.is_empty() {
            return;
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DNS_REFRESH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // tokio interval fires immediately; skip it
            loop {
                ticker.tick().await;
                for target in &hostname_targets {
                    refresh_addr(&target.address, &target.resolved).await;
                }
                for target in &tcp_targets {
                    refresh_addr(&target.address, &target.resolved).await;
                }
            }
        });
    }

    fn lookup(&self, hostname: &str) -> Option<&Arc<OriginTarget>> {
        wildcard_lookup(hostname, |key| self.services.get(key))
    }

    fn lookup_tcp(&self, name: &str) -> Option<&Arc<TcpOriginTarget>> {
        self.tcp_services.get(name)
    }
}

async fn refresh_addr(address: &str, resolved: &ArcSwap<Vec<SocketAddr>>) {
    match lookup_host(address).await {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if !addrs.is_empty() {
                resolved.store(Arc::new(addrs));
            }
        }
        Err(e) => {
            debug!(origin = %address, error = %e, "DNS refresh failed");
        }
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
    let _active = GaugeGuard::inc(&metrics.streams_active);

    let handshake = async {
        read_handshake(&mut quic_recv)
            .await
            .context("failed to read PROXY v2 preamble")
    };
    let (route_key, client_addrs) =
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

    if let Some(service_name) = route_key.strip_prefix(TCP_ROUTE_PREFIX) {
        return handle_tcp_stream(
            service_name,
            client_addrs,
            quic_send,
            quic_recv,
            service_map,
            edge_id,
            metrics,
            start,
        )
        .await;
    }

    let hostname = route_key;
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
async fn handle_tcp_stream(
    service_name: &str,
    client_addrs: ClientAddrs,
    mut quic_send: iroh::endpoint::SendStream,
    mut quic_recv: iroh::endpoint::RecvStream,
    service_map: &ServiceMap,
    edge_id: iroh::EndpointId,
    metrics: &AgentMetrics,
    start: Instant,
) -> anyhow::Result<()> {
    let Some(target) = service_map.lookup_tcp(service_name) else {
        metrics.record_stream_error(metrics::stream_error::NO_SERVICE);
        return Err(anyhow::anyhow!(
            "no tcp service configured for `{service_name}`"
        ));
    };

    let span = info_span!("tcp_stream",
        service = %service_name,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        debug!("forwarding tcp service to origin");
        let origin = match target.connect().await {
            Ok(s) => s,
            Err(e) => {
                metrics.record_stream_error(metrics::stream_error::ORIGIN_CONNECT);
                return Err(e);
            }
        };
        if let Err(e) = origin.set_nodelay(true) {
            warn!(origin = %target.address, error = %e, "failed to set TCP_NODELAY on tcp origin");
        }

        let (origin_read, mut origin_write) = origin.into_split();
        let mut origin_read = io::BufReader::with_capacity(COPY_BUF_SIZE, origin_read);

        let q2o = async {
            let res = forward_quic_to_writer(Vec::new(), &mut quic_recv, &mut origin_write).await;
            let _ = origin_write.shutdown().await;
            res
        };
        let o2q = async {
            let res = io::copy_buf(&mut origin_read, &mut quic_send).await;
            let _ = quic_send.finish();
            res
        };

        let (r1, r2) = tokio::join!(q2o, o2q);
        match &r1 {
            Ok(n) => metrics.add_bytes(metrics::direction::EDGE_TO_ORIGIN, *n),
            Err(e) => warn!("edge->tcp-origin: {e}"),
        }
        match &r2 {
            Ok(n) => metrics.add_bytes(metrics::direction::ORIGIN_TO_EDGE, *n),
            Err(e) => warn!("tcp-origin->edge: {e}"),
        }

        metrics.streams_completed.inc();
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(duration_ms, "tcp stream closed");
        Ok(())
    }
    .instrument(span)
    .await
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
