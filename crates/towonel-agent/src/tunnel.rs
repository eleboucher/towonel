use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use iroh::EndpointId;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::tunnel::{ClientAddrs, read_client_addrs, read_hostname_header};

use crate::config::{ProxyProtocol, ServiceConfig};

mod proxy_protocol;

const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const COPY_BUF_SIZE: usize = 64 * 1024;

async fn write_proxy_header(
    stream: &mut (impl AsyncWrite + Unpin),
    mode: ProxyProtocol,
    addrs: ClientAddrs,
) -> anyhow::Result<()> {
    if mode != ProxyProtocol::V2 {
        return Ok(());
    }
    let bytes = proxy_protocol::encode_v2(addrs)?;
    stream.write_all(&bytes).await?;
    Ok(())
}

struct OriginTarget {
    address: String,
    /// Empty means resolution has never succeeded; callers fall back to a
    /// direct `TcpStream::connect(&address)` so a transient DNS outage at
    /// startup doesn't permanently break a service.
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
    server_name: Option<String>,
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
    pub async fn from_config(services: &[ServiceConfig]) -> Self {
        let mut map: HashMap<String, Arc<OriginTarget>> = HashMap::new();
        for svc in services {
            let (initial, is_literal) = resolve_origin(&svc.origin).await;
            let target = Arc::new(OriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
                server_name: svc.origin_server_name.clone(),
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

        Self {
            services: map,
            tls_config,
        }
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
        let lower = hostname.to_lowercase();
        if let Some(target) = self.services.get(&lower) {
            return Some(target);
        }
        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            if let Some(target) = self.services.get(&wildcard) {
                return Some(target);
            }
        }
        None
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

    let client_addrs = read_client_addrs(&mut quic_recv)
        .await
        .context("failed to read client-addrs header")?;

    let target = service_map
        .lookup(&hostname)
        .ok_or_else(|| anyhow::anyhow!("no service configured for hostname {hostname}"))?;

    let span = info_span!("stream",
        %hostname,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        info!("forwarding to origin");

        let tcp_stream = target.connect().await?;
        if let Err(e) = tcp_stream.set_nodelay(true) {
            warn!(origin = %target.address, error = %e, "failed to set TCP_NODELAY on origin socket");
        }

        match &target.server_name {
            Some(sni) => {
                forward_tls(
                    tcp_stream,
                    sni,
                    Arc::clone(&service_map.tls_config),
                    target.proxy_protocol,
                    client_addrs,
                    &mut quic_recv,
                    &mut quic_send,
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
                )
                .await
            }
        }?;

        // truncation is intentional: streams won't last 584 million years
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;
        info!(duration_ms, "stream closed");
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
) -> anyhow::Result<()> {
    let (origin_read, mut origin_write) = origin.into_split();
    let mut origin_read = io::BufReader::with_capacity(COPY_BUF_SIZE, origin_read);
    let mut quic_recv = io::BufReader::with_capacity(COPY_BUF_SIZE, quic_recv);

    write_proxy_header(&mut origin_write, proxy, addrs).await?;

    let q2o = async {
        let res = io::copy_buf(&mut quic_recv, &mut origin_write).await;
        let _ = origin_write.shutdown().await;
        res
    };
    let o2q = async {
        let res = io::copy_buf(&mut origin_read, quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let (r1, r2) = tokio::join!(q2o, o2q);
    if let Err(e) = &r1 {
        warn!("edge->origin: {e}");
    }
    if let Err(e) = &r2 {
        warn!("origin->edge: {e}");
    }
    Ok(())
}

async fn forward_tls(
    mut origin: TcpStream,
    server_name: &str,
    tls_config: Arc<rustls::ClientConfig>,
    proxy: ProxyProtocol,
    addrs: ClientAddrs,
    quic_recv: &mut iroh::endpoint::RecvStream,
    quic_send: &mut iroh::endpoint::SendStream,
) -> anyhow::Result<()> {
    // PROXY v2 must precede the TLS ClientHello so the origin's TLS layer
    // sees a normal handshake after consuming the header.
    write_proxy_header(&mut origin, proxy, addrs).await?;

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let dns_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| anyhow::anyhow!("invalid origin_server_name `{server_name}`: {e}"))?;

    let tls_stream = connector
        .connect(dns_name, origin)
        .await
        .with_context(|| format!("TLS handshake with origin failed (SNI: {server_name})"))?;

    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_read = io::BufReader::with_capacity(COPY_BUF_SIZE, tls_read);
    let mut quic_recv = io::BufReader::with_capacity(COPY_BUF_SIZE, quic_recv);

    let q2o = async {
        let res = io::copy_buf(&mut quic_recv, &mut tls_write).await;
        let _ = tls_write.shutdown().await;
        res
    };
    let o2q = async {
        let res = io::copy_buf(&mut tls_read, quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let (r1, r2) = tokio::join!(q2o, o2q);
    if let Err(e) = &r1 {
        warn!("edge->origin(tls): {e}");
    }
    if let Err(e) = &r2 {
        warn!("origin(tls)->edge: {e}");
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
