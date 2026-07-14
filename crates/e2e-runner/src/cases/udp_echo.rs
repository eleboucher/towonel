use std::time::Duration;

use anyhow::{Result, bail, ensure};
use tokio::net::UdpSocket;

pub async fn run(edge_host: &str, port: u16) -> Result<()> {
    let payload = b"hello-udp-e2e";
    let reply = echo_roundtrip(edge_host, port, payload, 10).await?;
    ensure!(reply == payload, "udp echo mismatch: {reply:?}");
    tracing::info!("udp_echo: PASS");
    Ok(())
}

/// Send `payload` to `host:port` over a fresh UDP socket and return the reply.
/// UDP is lossy and the edge session takes a moment to establish on first
/// contact, so retry a bounded number of times before giving up.
pub async fn echo_roundtrip(
    host: &str,
    port: u16,
    payload: &[u8],
    attempts: usize,
) -> Result<Vec<u8>> {
    for attempt in 1..=attempts {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect((host, port)).await?;
        sock.send(payload).await?;
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(Err(e)) => tracing::debug!(attempt, error = %e, "udp recv error; retrying"),
            Err(_) => tracing::debug!(attempt, "udp recv timeout; retrying"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("no udp reply from {host}:{port} after {attempts} attempts")
}

/// True if no reply arrives within a short budget — used to assert a port has
/// no forwarding listener.
pub async fn no_reply(host: &str, port: u16) -> Result<bool> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((host, port)).await?;
    sock.send(b"probe").await?;
    let mut buf = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
        Ok(Ok(_)) => Ok(false),
        // A timeout, or an ICMP-driven connection-refused, both mean nothing
        // is forwarding this port.
        Ok(Err(_)) | Err(_) => Ok(true),
    }
}
