use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ppp::v2;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Buffer size for `tokio::io::copy_buf` on agent↔edge bidirectional pipes.
/// 64 KiB matches QUIC's typical window-unit and keeps syscall count low on
/// bulk transfers.
pub const COPY_BUF_SIZE: usize = 64 * 1024;

/// Marks a stream's AUTHORITY TLV as a raw TCP service rather than a hostname.
///
/// The edge writes this prefix; the agent strips it to dispatch to its TCP
/// origin map. Wire constant — must match exactly on both ends.
pub const TCP_ROUTE_PREFIX: &str = "tcp:";

/// Zero-copy forward from an iroh `RecvStream` to any `AsyncWrite` via
/// `read_chunk` (bypasses an intermediate `BufReader` memcpy).
///
/// An optional `prefix` (e.g. PROXY v2 header) is coalesced with the first
/// QUIC chunk into a single `write_all`, so with `TCP_NODELAY` set the peer
/// sees one segment instead of two back-to-back tiny ones. Pass `Vec::new()`
/// when no prefix is needed — the `is_empty` branch elides the extra copy.
pub async fn forward_quic_to_writer<W>(
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

/// Original client `SocketAddr` and the edge-facing destination `SocketAddr`.
/// Both are forwarded to the agent so it can emit a PROXY v2 header to the
/// origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddrs {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Fixed PROXY v2 header length: 12-byte signature + 4-byte version/fam/len.
const V2_PREAMBLE_LEN: usize = 16;

/// Write the edge→agent preamble as a PROXY v2 header whose AUTHORITY TLV
/// carries the SNI hostname. The agent reads this once and extracts both
/// client addrs and hostname.
pub async fn write_handshake(
    stream: &mut (impl AsyncWrite + Unpin),
    hostname: &str,
    addrs: ClientAddrs,
) -> std::io::Result<()> {
    let bytes = encode_proxy_v2_with_authority(hostname, addrs)?;
    stream.write_all(&bytes).await
}

fn encode_proxy_v2_with_authority(hostname: &str, addrs: ClientAddrs) -> std::io::Result<Vec<u8>> {
    let (src, dst) = unmap_to_matching_family(addrs.src, addrs.dst).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "src and dst address families differ",
        )
    })?;
    v2::Builder::with_addresses(
        v2::Version::Two | v2::Command::Proxy,
        v2::Protocol::Stream,
        (src, dst),
    )
    .write_tlv(v2::Type::Authority, hostname.as_bytes())
    .and_then(ppp::v2::Builder::build)
    .map_err(std::io::Error::other)
}

/// Read the edge→agent PROXY v2 preamble and return (hostname, addrs).
pub async fn read_handshake(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<(String, ClientAddrs)> {
    let mut preamble = [0u8; V2_PREAMBLE_LEN];
    stream.read_exact(&mut preamble).await?;
    let body_len = u16::from_be_bytes([preamble[14], preamble[15]]) as usize;
    let mut all = preamble.to_vec();
    all.resize(V2_PREAMBLE_LEN + body_len, 0);
    stream.read_exact(&mut all[V2_PREAMBLE_LEN..]).await?;

    let header = v2::Header::try_from(all.as_slice()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid PROXY v2 header: {e}"),
        )
    })?;

    let addrs = match header.addresses {
        v2::Addresses::IPv4(v4) => ClientAddrs {
            src: SocketAddr::V4(SocketAddrV4::new(v4.source_address, v4.source_port)),
            dst: SocketAddr::V4(SocketAddrV4::new(
                v4.destination_address,
                v4.destination_port,
            )),
        },
        v2::Addresses::IPv6(v6) => ClientAddrs {
            src: SocketAddr::V6(SocketAddrV6::new(v6.source_address, v6.source_port, 0, 0)),
            dst: SocketAddr::V6(SocketAddrV6::new(
                v6.destination_address,
                v6.destination_port,
                0,
                0,
            )),
        },
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported PROXY v2 address family: {other:?}"),
            ));
        }
    };

    let authority_code = u8::from(v2::Type::Authority);
    for tlv in header.tlvs() {
        let tlv = tlv.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid PROXY v2 TLV: {e}"),
            )
        })?;
        if tlv.kind == authority_code {
            let hostname = std::str::from_utf8(&tlv.value)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("hostname is not valid UTF-8: {e}"),
                    )
                })?
                .to_string();
            return Ok((hostname, addrs));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "PROXY v2 preamble missing AUTHORITY TLV (hostname)",
    ))
}

/// Dual-stack sockets surface IPv4 peers as `::ffff:a.b.c.d`. Unmap src and
/// dst back to native v4 so `(src, dst)` share a family before encoding.
fn unmap_to_matching_family(src: SocketAddr, dst: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
    let src = unmap_v4(src);
    let dst = unmap_v4(dst);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Some((src, dst)),
        _ => None,
    }
}

fn unmap_v4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_handshake_v4() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let hostname = "app.example.com";
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };

        write_handshake(&mut client, hostname, addrs).await.unwrap();
        drop(client);

        let (got_hostname, got_addrs) = read_handshake(&mut server).await.unwrap();
        assert_eq!(got_hostname, hostname);
        assert_eq!(got_addrs, addrs);
    }

    #[tokio::test]
    async fn roundtrip_handshake_v6() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let hostname = "app.example.com";
        let addrs = ClientAddrs {
            src: "[2001:db8::1]:54321".parse().unwrap(),
            dst: "[2001:db8::2]:443".parse().unwrap(),
        };

        write_handshake(&mut client, hostname, addrs).await.unwrap();
        drop(client);

        let (got_hostname, got_addrs) = read_handshake(&mut server).await.unwrap();
        assert_eq!(got_hostname, hostname);
        assert_eq!(got_addrs, addrs);
    }

    #[tokio::test]
    async fn dual_stack_v4_mapped_v6_is_unmapped() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let addrs = ClientAddrs {
            src: "[::ffff:203.0.113.7]:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };

        write_handshake(&mut client, "a.b", addrs).await.unwrap();
        drop(client);

        let (_, got) = read_handshake(&mut server).await.unwrap();
        assert_eq!(got.src, "203.0.113.7:54321".parse::<SocketAddr>().unwrap());
        assert_eq!(got.dst, "192.0.2.1:443".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn mixed_family_errors() {
        let mut buf = Vec::new();
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "[2001:db8::2]:443".parse().unwrap(),
        };
        let err = write_handshake(&mut buf, "a.b", addrs).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
