use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ppp::v2;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

/// Buffer size for `tokio::io::copy_buf` on agent↔edge bidirectional pipes.
/// 64 KiB matches QUIC's typical window-unit and keeps syscall count low on
/// bulk transfers.
pub const COPY_BUF_SIZE: usize = 64 * 1024;

/// Marks a stream's AUTHORITY TLV as a raw TCP service rather than a hostname.
///
/// The edge writes this prefix; the agent strips it to dispatch to its TCP
/// origin map. Wire constant — must match exactly on both ends.
pub const TCP_ROUTE_PREFIX: &str = "tcp:";

/// UDP equivalent of [`TCP_ROUTE_PREFIX`]. The payload on a `udp:` stream
/// is a sequence of [`write_datagram_frame`] frames.
pub const UDP_ROUTE_PREFIX: &str = "udp:";

/// Raw bytes at the head of an agent → edge control stream.
///
/// Unlike [`TCP_ROUTE_PREFIX`] / [`UDP_ROUTE_PREFIX`] (which live in the
/// PROXY v2 authority TLV), a control stream has no source/dest addresses,
/// so it skips the PROXY v2 wrap entirely.
pub const CONTROL_PREFIX: &str = "ctrl:";

pub const CONTROL_STATUS_OK: u8 = 0;
pub const CONTROL_STATUS_NOT_IMPLEMENTED: u8 = 1;
pub const CONTROL_STATUS_INVALID: u8 = 2;
/// Distinct from `NOT_IMPLEMENTED` so agent clients retry instead of giving up.
pub const CONTROL_STATUS_INTERNAL_ERROR: u8 = 3;

/// Cap on individual UDP datagram length carried over the QUIC pipe. Matches
/// the IPv4 datagram limit; anything larger is a sender configuration error.
pub const MAX_UDP_DATAGRAM: usize = 65_535;

/// Zero-copy forward from an iroh `RecvStream` to any `AsyncWrite` via
/// `read_chunk` (bypasses an intermediate `BufReader` memcpy).
///
/// An optional `prefix` (e.g. PROXY v2 header) is coalesced with the first
/// QUIC chunk into a single `write_all`, so with `TCP_NODELAY` set the peer
/// sees one segment instead of two back-to-back tiny ones. Pass `Vec::new()`
/// when no prefix is needed — the `is_empty` branch elides the extra copy.
///
/// Returns the byte total alongside the result so a partway failure still
/// reports its count — `tokio::io::copy*` discards its total on error. The
/// total excludes `prefix` (framing, not tunnel payload).
pub async fn forward_quic_to_writer<W>(
    mut prefix: Vec<u8>,
    recv: &mut iroh::endpoint::RecvStream,
    writer: &mut W,
) -> (u64, std::io::Result<()>)
where
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        match recv.read_chunk(COPY_BUF_SIZE).await {
            Ok(Some(chunk)) => {
                let write = if prefix.is_empty() {
                    writer.write_all(&chunk).await
                } else {
                    prefix.extend_from_slice(&chunk);
                    let res = writer.write_all(&prefix).await;
                    prefix = Vec::new();
                    res
                };
                if let Err(e) = write {
                    return (total, Err(e));
                }
                total = total.saturating_add(chunk.len() as u64);
            }
            Ok(None) => {
                if !prefix.is_empty()
                    && let Err(e) = writer.write_all(&prefix).await
                {
                    return (total, Err(e));
                }
                return (total, Ok(()));
            }
            Err(e) => return (total, Err(std::io::Error::other(e))),
        }
    }
}

/// Copy `reader` into `writer` like `tokio::io::copy_buf`.
///
/// Returns the bytes copied even on a partway failure — `tokio::io::copy*`
/// discards its total on error.
pub async fn copy_buf_counting<R, W>(reader: &mut R, writer: &mut W) -> (u64, std::io::Result<()>)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let buf = match reader.fill_buf().await {
            Ok(b) => b,
            Err(e) => return (total, Err(e)),
        };
        if buf.is_empty() {
            return (total, writer.flush().await);
        }
        match writer.write(buf).await {
            Ok(0) => return (total, Err(std::io::ErrorKind::WriteZero.into())),
            Ok(n) => {
                reader.consume(n);
                total = total.saturating_add(n as u64);
            }
            Err(e) => return (total, Err(e)),
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
    #[expect(
        clippy::indexing_slicing,
        reason = "all was just resized to V2_PREAMBLE_LEN + body_len"
    )]
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
///
/// UDP listeners report `[::]:port` as their local addr regardless of peer.
/// When the peer unmaps to v4, demote the v6 wildcard dst to v4 wildcard.
fn unmap_to_matching_family(src: SocketAddr, dst: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
    let src = unmap_v4(src);
    let dst = unmap_v4(dst);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Some((src, dst)),
        (IpAddr::V4(_), IpAddr::V6(v6)) if v6.is_unspecified() => Some((
            src,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), dst.port()),
        )),
        (IpAddr::V6(v6), IpAddr::V4(_)) if v6.is_unspecified() => Some((
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), src.port()),
            dst,
        )),
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

pub async fn write_control_prefix<W: AsyncWrite + Unpin>(stream: &mut W) -> std::io::Result<()> {
    stream.write_all(CONTROL_PREFIX.as_bytes()).await
}

pub async fn read_control_prefix<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<()> {
    let mut buf = [0u8; CONTROL_PREFIX.len()];
    stream.read_exact(&mut buf).await?;
    if buf != CONTROL_PREFIX.as_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream does not start with CONTROL_PREFIX",
        ));
    }
    Ok(())
}

pub async fn write_control_status<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: u8,
) -> std::io::Result<()> {
    stream.write_all(&[status]).await
}

pub async fn read_control_status<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

/// Write one length-prefixed UDP datagram (`u16` big-endian length + bytes).
pub async fn write_datagram_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    datagram: &[u8],
) -> std::io::Result<()> {
    if datagram.len() > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "udp datagram of {} bytes exceeds {MAX_UDP_DATAGRAM}-byte cap",
                datagram.len()
            ),
        ));
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "length is already bounded to MAX_UDP_DATAGRAM (65_535)"
    )]
    let len = datagram.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(datagram).await
}

/// Read one length-prefixed datagram into `buf`, returning bytes written.
/// `UnexpectedEof` here signals a clean half-close between frames.
pub async fn read_datagram_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("udp frame length {len} exceeds buffer ({})", buf.len()),
        ));
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "len was just checked against buf.len() above"
    )]
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
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

    #[tokio::test]
    async fn control_prefix_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(64);
        write_control_prefix(&mut client).await.unwrap();
        write_control_status(&mut client, CONTROL_STATUS_NOT_IMPLEMENTED)
            .await
            .unwrap();
        drop(client);

        read_control_prefix(&mut server).await.unwrap();
        let status = read_control_status(&mut server).await.unwrap();
        assert_eq!(status, CONTROL_STATUS_NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn read_control_prefix_rejects_other_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"junk!").await.unwrap();
        drop(client);
        let err = read_control_prefix(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
