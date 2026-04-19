use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Buffer size for `tokio::io::copy_buf` on agent↔edge bidirectional pipes.
/// 64 KiB matches QUIC's typical window-unit and keeps syscall count low on
/// bulk transfers.
pub const COPY_BUF_SIZE: usize = 64 * 1024;

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

/// RFC 1035 maximum domain name length.
const MAX_HOSTNAME_LEN: u16 = 253;

const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

/// Writes a hostname header as `[u16 BE length][hostname bytes]`.
pub async fn write_hostname_header(
    stream: &mut (impl AsyncWrite + Unpin),
    hostname: &str,
) -> std::io::Result<()> {
    let len = encoded_hostname_len(hostname)?;
    let mut buf = Vec::with_capacity(2 + hostname.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(hostname.as_bytes());
    stream.write_all(&buf).await
}

fn encoded_hostname_len(hostname: &str) -> std::io::Result<u16> {
    let len: u16 = hostname
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "hostname too long"))?;
    if len > MAX_HOSTNAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("hostname length {len} exceeds maximum {MAX_HOSTNAME_LEN}"),
        ));
    }
    Ok(len)
}

/// Writes the hostname header and the client-address frame as a single write
/// so the peer receives the entire preamble in one STREAM frame and unblocks
/// its readers with a single wakeup.
pub async fn write_handshake(
    stream: &mut (impl AsyncWrite + Unpin),
    hostname: &str,
    addrs: ClientAddrs,
) -> std::io::Result<()> {
    let len = encoded_hostname_len(hostname)?;
    let mut buf = Vec::with_capacity(2 + hostname.len() + 37);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(hostname.as_bytes());
    encode_client_addrs_into(&mut buf, addrs)?;
    stream.write_all(&buf).await
}

/// Reads a hostname header: `[u16 BE length]` then that many bytes of UTF-8.
///
/// Returns an error if the length exceeds the RFC 1035 maximum (253 bytes) or
/// the bytes are not valid UTF-8.
pub async fn read_hostname_header(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<String> {
    let len = stream.read_u16().await?;

    if len > MAX_HOSTNAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("hostname length {len} exceeds maximum {MAX_HOSTNAME_LEN}"),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("hostname is not valid UTF-8: {e}"),
        )
    })
}

/// Original client `SocketAddr` and the edge-facing destination `SocketAddr`.
/// Both are forwarded to the agent so it can emit a PROXY v2 header to the
/// origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddrs {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Writes the client-address frame.
///
/// Layout: `[u8 family (4|6)] [addr bytes] [u16 BE port]` twice, once for
/// src and once for dst. Src and dst must share the same family; dual-stack
/// v4-mapped-v6 addresses are normalized to v4 before writing.
pub async fn write_client_addrs(
    stream: &mut (impl AsyncWrite + Unpin),
    addrs: ClientAddrs,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(37);
    encode_client_addrs_into(&mut buf, addrs)?;
    stream.write_all(&buf).await
}

fn encode_client_addrs_into(buf: &mut Vec<u8>, addrs: ClientAddrs) -> std::io::Result<()> {
    let src = unmap_v4(addrs.src);
    let dst = unmap_v4(addrs.dst);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            buf.push(FAMILY_V4);
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            buf.push(FAMILY_V6);
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "src and dst address families differ",
            ));
        }
    }
    Ok(())
}

pub async fn read_client_addrs(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<ClientAddrs> {
    let family = stream.read_u8().await?;
    match family {
        FAMILY_V4 => {
            let src = read_sock4(stream).await?;
            let dst = read_sock4(stream).await?;
            Ok(ClientAddrs { src, dst })
        }
        FAMILY_V6 => {
            let src = read_sock6(stream).await?;
            let dst = read_sock6(stream).await?;
            Ok(ClientAddrs { src, dst })
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown address family: {other}"),
        )),
    }
}

/// Dual-stack sockets surface IPv4 peers as `::ffff:a.b.c.d`. Unmap those
/// back to native v4 so the on-wire family matches the caller's intent.
fn unmap_v4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        SocketAddr::V4(_) => addr,
    }
}

async fn read_sock4(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<SocketAddr> {
    let mut octets = [0u8; 4];
    stream.read_exact(&mut octets).await?;
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
}

async fn read_sock6(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<SocketAddr> {
    let mut octets = [0u8; 16];
    stream.read_exact(&mut octets).await?;
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn roundtrip_hostname_header() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let hostname = "app.example.com";
        write_hostname_header(&mut client, hostname).await.unwrap();
        drop(client);

        let result = read_hostname_header(&mut server).await.unwrap();
        assert_eq!(result, hostname);
    }

    #[tokio::test]
    async fn rejects_oversized_hostname() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        client.write_all(&[0xFF, 0xFF]).await.unwrap();
        drop(client);

        let err = read_hostname_header(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn roundtrip_client_addrs_v4() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };

        write_client_addrs(&mut client, addrs).await.unwrap();
        drop(client);

        assert_eq!(read_client_addrs(&mut server).await.unwrap(), addrs);
    }

    #[tokio::test]
    async fn roundtrip_handshake() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let hostname = "app.example.com";
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };

        write_handshake(&mut client, hostname, addrs).await.unwrap();
        drop(client);

        assert_eq!(read_hostname_header(&mut server).await.unwrap(), hostname);
        assert_eq!(read_client_addrs(&mut server).await.unwrap(), addrs);
    }

    #[tokio::test]
    async fn roundtrip_client_addrs_v6() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let addrs = ClientAddrs {
            src: "[2001:db8::1]:54321".parse().unwrap(),
            dst: "[2001:db8::2]:443".parse().unwrap(),
        };

        write_client_addrs(&mut client, addrs).await.unwrap();
        drop(client);

        assert_eq!(read_client_addrs(&mut server).await.unwrap(), addrs);
    }

    #[tokio::test]
    async fn dual_stack_v4_mapped_v6_is_unmapped() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let addrs = ClientAddrs {
            src: "[::ffff:203.0.113.7]:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };

        write_client_addrs(&mut client, addrs).await.unwrap();
        drop(client);

        let got = read_client_addrs(&mut server).await.unwrap();
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
        let err = write_client_addrs(&mut buf, addrs).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
