use std::net::SocketAddr;

use ppp::v2;
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE_LEN: usize = 12;
const FIXED_HEADER_LEN: usize = SIGNATURE_LEN + 4;

/// Read a `HAProxy` PROXY protocol v2 header from `stream` and return the
/// originating client address. The stream is advanced past the header so the
/// caller can keep reading the original payload (TLS handshake, HTTP request,
/// etc.). Returns an error if the bytes don't form a valid v2 PROXY header.
pub async fn read_v2<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<SocketAddr> {
    let mut head = [0u8; FIXED_HEADER_LEN];
    stream.read_exact(&mut head).await?;

    let payload_len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut buf = vec![0u8; FIXED_HEADER_LEN + payload_len];
    buf[..FIXED_HEADER_LEN].copy_from_slice(&head);
    stream.read_exact(&mut buf[FIXED_HEADER_LEN..]).await?;

    let header = v2::Header::try_from(buf.as_slice())
        .map_err(|e| anyhow::anyhow!("parse PROXY v2: {e:?}"))?;

    match header.addresses {
        v2::Addresses::IPv4(a) => Ok(SocketAddr::from((a.source_address, a.source_port))),
        v2::Addresses::IPv6(a) => Ok(SocketAddr::from((a.source_address, a.source_port))),
        v2::Addresses::Unix(_) | v2::Addresses::Unspecified => {
            anyhow::bail!("unsupported PROXY v2 address family")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v4_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        v2::Builder::with_addresses(
            v2::Version::Two | v2::Command::Proxy,
            v2::Protocol::Stream,
            (src, dst),
        )
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn parses_v4_header_and_leaves_payload() {
        let src: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut bytes = build_v4_header(src, dst);
        bytes.extend_from_slice(b"\x16\x03\x01trailing-tls-bytes");

        let (mut client, mut server) = tokio::io::duplex(8192);
        tokio::io::AsyncWriteExt::write_all(&mut client, &bytes)
            .await
            .unwrap();
        drop(client);

        let parsed = read_v2(&mut server).await.unwrap();
        assert_eq!(parsed, src);

        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"\x16\x03\x01trailing-tls-bytes");
    }

    #[tokio::test]
    async fn rejects_non_v2_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        drop(client);
        assert!(read_v2(&mut server).await.is_err());
    }
}
