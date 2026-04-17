use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// RFC 1035 maximum domain name length.
const MAX_HOSTNAME_LEN: u16 = 253;

/// Writes a hostname header as `[u16 BE length][hostname bytes]`.
pub async fn write_hostname_header(
    stream: &mut (impl AsyncWrite + Unpin),
    hostname: &str,
) -> std::io::Result<()> {
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

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(hostname.as_bytes()).await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn roundtrip_hostname_header() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let hostname = "app.example.com";

        write_hostname_header(&mut client, hostname).await.unwrap();
        drop(client); // close the write side so reads don't hang

        let result = read_hostname_header(&mut server).await.unwrap();
        assert_eq!(result, hostname);
    }

    #[tokio::test]
    async fn rejects_oversized_hostname() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Write a length that exceeds MAX_HOSTNAME_LEN (0xFFFF = 65535).
        client.write_all(&[0xFF, 0xFF]).await.unwrap();
        drop(client);

        let err = read_hostname_header(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum"));
    }
}
