use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn run(edge_host: &str, edge_tls_port: u16) -> Result<()> {
    let mut stream = TcpStream::connect((edge_host, edge_tls_port)).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await?;

    let mut buf = [0u8; 32];
    match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(0) | Err(_)) => {
            tracing::info!("proxy_v2: PASS");
            Ok(())
        }
        Ok(Ok(n)) => bail!(
            "edge sent {n} bytes after invalid PROXY v2: {:?}",
            buf.get(..n).unwrap_or(&buf[..])
        ),
        Err(_) => bail!("edge held connection open past 5s"),
    }
}
