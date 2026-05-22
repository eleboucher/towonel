use anyhow::{Result, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(edge_host: &str, edge_tcp_port: u16) -> Result<()> {
    let mut stream = TcpStream::connect((edge_host, edge_tcp_port)).await?;
    let payload = b"hello-towonel-e2e";
    stream.write_all(payload).await?;
    stream.shutdown().await?;

    let mut echoed = Vec::with_capacity(payload.len());
    stream.read_to_end(&mut echoed).await?;

    ensure!(echoed == payload, "tcp echo mismatch");
    tracing::info!("tcp_passthrough: PASS");
    Ok(())
}
