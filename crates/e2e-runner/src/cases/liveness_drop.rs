use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use bollard::Docker;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub async fn run(
    docker: &Docker,
    agent_container: &str,
    edge_host: &str,
    edge_tcp_port: u16,
    budget: Duration,
) -> Result<()> {
    docker.pause_container(agent_container).await?;
    tracing::info!(container = agent_container, "agent paused");

    let probe = probe_until_unroutable(edge_host, edge_tcp_port, budget).await;

    if let Err(e) = docker.unpause_container(agent_container).await {
        tracing::warn!(error = %e, "unpause failed");
    }

    probe?;
    tracing::info!("liveness_drop: PASS");
    Ok(())
}

async fn probe_until_unroutable(
    edge_host: &str,
    edge_tcp_port: u16,
    budget: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < budget {
        if let Err(e) = probe_once(edge_host, edge_tcp_port).await {
            tracing::info!(elapsed = ?start.elapsed(), error = %e, "route gone");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(anyhow!(
        "route to {edge_host}:{edge_tcp_port} still alive after {budget:?}"
    ))
}

async fn probe_once(host: &str, port: u16) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((host, port)))
        .await
        .map_err(|e| anyhow!("connect timeout: {e}"))??;
    stream.write_all(b"probe").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::with_capacity(5);
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut echoed),
    )
    .await
    .map_err(|e| anyhow!("read timeout: {e}"))??;
    if echoed != b"probe" {
        anyhow::bail!("probe echo mismatch ({} bytes)", echoed.len());
    }
    Ok(())
}
