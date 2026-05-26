use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use bollard::Docker;
use bollard::query_parameters::RestartContainerOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Restart the hub and assert routes converge again within the budget.
pub async fn run(
    docker: &Docker,
    hub_container: &str,
    edge_host: &str,
    edge_tcp_port: u16,
    budget: Duration,
) -> Result<()> {
    docker
        .restart_container(hub_container, None::<RestartContainerOptions>)
        .await?;
    tracing::info!(container = hub_container, "hub restarted");

    let start = Instant::now();
    while start.elapsed() < budget {
        if probe_once(edge_host, edge_tcp_port).await.is_ok() {
            tracing::info!(elapsed = ?start.elapsed(), "route_recovery_after_hub_restart: PASS");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(anyhow!(
        "route to {edge_host}:{edge_tcp_port} not restored within {budget:?}"
    ))
}

async fn probe_once(host: &str, port: u16) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((host, port)))
        .await
        .map_err(|e| anyhow!("connect timeout: {e}"))??;
    stream.write_all(b"probe").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::with_capacity(5);
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut echoed))
        .await
        .map_err(|e| anyhow!("read timeout: {e}"))??;
    if echoed != b"probe" {
        anyhow::bail!("probe echo mismatch ({} bytes)", echoed.len());
    }
    Ok(())
}
