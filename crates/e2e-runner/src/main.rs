use std::time::Duration;

use anyhow::{Context, Result};

mod cases;
mod ops_client;
mod poll;
mod proxy_v2;
mod token_broker;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        anyhow::bail!("rustls CryptoProvider already installed");
    }

    let ctx = Context_::from_env()?;
    let operator_key = read_operator_key(&ctx.operator_key_file, Duration::from_secs(30)).await?;

    let ops = ops_client::OpsClient::new(&ctx.hub_base, &operator_key);
    ops.wait_healthy(Duration::from_secs(30)).await?;

    cases::operator_api::run(&ops).await?;

    let invite = ops.create_invite(&[&ctx.tenant_hostname]).await?;
    tracing::info!(tenant_id = %invite.tenant_id, "minted invite");

    let broker_listen = ctx.broker_listen.parse()?;
    let _broker = token_broker::Broker::new(invite.token.clone())
        .serve(broker_listen)
        .await?;

    cases::agent_registration::run(&ops, &invite.tenant_id, &ctx.tenant_hostname).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    cases::tcp_passthrough::run(&ctx.edge_host, ctx.origin_tcp_port).await?;
    cases::tls_passthrough::run(
        &ctx.edge_host,
        ctx.edge_tls_port,
        &ctx.tenant_hostname,
        std::path::Path::new("/fixtures/origin-tls.pem"),
    )
    .await?;
    cases::proxy_v2::run(&ctx.edge_host, ctx.edge_tls_port).await?;

    let docker = bollard::Docker::connect_with_local_defaults()?;
    cases::liveness_drop::run(
        &docker,
        &ctx.agent_container,
        &ctx.edge_host,
        ctx.origin_tcp_port,
        ctx.liveness_budget,
    )
    .await?;

    Ok(())
}

struct Context_ {
    hub_base: String,
    operator_key_file: std::path::PathBuf,
    tenant_hostname: String,
    broker_listen: String,
    edge_host: String,
    edge_tls_port: u16,
    origin_tcp_port: u16,
    agent_container: String,
    liveness_budget: Duration,
}

impl Context_ {
    fn from_env() -> Result<Self> {
        let liveness_budget_secs: u64 = std::env::var("E2E_LIVENESS_BUDGET_SECS")
            .ok()
            .map(|s| s.parse())
            .transpose()
            .context("E2E_LIVENESS_BUDGET_SECS")?
            .unwrap_or(150);
        Ok(Self {
            hub_base: required("E2E_HUB_BASE")?,
            operator_key_file: required("E2E_OPERATOR_KEY_FILE")?.into(),
            tenant_hostname: required("E2E_TENANT_HOSTNAME")?,
            broker_listen: std::env::var("E2E_BROKER_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:7777".to_string()),
            edge_host: required("E2E_EDGE_HOST")?,
            edge_tls_port: required("E2E_EDGE_PORT")?
                .parse()
                .context("E2E_EDGE_PORT")?,
            origin_tcp_port: required("E2E_ORIGIN_TCP_PORT")?
                .parse()
                .context("E2E_ORIGIN_TCP_PORT")?,
            agent_container: required("E2E_AGENT_CONTAINER")?,
            liveness_budget: Duration::from_secs(liveness_budget_secs),
        })
    }
}

fn required(var: &str) -> Result<String> {
    std::env::var(var).with_context(|| format!("env var {var} is required"))
}

async fn read_operator_key(path: &std::path::Path, max_wait: Duration) -> Result<String> {
    let deadline = std::time::Instant::now() + max_wait;
    loop {
        match tokio::fs::read_to_string(path).await {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() {
                    return Ok(trimmed);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context(format!("read {}", path.display())),
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("operator key at {} not readable", path.display());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
