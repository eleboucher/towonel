use std::path::PathBuf;

use anyhow::anyhow;

use crate::config::TlsConfig;
use crate::hub::acme::{CAA_VALIDATION_METHOD, load_account_info};

pub async fn cmd_acme_account() -> anyhow::Result<()> {
    let tls = load_tls_from_env();
    let email = tls
        .acme_email
        .as_deref()
        .ok_or_else(|| anyhow!("TOWONEL_HUB_TLS_ACME_EMAIL is required"))?;

    let info = load_account_info(
        &tls.cert_dir,
        email,
        tls.acme_staging,
        tls.acme_directory_url.clone(),
    )
    .await?
    .ok_or_else(|| {
        anyhow!(
            "no ACME account at {} yet (created on first TLS handshake)",
            tls.cert_dir.display()
        )
    })?;

    let account_uri = info.account_uri;
    println!("CA:          {}", info.ca);
    println!("Account URI: {account_uri}");
    println!("Status:      {}", info.status);
    println!();
    println!(
        "<domain> CAA 0 issue \"letsencrypt.org;validationmethods={CAA_VALIDATION_METHOD};accounturi={account_uri}\""
    );
    Ok(())
}

fn load_tls_from_env() -> TlsConfig {
    let cert_dir = std::env::var("TOWONEL_HUB_TLS_CERT_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("TOWONEL_DATA_DIR")
                .ok()
                .map(|d| PathBuf::from(d).join("certs"))
        })
        .unwrap_or_else(|| PathBuf::from("/data/certs"));
    let acme_email = std::env::var("TOWONEL_HUB_TLS_ACME_EMAIL").ok();
    let acme_staging = std::env::var("TOWONEL_HUB_TLS_ACME_STAGING")
        .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"));
    let acme_directory_url = std::env::var("TOWONEL_HUB_TLS_ACME_DIRECTORY_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    TlsConfig {
        cert_dir,
        acme_email,
        acme_staging,
        acme_directory_url,
    }
}
