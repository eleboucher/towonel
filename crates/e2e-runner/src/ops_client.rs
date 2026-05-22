use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};

#[derive(Debug, Clone)]
pub struct OpsClient {
    base: String,
    api_key: String,
    http: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct CreateInviteReq<'a> {
    name: Option<&'a str>,
    hostnames: &'a [&'a str],
    expires_in_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteResp {
    pub token: String,
    pub tenant_id: String,
}

#[derive(Debug)]
pub struct DecodedEntry {
    pub op: ConfigOp,
}

#[derive(Debug)]
pub struct EntriesResp {
    pub entries: Vec<DecodedEntry>,
}

impl OpsClient {
    pub fn new(base: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
        }
    }

    pub async fn wait_healthy(&self, max_wait: std::time::Duration) -> Result<()> {
        let url = format!("{}/v1/health", self.base.trim_end_matches('/'));
        let deadline = std::time::Instant::now() + max_wait;
        loop {
            if let Ok(r) = self.http.get(&url).send().await
                && r.status().is_success()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("{url} not healthy after {max_wait:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    pub async fn create_invite(&self, hostnames: &[&str]) -> Result<CreateInviteResp> {
        let url = format!("{}/v1/invites", self.base.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&CreateInviteReq {
                name: Some("e2e"),
                hostnames,
                expires_in_secs: None,
            })
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            anyhow::bail!(
                "POST /v1/invites: {status} {}",
                String::from_utf8_lossy(&body)
            );
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// CBOR-encoded `Vec<SignedConfigEntry>`; decode each entry's payload
    /// so callers can match `ConfigOp` directly.
    pub async fn list_entries(&self, tenant_id: &str) -> Result<EntriesResp> {
        let url = format!(
            "{}/v1/tenants/{}/entries",
            self.base.trim_end_matches('/'),
            tenant_id
        );
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            anyhow::bail!("GET {url}: {status} {}", String::from_utf8_lossy(&body));
        }
        let signed: Vec<SignedConfigEntry> =
            ciborium::from_reader(body.as_ref()).context("decode entries")?;
        let entries = signed
            .into_iter()
            .map(|e| -> Result<_> {
                let payload: ConfigPayload = ciborium::from_reader(e.payload_cbor.as_slice())?;
                Ok(DecodedEntry { op: payload.op })
            })
            .collect::<Result<_>>()?;
        Ok(EntriesResp { entries })
    }

    pub async fn raw_get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{path}", self.base.trim_end_matches('/'));
        Ok(self.http.get(&url).send().await?)
    }

    pub async fn raw_post_unauth(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{path}", self.base.trim_end_matches('/'));
        Ok(self.http.post(&url).json(&body).send().await?)
    }
}
