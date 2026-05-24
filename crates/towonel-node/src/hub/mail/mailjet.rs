//! <https://dev.mailjet.com/email/reference/send-emails/>

use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tracing::warn;
use zeroize::Zeroizing;

use super::{LinkBase, Mailer, templates};

const MAILJET_ENDPOINT: &str = "https://api.mailjet.com/v3.1/send";

#[derive(Clone, Debug)]
pub struct MailjetSettings {
    pub api_key: String,
    pub api_secret: Zeroizing<String>,
    pub from_email: String,
    pub from_name: String,
    pub link_base: LinkBase,
    pub sandbox: bool,
}

#[derive(Debug)]
pub struct MailjetMailer {
    settings: MailjetSettings,
    client: reqwest::Client,
}

impl MailjetMailer {
    pub fn new(settings: MailjetSettings) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { settings, client })
    }

    async fn send(&self, to: &str, rendered: templates::RenderedMail) -> anyhow::Result<()> {
        let body = MailjetRequest {
            sandbox_mode: self.settings.sandbox,
            messages: vec![MailjetMessage {
                from: MailjetAddress {
                    email: &self.settings.from_email,
                    name: &self.settings.from_name,
                },
                to: vec![MailjetAddress {
                    email: to,
                    name: to,
                }],
                subject: &rendered.subject,
                text_part: &rendered.text,
                html_part: &rendered.html,
            }],
        };

        let resp = self
            .client
            .post(MAILJET_ENDPOINT)
            .basic_auth(
                &self.settings.api_key,
                Some(self.settings.api_secret.as_str()),
            )
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %detail, "mailjet send failed");
            anyhow::bail!("mailjet returned {status}");
        }
        Ok(())
    }
}

#[async_trait]
impl Mailer for MailjetMailer {
    async fn send_verification(&self, to: &str, token: &str) -> anyhow::Result<()> {
        let rendered =
            templates::verification(&self.settings.link_base, &self.settings.from_name, token);
        self.send(to, rendered).await
    }

    async fn send_password_reset(&self, to: &str, token: &str) -> anyhow::Result<()> {
        let rendered =
            templates::password_reset(&self.settings.link_base, &self.settings.from_name, token);
        self.send(to, rendered).await
    }

    async fn send_signup_invite(&self, to: &str, code: &str) -> anyhow::Result<()> {
        let rendered =
            templates::signup_invite(&self.settings.link_base, &self.settings.from_name, code);
        self.send(to, rendered).await
    }
}

#[derive(Serialize)]
struct MailjetRequest<'a> {
    #[serde(rename = "SandboxMode")]
    sandbox_mode: bool,
    #[serde(rename = "Messages")]
    messages: Vec<MailjetMessage<'a>>,
}

#[derive(Serialize)]
struct MailjetMessage<'a> {
    #[serde(rename = "From")]
    from: MailjetAddress<'a>,
    #[serde(rename = "To")]
    to: Vec<MailjetAddress<'a>>,
    #[serde(rename = "Subject")]
    subject: &'a str,
    #[serde(rename = "TextPart")]
    text_part: &'a str,
    #[serde(rename = "HTMLPart")]
    html_part: &'a str,
}

#[derive(Serialize)]
struct MailjetAddress<'a> {
    #[serde(rename = "Email")]
    email: &'a str,
    #[serde(rename = "Name")]
    name: &'a str,
}
