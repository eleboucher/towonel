use std::sync::Arc;

use async_trait::async_trait;

mod mailjet;
mod templates;

pub use mailjet::{MailjetMailer, MailjetSettings};

#[derive(Clone, Debug)]
pub enum LinkBase {
    Hub(String),
    Console(String),
}

impl LinkBase {
    pub fn verify_url(&self, token: &str) -> String {
        match self {
            Self::Hub(base) => format!("{}/v1/auth/verify?token={token}", trim_trailing(base)),
            Self::Console(base) => format!("{}/verify?token={token}", trim_trailing(base)),
        }
    }

    pub fn password_reset_url(&self, token: &str) -> String {
        match self {
            Self::Hub(base) => format!(
                "{}/v1/auth/password/reset/confirm?token={token}",
                trim_trailing(base),
            ),
            Self::Console(base) => format!("{}/reset/confirm?token={token}", trim_trailing(base)),
        }
    }

    pub fn signup_invite_url(&self, code: &str) -> String {
        let base = match self {
            Self::Hub(b) | Self::Console(b) => trim_trailing(b),
        };
        format!("{base}/signup?code={code}")
    }
}

fn trim_trailing(s: &str) -> &str {
    s.trim_end_matches('/')
}

#[async_trait]
pub trait Mailer: Send + Sync + std::fmt::Debug {
    async fn send_verification(&self, to: &str, token: &str) -> anyhow::Result<()>;
    async fn send_password_reset(&self, to: &str, token: &str) -> anyhow::Result<()>;
    async fn send_signup_invite(&self, to: &str, code: &str) -> anyhow::Result<()>;
}

pub type SharedMailer = Arc<dyn Mailer>;
