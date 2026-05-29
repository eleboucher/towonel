//! Direct DB write to create signup codes from the CLI, so operators can hand
//! out invite links without needing the web frontend to be reachable.

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use crate::hub::db::Db;

const VALID_ROLES: &[&str] = &["user", "operator"];

pub async fn cmd_signup_invite_create(
    role: String,
    expires_in_days: Option<u32>,
) -> anyhow::Result<()> {
    if !VALID_ROLES.contains(&role.as_str()) {
        return Err(anyhow!("role must be one of {VALID_ROLES:?}, got {role:?}"));
    }

    let database = super::load_database_from_env();
    let url = database.connection_url()?;
    let db = Db::open(&url, database.max_open(), database.max_idle())
        .await
        .with_context(|| format!("failed to open DB at {url}"))?;

    let code = generate_code();
    let now_ms = i64::try_from(towonel_common::time::now_ms()).unwrap_or(i64::MAX);
    let expires_at_ms =
        expires_in_days.map(|d| now_ms.saturating_add(i64::from(d) * 24 * 60 * 60 * 1000));

    db.insert_signup_invite(&code, &role, expires_at_ms, None, now_ms)
        .await
        .context("failed to insert signup invite row")?;

    println!("{code}");
    if let Some(exp) = expires_at_ms {
        eprintln!("role={role}, expires_at_ms={exp}");
    } else {
        eprintln!("role={role}, never expires");
    }
    Ok(())
}

fn generate_code() -> String {
    let mut buf = [0u8; 18];
    getrandom::fill(&mut buf).expect("OS RNG");
    B64.encode(buf)
}
