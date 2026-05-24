//! Direct DB write to bootstrap the first operator account before any web
//! flow exists.

use anyhow::{Context, anyhow};

use crate::config::{DatabaseConfig, DbDriver};
use crate::hub::auth::password;
use crate::hub::db::Db;
use crate::hub::db::users::NewUser;

const VALID_ROLES: &[&str] = &["user", "operator"];

pub async fn cmd_user_create(
    email: String,
    role: String,
    password_arg: Option<String>,
) -> anyhow::Result<()> {
    if !VALID_ROLES.contains(&role.as_str()) {
        return Err(anyhow!("role must be one of {VALID_ROLES:?}, got {role:?}"));
    }
    if !email.contains('@') || email.len() > 254 {
        return Err(anyhow!("invalid email"));
    }

    let password = if let Some(p) = password_arg {
        p
    } else {
        let p = rpassword::prompt_password("Password: ")
            .context("failed to read password from terminal")?;
        let confirm = rpassword::prompt_password("Confirm: ")
            .context("failed to read confirmation from terminal")?;
        if p != confirm {
            return Err(anyhow!("passwords do not match"));
        }
        p
    };
    if password.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }

    let database = load_database_from_env();
    let url = database.connection_url()?;
    let db = Db::open(&url, database.max_open(), database.max_idle())
        .await
        .with_context(|| format!("failed to open DB at {url}"))?;

    if db.find_user_by_email(&email).await?.is_some() {
        return Err(anyhow!("user with email {email} already exists"));
    }

    let hash = password::hash(&password)
        .await
        .context("failed to hash password")?;
    let id = new_user_id();
    let now_ms = i64::try_from(towonel_common::time::now_ms()).unwrap_or(i64::MAX);

    db.insert_user(NewUser {
        id: &id,
        email: &email,
        password_hash: &hash,
        role: &role,
        email_verified_at_ms: Some(now_ms),
        now_ms,
    })
    .await
    .context("failed to insert user row")?;

    println!("created {role} account {email} (id {id})");
    Ok(())
}

fn load_database_from_env() -> DatabaseConfig {
    let driver = std::env::var("TOWONEL_HUB_DB_DRIVER")
        .ok()
        .as_deref()
        .map_or(DbDriver::Sqlite, |s| match s {
            "postgres" => DbDriver::Postgres,
            _ => DbDriver::Sqlite,
        });
    let dsn = std::env::var("TOWONEL_HUB_DB_DSN").ok().or_else(|| {
        std::env::var("TOWONEL_DATA_DIR")
            .ok()
            .map(|d| format!("{d}/hub.db"))
    });
    DatabaseConfig {
        driver,
        dsn,
        max_open_conns: None,
        max_idle_conns: None,
    }
}

fn new_user_id() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS RNG");
    B64.encode(buf)
}
