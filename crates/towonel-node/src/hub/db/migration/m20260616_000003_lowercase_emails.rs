use std::collections::HashMap;

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        if matches!(backend, DatabaseBackend::MySql) {
            return Err(DbErr::Migration(
                "MySQL backend is not supported".to_string(),
            ));
        }

        let txn = db.begin().await?;
        normalize_users(&txn, backend).await?;
        normalize_signup_invites(&txn, backend).await?;
        normalize_oauth_identity_emails(&txn, backend).await?;
        txn.commit().await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "lowercase emails migration is irreversible".to_string(),
        ))
    }
}

fn normalize_email(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

async fn normalize_users(db: &impl ConnectionTrait, backend: DatabaseBackend) -> Result<(), DbErr> {
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT id, email FROM users".to_string(),
        ))
        .await?;

    // Surface all collisions at once rather than failing on the first
    // UNIQUE violation.
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for row in &rows {
        let id = row.try_get::<String>("", "id")?;
        let email = row.try_get::<String>("", "email")?;
        groups.entry(normalize_email(&email)).or_default().push(id);
    }
    let conflicts: Vec<(String, Vec<String>)> = groups
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .collect();
    if !conflicts.is_empty() {
        let summary: Vec<String> = conflicts
            .iter()
            .map(|(key, ids)| format!("{key} <- {ids:?}"))
            .collect();
        return Err(DbErr::Migration(format!(
            "users.email has {} collapse group(s) after trim+lowercase; \
             resolve manually before this migration can run: [{}]",
            conflicts.len(),
            summary.join("; "),
        )));
    }

    for row in &rows {
        let id = row.try_get::<String>("", "id")?;
        let email = row.try_get::<String>("", "email")?;
        let normalized = normalize_email(&email);
        if normalized != email {
            db.execute_raw(Statement::from_sql_and_values(
                backend,
                "UPDATE users SET email = $1 WHERE id = $2",
                [normalized.into(), id.into()],
            ))
            .await?;
        }
    }
    Ok(())
}

async fn normalize_signup_invites(
    db: &impl ConnectionTrait,
    backend: DatabaseBackend,
) -> Result<(), DbErr> {
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT code, recipient_email FROM signup_invites WHERE recipient_email IS NOT NULL"
                .to_string(),
        ))
        .await?;
    for row in &rows {
        let code = row.try_get::<String>("", "code")?;
        let email = row.try_get::<String>("", "recipient_email")?;
        let normalized = normalize_email(&email);
        if normalized != email {
            db.execute_raw(Statement::from_sql_and_values(
                backend,
                "UPDATE signup_invites SET recipient_email = $1 WHERE code = $2",
                [normalized.into(), code.into()],
            ))
            .await?;
        }
    }
    Ok(())
}

async fn normalize_oauth_identity_emails(
    db: &impl ConnectionTrait,
    backend: DatabaseBackend,
) -> Result<(), DbErr> {
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT provider, subject, email FROM user_oauth_identities WHERE email IS NOT NULL"
                .to_string(),
        ))
        .await?;
    for row in &rows {
        let provider = row.try_get::<String>("", "provider")?;
        let subject = row.try_get::<String>("", "subject")?;
        let email = row.try_get::<String>("", "email")?;
        let normalized = normalize_email(&email);
        if normalized != email {
            db.execute_raw(Statement::from_sql_and_values(
                backend,
                "UPDATE user_oauth_identities SET email = $1 \
                 WHERE provider = $2 AND subject = $3",
                [normalized.into(), provider.into(), subject.into()],
            ))
            .await?;
        }
    }
    Ok(())
}
