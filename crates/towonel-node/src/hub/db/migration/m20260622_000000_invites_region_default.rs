use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        match backend {
            DatabaseBackend::Postgres => {
                db.execute(Statement::from_string(
                    backend,
                    "UPDATE invites SET region = 'EU' WHERE region IS NULL".to_string(),
                ))
                .await?;
                db.execute(Statement::from_string(
                    backend,
                    "ALTER TABLE invites ALTER COLUMN region SET DEFAULT 'EU'".to_string(),
                ))
                .await?;
            }
            DatabaseBackend::Sqlite => {
                rebuild_sqlite(db).await?;
            }
            DatabaseBackend::MySql => {
                return Err(DbErr::Migration("unsupported backend".to_string()));
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        match backend {
            DatabaseBackend::Postgres => {
                db.execute(Statement::from_string(
                    backend,
                    "ALTER TABLE invites ALTER COLUMN region DROP DEFAULT".to_string(),
                ))
                .await?;
            }
            _ => {
                return Err(DbErr::Migration("irreversible on this backend".to_string()));
            }
        }

        Ok(())
    }
}

async fn rebuild_sqlite(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let sql = [
        "CREATE TABLE invites_new (
            invite_id BLOB NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            secret_hash BLOB NOT NULL,
            expires_at_ms INTEGER,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'revoked')),
            tenant_id BLOB,
            tenant_pq_public_key BLOB,
            redeemed_at_ms INTEGER,
            created_at_ms INTEGER NOT NULL,
            hostnames TEXT NOT NULL DEFAULT '[]',
            region TEXT DEFAULT 'EU',
            failover_regions TEXT NOT NULL DEFAULT '[]'
        )",
        "INSERT INTO invites_new SELECT invite_id, name, secret_hash, expires_at_ms, status, tenant_id, tenant_pq_public_key, redeemed_at_ms, created_at_ms, hostnames, COALESCE(region, 'EU'), failover_regions FROM invites",
        "DROP TABLE invites",
        "ALTER TABLE invites_new RENAME TO invites",
    ];
    for stmt in sql {
        db.execute(Statement::from_string(DatabaseBackend::Sqlite, stmt))
            .await?;
    }
    Ok(())
}
