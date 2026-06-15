use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};
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
            // SQLite (the primary backend) has no `ALTER COLUMN DROP DEFAULT`;
            // dropping it would need a full table rebuild. The leftover
            // `DEFAULT 'EU'` is benign and the up() NULL→'EU' backfill is
            // irreversible regardless, so down() is a no-op here rather than a
            // hard error that would break `migrate down` on the main backend.
            DatabaseBackend::Sqlite => {}
            DatabaseBackend::MySql => {
                return Err(DbErr::Migration("unsupported backend".to_string()));
            }
        }

        Ok(())
    }
}

async fn rebuild_sqlite(db: &(impl ConnectionTrait + TransactionTrait)) -> Result<(), DbErr> {
    let sql = [
        // A previously failed run can leave this behind (statements outside
        // the transaction below); the original table is untouched then.
        "DROP TABLE IF EXISTS invites_new",
        "CREATE TABLE invites_new (
            invite_id BLOB NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            secret_hash BLOB NOT NULL,
            expires_at_ms INTEGER,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'revoked')),
            tenant_id BLOB,
            tenant_pq_public_key BLOB,
            created_at_ms INTEGER NOT NULL,
            hostnames TEXT NOT NULL DEFAULT '[]',
            region TEXT DEFAULT 'EU',
            failover_regions TEXT NOT NULL DEFAULT '[]'
        )",
        "INSERT INTO invites_new SELECT invite_id, name, secret_hash, expires_at_ms, status, tenant_id, tenant_pq_public_key, created_at_ms, hostnames, COALESCE(region, 'EU'), failover_regions FROM invites",
        "DROP TABLE invites",
        "ALTER TABLE invites_new RENAME TO invites",
        // DROP TABLE removed the cascade triggers from
        // m20260527_000000_tenants_table_with_fk; recreate them.
        "CREATE TRIGGER IF NOT EXISTS delete_port_reservations_on_invite_delete
            AFTER DELETE ON invites
            BEGIN
                DELETE FROM port_reservations WHERE tenant_id = OLD.tenant_id;
            END",
        "CREATE TRIGGER IF NOT EXISTS delete_tenant_ownership_on_invite_delete
            AFTER DELETE ON invites
            BEGIN
                DELETE FROM tenant_ownership WHERE tenant_id = OLD.tenant_id;
            END",
    ];
    // One transaction so a crash mid-rebuild can't strand a half-renamed
    // table or drop the cascade triggers without their replacements.
    let txn = db.begin().await?;
    for stmt in sql {
        txn.execute(Statement::from_string(DatabaseBackend::Sqlite, stmt))
            .await?;
    }
    txn.commit().await
}
