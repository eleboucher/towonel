use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

/// Widen `invites.status` to accept `'claimed'`.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        match db.get_database_backend() {
            DatabaseBackend::Sqlite => rebuild_sqlite(db).await,
            DatabaseBackend::Postgres => widen_postgres(db).await,
            other => Err(DbErr::Migration(format!(
                "{other:?} backend is not supported"
            ))),
        }
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "invite_status_claimed widen is irreversible".to_string(),
        ))
    }
}

async fn rebuild_sqlite(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let stmts = [
        "CREATE TABLE invites_new (
            invite_id BLOB NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            secret_hash BLOB NOT NULL,
            expires_at_ms INTEGER NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'revoked')),
            tenant_id BLOB NULL,
            tenant_pq_public_key BLOB NULL,
            created_at_ms INTEGER NOT NULL
        )",
        "INSERT INTO invites_new SELECT invite_id, name, secret_hash, expires_at_ms, status, tenant_id, tenant_pq_public_key, created_at_ms FROM invites",
        "DROP TABLE invites",
        "ALTER TABLE invites_new RENAME TO invites",
    ];
    for sql in stmts {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await?;
    }
    Ok(())
}

async fn widen_postgres(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let drop_existing = r"
        DO $$
        DECLARE r RECORD;
        BEGIN
            FOR r IN
                SELECT con.conname
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                WHERE rel.relname = 'invites' AND con.contype = 'c'
            LOOP
                EXECUTE format('ALTER TABLE invites DROP CONSTRAINT %I', r.conname);
            END LOOP;
        END $$;
    ";
    let add_widened = "ALTER TABLE invites ADD CONSTRAINT invites_status_check CHECK (status IN ('pending', 'claimed', 'revoked'))";
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Postgres,
        drop_existing.to_string(),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Postgres,
        add_widened.to_string(),
    ))
    .await?;
    Ok(())
}
