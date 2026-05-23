use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

/// Widen `admin_actions.actor_kind` to accept `'system'` (for signup events).
/// `SQLite` rebuilds the table; Postgres drops the unnamed inline CHECK and
/// adds the widened one.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        match db.get_database_backend() {
            DatabaseBackend::Sqlite => rebuild_sqlite(db).await,
            DatabaseBackend::Postgres => widen_postgres(db).await,
            DatabaseBackend::MySql => Err(DbErr::Migration(
                "MySQL backend is not supported".to_string(),
            )),
        }
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "actor_kind widen migration is irreversible".to_string(),
        ))
    }
}

async fn rebuild_sqlite(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let stmts = [
        "CREATE TABLE admin_actions_new (
            id TEXT NOT NULL PRIMARY KEY,
            actor_user_id TEXT NULL,
            actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'operator_key', 'system')),
            action TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_id TEXT NULL,
            metadata BLOB NULL,
            created_at_ms INTEGER NOT NULL,
            FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
        )",
        "INSERT INTO admin_actions_new SELECT id, actor_user_id, actor_kind, action, target_kind, target_id, metadata, created_at_ms FROM admin_actions",
        "DROP TABLE admin_actions",
        "ALTER TABLE admin_actions_new RENAME TO admin_actions",
    ];
    for sql in stmts {
        db.execute(Statement::from_string(
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
                WHERE rel.relname = 'admin_actions' AND con.contype = 'c'
            LOOP
                EXECUTE format('ALTER TABLE admin_actions DROP CONSTRAINT %I', r.conname);
            END LOOP;
        END $$;
    ";
    let add_widened = "ALTER TABLE admin_actions ADD CONSTRAINT admin_actions_actor_kind_check CHECK (actor_kind IN ('user', 'operator_key', 'system'))";
    db.execute(Statement::from_string(
        DatabaseBackend::Postgres,
        drop_existing.to_string(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DatabaseBackend::Postgres,
        add_widened.to_string(),
    ))
    .await?;
    Ok(())
}
