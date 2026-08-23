use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The GIN index on invites.hostnames is never queried: the conflict
        // check scans in app code (case-folded, cross-backend), so the index
        // is dead weight. Postgres-only; SQLite never had it.
        let db = manager.get_connection();
        if matches!(db.get_database_backend(), DatabaseBackend::Postgres) {
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Postgres,
                "DROP INDEX IF EXISTS idx_invites_hostnames".to_string(),
            ))
            .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
