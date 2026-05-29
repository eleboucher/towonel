use sea_orm::Statement;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        tracing::info!("migration m20260620_000000_invites_region: starting");
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        // Nullable region: a NULL row resolves to DEFAULT_REGION when read, so
        // existing invites keep working without a backfill.
        let region_sql = "ALTER TABLE invites ADD COLUMN region TEXT";
        db.execute(Statement::from_string(backend, region_sql.to_string()))
            .await?;

        let failover_type = match backend {
            sea_orm::DatabaseBackend::Postgres => "JSONB NOT NULL DEFAULT '[]'::jsonb",
            _ => "TEXT NOT NULL DEFAULT '[]'",
        };
        let failover_sql =
            format!("ALTER TABLE invites ADD COLUMN failover_regions {failover_type}");
        db.execute(Statement::from_string(backend, failover_sql))
            .await?;

        tracing::info!("migration m20260620_000000_invites_region: region columns added");
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        db.execute(Statement::from_string(
            backend,
            "ALTER TABLE invites DROP COLUMN failover_regions".to_string(),
        ))
        .await?;
        db.execute(Statement::from_string(
            backend,
            "ALTER TABLE invites DROP COLUMN region".to_string(),
        ))
        .await?;
        Ok(())
    }
}
