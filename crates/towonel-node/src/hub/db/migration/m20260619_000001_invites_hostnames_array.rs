use sea_orm::Statement;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        tracing::info!("migration m20260619_000001_invites_hostnames_array: starting");
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        let column_type = match backend {
            sea_orm::DatabaseBackend::Postgres => "JSONB NOT NULL DEFAULT '[]'::jsonb",
            _ => "TEXT NOT NULL DEFAULT '[]'",
        };

        // Add hostnames column
        let alter_sql = format!("ALTER TABLE invites ADD COLUMN hostnames {column_type}");
        tracing::debug!("Executing: {}", alter_sql);
        db.execute(Statement::from_string(backend, alter_sql.clone()))
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to add hostnames column: {} on SQL: {}",
                    e,
                    alter_sql
                );
                e
            })?;
        tracing::info!("Successfully added hostnames column");

        // Check if the invite_hostnames table exists to migrate data
        // Alias the result column explicitly: SQLite names a bare
        // `SELECT EXISTS(...)` column after the whole expression text, so
        // try_get("exists") would miss it and the data copy + drop would be
        // silently skipped.
        let table_exists_sql = match backend {
            sea_orm::DatabaseBackend::Postgres => {
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'invite_hostnames') AS \"exists\""
            }
            sea_orm::DatabaseBackend::Sqlite => {
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'invite_hostnames') AS \"exists\""
            }
            sea_orm::DatabaseBackend::MySql => "SELECT FALSE AS \"exists\"",
        };
        let table_exists = db
            .query_one(Statement::from_string(
                backend,
                table_exists_sql.to_string(),
            ))
            .await
            .ok()
            .flatten()
            .and_then(|row| row.try_get::<bool>("", "exists").ok())
            .unwrap_or(false);

        if table_exists {
            let migrate_sql = match backend {
                sea_orm::DatabaseBackend::Postgres => {
                    r"
                    UPDATE invites
                    SET hostnames = (
                        SELECT JSONB_AGG(h.hostname ORDER BY h.hostname_lower)
                        FROM invite_hostnames h
                        WHERE h.invite_id = invites.invite_id
                    )
                    WHERE EXISTS (
                        SELECT 1 FROM invite_hostnames h WHERE h.invite_id = invites.invite_id
                    )
                    "
                }
                sea_orm::DatabaseBackend::Sqlite => {
                    r"
                    UPDATE invites
                    SET hostnames = (
                        SELECT json_group_array(h.hostname)
                        FROM invite_hostnames h
                        WHERE h.invite_id = invites.invite_id
                    )
                    WHERE EXISTS (
                        SELECT 1 FROM invite_hostnames h WHERE h.invite_id = invites.invite_id
                    )
                    "
                }
                sea_orm::DatabaseBackend::MySql => "",
            };

            if !migrate_sql.is_empty() {
                db.execute(Statement::from_string(backend, migrate_sql.to_string()))
                    .await?;
                tracing::info!(
                    "Migrated hostnames from invite_hostnames table to invites.hostnames"
                );
            }

            // Drop the child table
            manager
                .drop_table(Table::drop().table(InviteHostnames::Table).to_owned())
                .await?;
        } else {
            tracing::debug!(
                "Skipping hostname data migration: invite_hostnames table does not exist"
            );
        }

        // Create GIN index for efficient hostname lookups (PostgreSQL only)
        if matches!(backend, sea_orm::DatabaseBackend::Postgres) {
            let index_sql =
                "CREATE INDEX IF NOT EXISTS idx_invites_hostnames ON invites USING GIN (hostnames)";
            if let Err(e) = db
                .execute(Statement::from_string(backend, index_sql.to_string()))
                .await
            {
                tracing::warn!("Failed to create GIN index: {e}");
            }
        }

        tracing::info!(
            "migration m20260619_000001_invites_hostnames_array: hostnames moved to JSON column"
        );

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "This migration is irreversible (data-destructive)".to_string(),
        ))
    }
}

#[derive(DeriveIden)]
enum InviteHostnames {
    Table,
}
