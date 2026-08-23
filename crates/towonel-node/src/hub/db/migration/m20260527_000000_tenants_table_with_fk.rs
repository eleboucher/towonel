use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;
use tracing;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let count_stmt = Statement::from_string(
            backend,
            "SELECT COUNT(*) AS c FROM port_reservations".to_string(),
        );
        let count: i64 = db
            .query_one_raw(count_stmt)
            .await
            .ok()
            .flatten()
            .and_then(|row| row.try_get::<i64>("", "c").ok())
            .unwrap_or(0);

        if count > 0 {
            tracing::info!(
                existing_reservations = count,
                "adding CASCADE DELETE for port_reservations and tenant_ownership"
            );
        }

        match backend {
            sea_orm::DatabaseBackend::Postgres => {
                db.execute_raw(Statement::from_string(
                    backend,
                    r"
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.table_constraints
                            WHERE constraint_name = 'uq_invites_tenant_id'
                              AND table_name = 'invites'
                        ) THEN
                            ALTER TABLE invites
                                ADD CONSTRAINT uq_invites_tenant_id UNIQUE (tenant_id);
                        END IF;
                    END $$
                    ",
                ))
                .await?;

                db.execute_raw(Statement::from_string(
                    backend,
                    r"
                    ALTER TABLE port_reservations
                    ADD CONSTRAINT fk_port_reservations_invite
                    FOREIGN KEY (tenant_id)
                    REFERENCES invites(tenant_id)
                    ON DELETE CASCADE
                    ",
                ))
                .await?;

                db.execute_raw(Statement::from_string(
                    backend,
                    r"
                    ALTER TABLE tenant_ownership
                    ADD CONSTRAINT fk_tenant_ownership_invite
                    FOREIGN KEY (tenant_id)
                    REFERENCES invites(tenant_id)
                    ON DELETE CASCADE
                    ",
                ))
                .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {
                db.execute_raw(Statement::from_string(
                    backend,
                    r"
                    CREATE TRIGGER delete_port_reservations_on_invite_delete
                    AFTER DELETE ON invites
                    BEGIN
                        DELETE FROM port_reservations WHERE tenant_id = OLD.tenant_id;
                    END
                    ",
                ))
                .await?;

                db.execute_raw(Statement::from_string(
                    backend,
                    r"
                    CREATE TRIGGER delete_tenant_ownership_on_invite_delete
                    AFTER DELETE ON invites
                    BEGIN
                        DELETE FROM tenant_ownership WHERE tenant_id = OLD.tenant_id;
                    END
                    ",
                ))
                .await?;
            }
            _ => {
                return Err(DbErr::Migration("Unsupported database backend".to_string()));
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        match backend {
            sea_orm::DatabaseBackend::Postgres => {
                db.execute_raw(Statement::from_string(
                    backend,
                    "ALTER TABLE port_reservations DROP CONSTRAINT fk_port_reservations_invite",
                ))
                .await?;
                db.execute_raw(Statement::from_string(
                    backend,
                    "ALTER TABLE tenant_ownership DROP CONSTRAINT fk_tenant_ownership_invite",
                ))
                .await?;
                db.execute_raw(Statement::from_string(
                    backend,
                    "ALTER TABLE invites DROP CONSTRAINT uq_invites_tenant_id",
                ))
                .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {
                db.execute_raw(Statement::from_string(
                    backend,
                    "DROP TRIGGER IF EXISTS delete_port_reservations_on_invite_delete",
                ))
                .await?;
                db.execute_raw(Statement::from_string(
                    backend,
                    "DROP TRIGGER IF EXISTS delete_tenant_ownership_on_invite_delete",
                ))
                .await?;
            }
            _ => {
                return Err(DbErr::Migration("Unsupported database backend".to_string()));
            }
        }

        Ok(())
    }
}
