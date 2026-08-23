use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(HubSigningKeys::Table)
                    .col(
                        ColumnDef::new(HubSigningKeys::Kid)
                            .big_integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(HubSigningKeys::PublicKey)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HubSigningKeys::PrivateKeySealed)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HubSigningKeys::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(HubSigningKeys::RetiredAtMs).big_integer())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_hub_signing_keys_active")
                    .table(HubSigningKeys::Table)
                    .col(HubSigningKeys::RetiredAtMs)
                    .to_owned(),
            )
            .await?;

        // Partial unique index: at most one active (retired_at_ms IS NULL)
        // row. Indexing on the constant `1` ensures every row matching the
        // partial predicate produces the same index key, so a second insert
        // collides. Indexing on `retired_at_ms` directly would NOT enforce
        // uniqueness — both Postgres and SQLite allow multiple NULLs in a
        // UNIQUE index by default.
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let stmt = "CREATE UNIQUE INDEX uniq_hub_signing_keys_active \
                    ON hub_signing_keys ((1)) \
                    WHERE retired_at_ms IS NULL";
        db.execute_raw(Statement::from_string(backend, stmt.to_string()))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(HubSigningKeys::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum HubSigningKeys {
    Table,
    Kid,
    PublicKey,
    PrivateKeySealed,
    CreatedAtMs,
    RetiredAtMs,
}
