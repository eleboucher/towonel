use sea_orm_migration::prelude::*;

/// Tombstone for the removed federation `edge_invites` table. Kept so
/// existing deployments don't see a missing entry in their applied-
/// migrations table; the actual cleanup runs in the follow-up
/// `m20260524_000000_drop_edge_invites` migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
