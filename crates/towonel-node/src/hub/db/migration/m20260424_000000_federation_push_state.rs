use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(FederationPushState::Table)
                    .col(
                        ColumnDef::new(FederationPushState::PeerNodeId)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederationPushState::TenantId)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederationPushState::TenantPushed)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(FederationPushState::RemovalPushed)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(FederationPushState::LastSentSequence)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .primary_key(
                        Index::create()
                            .col(FederationPushState::PeerNodeId)
                            .col(FederationPushState::TenantId),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FederationPushState::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum FederationPushState {
    Table,
    PeerNodeId,
    TenantId,
    TenantPushed,
    RemovalPushed,
    LastSentSequence,
}
