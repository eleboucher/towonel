use sea_orm_migration::prelude::*;

/// Liveness tracking for ephemeral agents. Stateless agents heartbeat every
/// 20s; the route table filters out agents whose `last_seen_ms` is older
/// than the TTL (90s live window, 5min prune cutoff).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AgentLiveness::Table)
                    .col(ColumnDef::new(AgentLiveness::TenantId).binary().not_null())
                    .col(ColumnDef::new(AgentLiveness::AgentId).binary().not_null())
                    .col(
                        ColumnDef::new(AgentLiveness::LastSeenMs)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(AgentLiveness::TenantId)
                            .col(AgentLiveness::AgentId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_agent_liveness_last_seen")
                    .table(AgentLiveness::Table)
                    .col(AgentLiveness::LastSeenMs)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AgentLiveness::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum AgentLiveness {
    Table,
    TenantId,
    AgentId,
    LastSeenMs,
}
