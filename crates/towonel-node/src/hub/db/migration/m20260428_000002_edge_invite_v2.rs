use sea_orm_migration::prelude::*;

/// Edge invite v2: node seed lives in the token, so `edge_node_id` is
/// bound at creation (`NOT NULL`, `UNIQUE`) and there is no redemption
/// step, no expiry column, and no separate `edges` projection.
/// Subscription auth reads `edge_invites` directly. v1 rows are dropped
/// -- their `edge_node_id` was not seed-derived so no migration path
/// exists; reissue tokens after this runs.
#[derive(DeriveMigrationName)]
pub struct Migration;

async fn warn_if_destructive(manager: &SchemaManager<'_>) {
    use sea_orm::{ConnectionTrait, Statement};
    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let count: i64 = db
        .query_one(Statement::from_string(
            backend,
            "SELECT COUNT(*) AS c FROM edge_invites".to_string(),
        ))
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<i64>("", "c").ok())
        .unwrap_or(-1);
    if count > 0 {
        tracing::warn!(
            existing_edge_invites = count,
            "migration m20260428_edge_invite_v2: dropping `edge_invites` and \
             `edges` -- existing rows will be lost. v1 edge tokens are \
             invalid under v2; reissue with `towonel edge-invite create`.",
        );
    } else {
        tracing::info!("migration m20260428_edge_invite_v2: applying schema (no existing rows)");
    }
}

fn build_edge_invites_table() -> TableCreateStatement {
    Table::create()
        .table(EdgeInvites::Table)
        .col(
            ColumnDef::new(EdgeInvites::InviteId)
                .binary()
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(EdgeInvites::Name).string().not_null())
        .col(ColumnDef::new(EdgeInvites::SecretHash).binary().not_null())
        .col(
            ColumnDef::new(EdgeInvites::Status)
                .string()
                .not_null()
                .default("pending")
                .check(Expr::col(EdgeInvites::Status).is_in(["pending", "revoked"])),
        )
        .col(
            ColumnDef::new(EdgeInvites::EdgeNodeId)
                .binary()
                .not_null()
                .unique_key(),
        )
        .col(
            ColumnDef::new(EdgeInvites::CreatedAtMs)
                .big_integer()
                .not_null(),
        )
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        warn_if_destructive(manager).await;

        manager
            .drop_table(Table::drop().table(EdgeInvites::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Edges::Table).if_exists().to_owned())
            .await?;
        manager.create_table(build_edge_invites_table()).await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "edge invite v2 migration is irreversible (data-destructive)".to_string(),
        ))
    }
}

#[derive(DeriveIden)]
enum EdgeInvites {
    Table,
    InviteId,
    Name,
    SecretHash,
    Status,
    EdgeNodeId,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum Edges {
    Table,
}
