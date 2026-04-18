use sea_orm_migration::prelude::*;

/// Invite v2 schema: drop + recreate `invites` and `invite_hostnames` so
/// `expires_at_ms` is nullable (forever-valid tokens) and the tenant id /
/// pq public key are populated at creation time rather than redemption.
///
/// The initial migration's columns for `tenant_id` and `tenant_pq_public_key`
/// were already nullable; keeping them nullable keeps the entity model stable.
/// Existing rows from v1 are dropped on purpose -- v1 tokens are unreachable
/// once the v1 parser is removed, and stored seeds were never persisted so
/// tenants cannot be reused from the old state.
#[derive(DeriveMigrationName)]
pub struct Migration;

async fn warn_if_destructive(manager: &SchemaManager<'_>) {
    use sea_orm::{ConnectionTrait, Statement};
    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let count: i64 = db
        .query_one(Statement::from_string(
            backend,
            "SELECT COUNT(*) AS c FROM invites".to_string(),
        ))
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<i64>("", "c").ok())
        .unwrap_or(-1);
    if count > 0 {
        tracing::warn!(
            existing_invites = count,
            "migration m20260428_invite_v2: dropping `invites` and \
             `invite_hostnames` -- existing rows will be lost. v1 tokens \
             are invalid under v2; reissue with `towonel-cli invite create`.",
        );
    } else {
        tracing::info!("migration m20260428_invite_v2: applying schema (no existing rows)");
    }
}

fn build_invites_table() -> TableCreateStatement {
    Table::create()
        .table(Invites::Table)
        .col(
            ColumnDef::new(Invites::InviteId)
                .binary()
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(Invites::Name).string().not_null())
        .col(ColumnDef::new(Invites::SecretHash).binary().not_null())
        .col(ColumnDef::new(Invites::ExpiresAtMs).big_integer().null())
        .col(
            ColumnDef::new(Invites::Status)
                .string()
                .not_null()
                .default("pending")
                .check(Expr::col(Invites::Status).is_in(["pending", "revoked"])),
        )
        .col(ColumnDef::new(Invites::TenantId).binary().null())
        .col(ColumnDef::new(Invites::TenantPqPublicKey).binary().null())
        .col(
            ColumnDef::new(Invites::CreatedAtMs)
                .big_integer()
                .not_null(),
        )
        .to_owned()
}

fn build_invite_hostnames_table() -> TableCreateStatement {
    Table::create()
        .table(InviteHostnames::Table)
        .col(
            ColumnDef::new(InviteHostnames::InviteId)
                .binary()
                .not_null(),
        )
        .col(
            ColumnDef::new(InviteHostnames::HostnameLower)
                .string()
                .not_null(),
        )
        .col(
            ColumnDef::new(InviteHostnames::Hostname)
                .string()
                .not_null(),
        )
        .primary_key(
            Index::create()
                .col(InviteHostnames::InviteId)
                .col(InviteHostnames::HostnameLower),
        )
        .foreign_key(
            ForeignKey::create()
                .from(InviteHostnames::Table, InviteHostnames::InviteId)
                .to(Invites::Table, Invites::InviteId)
                .on_delete(ForeignKeyAction::Cascade),
        )
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        warn_if_destructive(manager).await;

        manager
            .drop_table(Table::drop().table(InviteHostnames::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Invites::Table).to_owned())
            .await?;
        manager.create_table(build_invites_table()).await?;
        manager.create_table(build_invite_hostnames_table()).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_invite_hostnames_hostname_lower")
                    .table(InviteHostnames::Table)
                    .col(InviteHostnames::HostnameLower)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "invite v2 migration is irreversible (data-destructive)".to_string(),
        ))
    }
}

#[derive(DeriveIden)]
enum Invites {
    Table,
    InviteId,
    Name,
    SecretHash,
    ExpiresAtMs,
    Status,
    TenantId,
    TenantPqPublicKey,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum InviteHostnames {
    Table,
    InviteId,
    HostnameLower,
    Hostname,
}
