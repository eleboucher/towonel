use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[allow(clippy::too_many_lines)]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Entries::Table)
                    .col(ColumnDef::new(Entries::TenantId).binary().not_null())
                    .col(ColumnDef::new(Entries::Sequence).big_integer().not_null())
                    .col(ColumnDef::new(Entries::PayloadCbor).binary().not_null())
                    .col(ColumnDef::new(Entries::Signature).binary().not_null())
                    .primary_key(
                        Index::create()
                            .col(Entries::TenantId)
                            .col(Entries::Sequence),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
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
                    .col(ColumnDef::new(Invites::ExpiresAtMs).big_integer().not_null())
                    .col(
                        ColumnDef::new(Invites::Status)
                            .string()
                            .not_null()
                            .default("pending")
                            .check(Expr::col(Invites::Status).is_in([
                                "pending",
                                "redeemed",
                                "revoked",
                            ])),
                    )
                    .col(ColumnDef::new(Invites::TenantId).binary().null())
                    .col(ColumnDef::new(Invites::TenantPqPublicKey).binary().null())
                    .col(ColumnDef::new(Invites::RedeemedAtMs).big_integer().null())
                    .col(ColumnDef::new(Invites::CreatedAtMs).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(InviteHostnames::Table)
                    .col(ColumnDef::new(InviteHostnames::InviteId).binary().not_null())
                    .col(
                        ColumnDef::new(InviteHostnames::HostnameLower)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(InviteHostnames::Hostname).string().not_null())
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
                    .to_owned(),
            )
            .await?;

        // Index used by the hostname conflict check in
        // `any_pending_invite_claims`. `hostname_lower` is already lowercased
        // at insert time, so a plain btree index is enough.
        manager
            .create_index(
                Index::create()
                    .name("idx_invite_hostnames_hostname_lower")
                    .table(InviteHostnames::Table)
                    .col(InviteHostnames::HostnameLower)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TenantRemovals::Table)
                    .col(
                        ColumnDef::new(TenantRemovals::TenantId)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TenantRemovals::RemovedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
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
                        ColumnDef::new(EdgeInvites::ExpiresAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EdgeInvites::Status)
                            .string()
                            .not_null()
                            .default("pending")
                            .check(Expr::col(EdgeInvites::Status).is_in([
                                "pending",
                                "redeemed",
                                "revoked",
                            ])),
                    )
                    .col(ColumnDef::new(EdgeInvites::EdgeNodeId).binary().null())
                    .col(
                        ColumnDef::new(EdgeInvites::RedeemedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(EdgeInvites::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Edges::Table)
                    .col(
                        ColumnDef::new(Edges::EdgeNodeId)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Edges::Name).string().not_null())
                    .col(
                        ColumnDef::new(Edges::RegisteredAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FederatedTenants::Table)
                    .col(
                        ColumnDef::new(FederatedTenants::TenantId)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(FederatedTenants::PqPublicKey)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederatedTenants::RegisteredAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederatedTenants::SourcePeerNodeId)
                            .binary()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FederatedTenantHostnames::Table)
                    .col(
                        ColumnDef::new(FederatedTenantHostnames::TenantId)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederatedTenantHostnames::HostnameLower)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(FederatedTenantHostnames::Hostname)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(FederatedTenantHostnames::TenantId)
                            .col(FederatedTenantHostnames::HostnameLower),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                FederatedTenantHostnames::Table,
                                FederatedTenantHostnames::TenantId,
                            )
                            .to(FederatedTenants::Table, FederatedTenants::TenantId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(FederatedTenantHostnames::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(FederatedTenants::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Edges::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EdgeInvites::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TenantRemovals::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(InviteHostnames::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Invites::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Entries::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Entries {
    Table,
    TenantId,
    Sequence,
    PayloadCbor,
    Signature,
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
    RedeemedAtMs,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum InviteHostnames {
    Table,
    InviteId,
    HostnameLower,
    Hostname,
}

#[derive(DeriveIden)]
enum TenantRemovals {
    Table,
    TenantId,
    RemovedAtMs,
}

#[derive(DeriveIden)]
enum EdgeInvites {
    Table,
    InviteId,
    Name,
    SecretHash,
    ExpiresAtMs,
    Status,
    EdgeNodeId,
    RedeemedAtMs,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum Edges {
    Table,
    EdgeNodeId,
    Name,
    RegisteredAtMs,
}

#[derive(DeriveIden)]
enum FederatedTenants {
    Table,
    TenantId,
    PqPublicKey,
    RegisteredAtMs,
    SourcePeerNodeId,
}

#[derive(DeriveIden)]
enum FederatedTenantHostnames {
    Table,
    TenantId,
    HostnameLower,
    Hostname,
}
