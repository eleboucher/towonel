use sea_orm_migration::prelude::*;

/// Tables are created unconditionally so flipping `TOWONEL_HUB_WEB_ENABLED`
/// at runtime needs no extra migration step.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[expect(
        clippy::too_many_lines,
        reason = "linear table-create sequence for 5 tables"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .col(ColumnDef::new(Users::Id).string().not_null().primary_key())
                    .col(
                        ColumnDef::new(Users::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::PasswordHash).string().not_null())
                    .col(
                        ColumnDef::new(Users::Role)
                            .string()
                            .not_null()
                            .default("user")
                            .check(Expr::col(Users::Role).is_in(["user", "operator"])),
                    )
                    .col(ColumnDef::new(Users::DisabledAtMs).big_integer().null())
                    .col(ColumnDef::new(Users::CreatedAtMs).big_integer().not_null())
                    .col(ColumnDef::new(Users::UpdatedAtMs).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .col(
                        ColumnDef::new(Sessions::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sessions::UserId).string().not_null())
                    .col(
                        ColumnDef::new(Sessions::TokenHash)
                            .binary()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Sessions::ExpiresAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Sessions::IpAddress).string().null())
                    .col(ColumnDef::new(Sessions::UserAgent).string().null())
                    .col(
                        ColumnDef::new(Sessions::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_user_id")
                    .table(Sessions::Table)
                    .col(Sessions::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_expires_at_ms")
                    .table(Sessions::Table)
                    .col(Sessions::ExpiresAtMs)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SignupInvites::Table)
                    .col(
                        ColumnDef::new(SignupInvites::Code)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SignupInvites::Role)
                            .string()
                            .not_null()
                            .default("user")
                            .check(Expr::col(SignupInvites::Role).is_in(["user", "operator"])),
                    )
                    .col(
                        ColumnDef::new(SignupInvites::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SignupInvites::ExpiresAtMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SignupInvites::RedeemedByUserId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SignupInvites::RedeemedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SignupInvites::Table, SignupInvites::RedeemedByUserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TenantOwnership::Table)
                    .col(ColumnDef::new(TenantOwnership::UserId).string().not_null())
                    .col(
                        ColumnDef::new(TenantOwnership::TenantId)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TenantOwnership::InviteId)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TenantOwnership::DisplayName)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TenantOwnership::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(TenantOwnership::UserId)
                            .col(TenantOwnership::TenantId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(TenantOwnership::Table, TenantOwnership::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_tenant_ownership_invite_id")
                    .table(TenantOwnership::Table)
                    .col(TenantOwnership::InviteId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AdminActions::Table)
                    .col(
                        ColumnDef::new(AdminActions::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AdminActions::ActorUserId).string().null())
                    .col(
                        ColumnDef::new(AdminActions::ActorKind)
                            .string()
                            .not_null()
                            .check(
                                Expr::col(AdminActions::ActorKind).is_in(["user", "operator_key"]),
                            ),
                    )
                    .col(ColumnDef::new(AdminActions::Action).string().not_null())
                    .col(ColumnDef::new(AdminActions::TargetKind).string().not_null())
                    .col(ColumnDef::new(AdminActions::TargetId).string().null())
                    .col(ColumnDef::new(AdminActions::Metadata).json_binary().null())
                    .col(
                        ColumnDef::new(AdminActions::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(AdminActions::Table, AdminActions::ActorUserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AdminActions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TenantOwnership::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SignupInvites::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Sessions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Email,
    PasswordHash,
    Role,
    DisabledAtMs,
    CreatedAtMs,
    UpdatedAtMs,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAtMs,
    IpAddress,
    UserAgent,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum SignupInvites {
    Table,
    Code,
    Role,
    CreatedAtMs,
    ExpiresAtMs,
    RedeemedByUserId,
    RedeemedAtMs,
}

#[derive(DeriveIden)]
enum TenantOwnership {
    Table,
    UserId,
    TenantId,
    InviteId,
    DisplayName,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum AdminActions {
    Table,
    Id,
    ActorUserId,
    ActorKind,
    Action,
    TargetKind,
    TargetId,
    Metadata,
    CreatedAtMs,
}
