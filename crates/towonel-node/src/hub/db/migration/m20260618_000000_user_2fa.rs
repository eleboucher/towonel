use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[expect(
        clippy::too_many_lines,
        reason = "linear DDL — three tables + indexes in one migration"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserTotp::Table)
                    .col(
                        ColumnDef::new(UserTotp::UserId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserTotp::SecretEncrypted)
                            .binary()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserTotp::ConfirmedAtMs).big_integer().null())
                    .col(ColumnDef::new(UserTotp::LastUsedStep).big_integer().null())
                    .col(
                        ColumnDef::new(UserTotp::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserTotp::Table, UserTotp::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UserBackupCodes::Table)
                    .col(
                        ColumnDef::new(UserBackupCodes::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserBackupCodes::UserId).string().not_null())
                    .col(ColumnDef::new(UserBackupCodes::CodeHash).text().not_null())
                    .col(
                        ColumnDef::new(UserBackupCodes::UsedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserBackupCodes::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserBackupCodes::Table, UserBackupCodes::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_backup_codes_user_id")
                    .table(UserBackupCodes::Table)
                    .col(UserBackupCodes::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(LoginChallenges::Table)
                    .col(
                        ColumnDef::new(LoginChallenges::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(LoginChallenges::UserId).string().not_null())
                    .col(
                        ColumnDef::new(LoginChallenges::TokenHash)
                            .binary()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(LoginChallenges::ExpiresAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(LoginChallenges::UsedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(LoginChallenges::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(LoginChallenges::Table, LoginChallenges::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_login_challenges_expires_at_ms")
                    .table(LoginChallenges::Table)
                    .col(LoginChallenges::ExpiresAtMs)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LoginChallenges::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UserBackupCodes::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UserTotp::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum UserTotp {
    Table,
    UserId,
    SecretEncrypted,
    ConfirmedAtMs,
    LastUsedStep,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum UserBackupCodes {
    Table,
    Id,
    UserId,
    CodeHash,
    UsedAtMs,
    CreatedAtMs,
}

#[derive(DeriveIden)]
enum LoginChallenges {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAtMs,
    UsedAtMs,
    CreatedAtMs,
}
