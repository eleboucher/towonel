use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::EmailVerifiedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EmailVerificationTokens::Table)
                    .col(
                        ColumnDef::new(EmailVerificationTokens::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(EmailVerificationTokens::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EmailVerificationTokens::TokenHash)
                            .binary()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(EmailVerificationTokens::ExpiresAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EmailVerificationTokens::ConsumedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(EmailVerificationTokens::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                EmailVerificationTokens::Table,
                                EmailVerificationTokens::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_email_verification_tokens_user_id")
                    .table(EmailVerificationTokens::Table)
                    .col(EmailVerificationTokens::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_email_verification_tokens_expires_at_ms")
                    .table(EmailVerificationTokens::Table)
                    .col(EmailVerificationTokens::ExpiresAtMs)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(EmailVerificationTokens::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::EmailVerifiedAtMs)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    EmailVerifiedAtMs,
}

#[derive(DeriveIden)]
enum EmailVerificationTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAtMs,
    ConsumedAtMs,
    CreatedAtMs,
}
