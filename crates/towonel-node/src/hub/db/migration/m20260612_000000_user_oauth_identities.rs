use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserOauthIdentities::Table)
                    .col(
                        ColumnDef::new(UserOauthIdentities::Provider)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::Subject)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserOauthIdentities::Email).string().null())
                    .col(
                        ColumnDef::new(UserOauthIdentities::LinkedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(UserOauthIdentities::Provider)
                            .col(UserOauthIdentities::Subject),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserOauthIdentities::Table, UserOauthIdentities::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_oauth_identities_user_id")
                    .table(UserOauthIdentities::Table)
                    .col(UserOauthIdentities::UserId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserOauthIdentities::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum UserOauthIdentities {
    Table,
    Provider,
    Subject,
    UserId,
    Email,
    LinkedAtMs,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}
