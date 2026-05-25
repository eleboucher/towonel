use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserPasskeys::Table)
                    .col(
                        ColumnDef::new(UserPasskeys::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserPasskeys::UserId).string().not_null())
                    .col(ColumnDef::new(UserPasskeys::PasskeyJson).text().not_null())
                    .col(ColumnDef::new(UserPasskeys::Name).text().not_null())
                    .col(
                        ColumnDef::new(UserPasskeys::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserPasskeys::Table, UserPasskeys::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_passkeys_user_id")
                    .table(UserPasskeys::Table)
                    .col(UserPasskeys::UserId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserPasskeys::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum UserPasskeys {
    Table,
    Id,
    UserId,
    PasskeyJson,
    Name,
    CreatedAtMs,
}
