use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(HubInitCanary::Table)
                    .col(
                        ColumnDef::new(HubInitCanary::Key)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(HubInitCanary::Blob).binary().not_null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(HubInitCanary::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum HubInitCanary {
    Table,
    Key,
    Blob,
}
