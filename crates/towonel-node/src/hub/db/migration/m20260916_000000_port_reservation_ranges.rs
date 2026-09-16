use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Default 0 so ADD COLUMN works on SQLite too; existing rows are
        // backfilled below and the hub always writes the column.
        manager
            .alter_table(
                Table::alter()
                    .table(PortReservations::Table)
                    .add_column(
                        ColumnDef::new(PortReservations::PortEnd)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "UPDATE port_reservations SET port_end = port WHERE port_end = 0".to_string(),
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(PortReservations::Table)
                    .drop_column(PortReservations::PortEnd)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum PortReservations {
    Table,
    PortEnd,
}
