use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PortReservations::Table)
                    .col(
                        ColumnDef::new(PortReservations::Id)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PortReservations::TenantId)
                            .binary()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PortReservations::IpAddress).string().null())
                    .col(ColumnDef::new(PortReservations::Port).integer().not_null())
                    .col(
                        ColumnDef::new(PortReservations::Protocol)
                            .string()
                            .not_null()
                            .check(Expr::col(PortReservations::Protocol).is_in(["tcp", "udp"])),
                    )
                    .col(ColumnDef::new(PortReservations::Label).string().null())
                    .col(
                        ColumnDef::new(PortReservations::ClaimedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_port_reservations_tenant")
                    .table(PortReservations::Table)
                    .col(PortReservations::TenantId)
                    .to_owned(),
            )
            .await?;

        // SQL UNIQUE does not collide on NULL in either Postgres or SQLite,
        // so coalesce the shared-IP NULL to a sentinel string for the index.
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        db.execute(Statement::from_string(
            backend,
            "CREATE UNIQUE INDEX uniq_port_reservations_slot \
             ON port_reservations (COALESCE(ip_address, 'shared'), port, protocol)"
                .to_string(),
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PortReservations::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum PortReservations {
    Table,
    Id,
    TenantId,
    IpAddress,
    Port,
    Protocol,
    Label,
    ClaimedAtMs,
}
