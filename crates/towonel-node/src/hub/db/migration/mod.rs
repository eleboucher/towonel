use sea_orm_migration::prelude::*;

mod m20260422_000000_initial;
mod m20260424_000000_federation_push_state;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260422_000000_initial::Migration),
            Box::new(m20260424_000000_federation_push_state::Migration),
        ]
    }
}
