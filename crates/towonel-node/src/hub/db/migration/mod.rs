use sea_orm_migration::prelude::*;

mod m20260422_000000_initial;
mod m20260424_000000_federation_push_state;
mod m20260428_000000_invite_v2;
mod m20260428_000001_agent_liveness;
mod m20260428_000002_edge_invite_v2;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260422_000000_initial::Migration),
            Box::new(m20260424_000000_federation_push_state::Migration),
            Box::new(m20260428_000000_invite_v2::Migration),
            Box::new(m20260428_000001_agent_liveness::Migration),
            Box::new(m20260428_000002_edge_invite_v2::Migration),
        ]
    }
}
