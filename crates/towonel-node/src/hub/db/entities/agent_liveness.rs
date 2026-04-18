use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "agent_liveness")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub agent_id: Vec<u8>,
    pub last_seen_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
