use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "edges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub edge_node_id: Vec<u8>,
    pub name: String,
    pub registered_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
