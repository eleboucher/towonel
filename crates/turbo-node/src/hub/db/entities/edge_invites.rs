use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "edge_invites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub invite_id: Vec<u8>,
    pub name: String,
    pub secret_hash: Vec<u8>,
    pub expires_at_ms: i64,
    pub status: String,
    pub edge_node_id: Option<Vec<u8>>,
    pub redeemed_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
