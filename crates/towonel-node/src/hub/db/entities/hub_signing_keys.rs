use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "hub_signing_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub kid: i64,
    pub public_key: Vec<u8>,
    pub private_key_sealed: Vec<u8>,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
