use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "federation_push_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub peer_node_id: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: Vec<u8>,
    pub tenant_pushed: bool,
    pub removal_pushed: bool,
    pub last_sent_sequence: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
