use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "federated_tenants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: Vec<u8>,
    pub pq_public_key: Vec<u8>,
    pub registered_at_ms: i64,
    pub source_peer_node_id: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::federated_tenant_hostnames::Entity")]
    Hostnames,
}

impl Related<super::federated_tenant_hostnames::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hostnames.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
