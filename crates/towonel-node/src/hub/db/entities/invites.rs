use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "invites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub invite_id: Vec<u8>,
    pub name: String,
    pub secret_hash: Vec<u8>,
    pub expires_at_ms: Option<i64>,
    pub status: String,
    pub tenant_id: Option<Vec<u8>>,
    pub tenant_pq_public_key: Option<Vec<u8>>,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::invite_hostnames::Entity")]
    Hostnames,
}

impl Related<super::invite_hostnames::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Hostnames.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
