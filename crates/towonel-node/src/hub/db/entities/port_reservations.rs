use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "port_reservations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Vec<u8>,
    pub tenant_id: Vec<u8>,
    pub ip_address: Option<String>,
    pub port: i32,
    pub protocol: String,
    pub label: Option<String>,
    pub claimed_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::invites::Entity",
        from = "Column::TenantId",
        to = "super::invites::Column::TenantId",
        on_delete = "Cascade"
    )]
    Invite,
}

impl Related<super::invites::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Invite.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
