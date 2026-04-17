use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "invite_hostnames")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub invite_id: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub hostname_lower: String,
    pub hostname: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::invites::Entity",
        from = "Column::InviteId",
        to = "super::invites::Column::InviteId",
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
