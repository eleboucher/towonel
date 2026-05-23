#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_actions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub actor_user_id: Option<String>,
    pub actor_kind: String,
    pub action: String,
    pub target_kind: String,
    pub target_id: Option<String>,
    pub metadata: Option<Json>,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::ActorUserId",
        to = "super::users::Column::Id",
        on_delete = "SetNull"
    )]
    Actor,
}

impl ActiveModelBehavior for ActiveModel {}
