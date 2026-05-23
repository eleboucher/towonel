#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signup_invites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub code: String,
    pub role: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub redeemed_by_user_id: Option<String>,
    pub redeemed_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::RedeemedByUserId",
        to = "super::users::Column::Id",
        on_delete = "SetNull"
    )]
    RedeemedBy,
}

impl ActiveModelBehavior for ActiveModel {}
