#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, EntityTrait};

use super::Db;
use super::entities::admin_actions;

pub struct NewAdminAction<'a> {
    pub id: &'a str,
    pub actor_user_id: Option<&'a str>,
    pub actor_kind: &'a str,
    pub action: &'a str,
    pub target_kind: &'a str,
    pub target_id: Option<&'a str>,
    pub metadata: Option<serde_json::Value>,
    pub now_ms: i64,
}

impl Db {
    pub async fn insert_admin_action(&self, a: NewAdminAction<'_>) -> anyhow::Result<()> {
        let model = admin_actions::ActiveModel {
            id: ActiveValue::Set(a.id.to_string()),
            actor_user_id: ActiveValue::Set(a.actor_user_id.map(str::to_string)),
            actor_kind: ActiveValue::Set(a.actor_kind.to_string()),
            action: ActiveValue::Set(a.action.to_string()),
            target_kind: ActiveValue::Set(a.target_kind.to_string()),
            target_id: ActiveValue::Set(a.target_id.map(str::to_string)),
            metadata: ActiveValue::Set(a.metadata),
            created_at_ms: ActiveValue::Set(a.now_ms),
        };
        admin_actions::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}
