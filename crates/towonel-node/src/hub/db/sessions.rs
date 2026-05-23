#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::sessions;

pub struct NewSession<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub token_hash: &'a [u8],
    pub expires_at_ms: i64,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub expires_at_ms: i64,
}

impl Db {
    pub async fn insert_session(&self, s: NewSession<'_>) -> anyhow::Result<()> {
        let model = sessions::ActiveModel {
            id: ActiveValue::Set(s.id.to_string()),
            user_id: ActiveValue::Set(s.user_id.to_string()),
            token_hash: ActiveValue::Set(s.token_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(s.expires_at_ms),
            ip_address: ActiveValue::Set(s.ip_address.map(str::to_string)),
            user_agent: ActiveValue::Set(s.user_agent.map(str::to_string)),
            created_at_ms: ActiveValue::Set(s.now_ms),
        };
        sessions::Entity::insert(model).exec(&self.conn).await?;
        Ok(())
    }

    pub async fn find_active_session(
        &self,
        id: &str,
        token_hash: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<Option<SessionRow>> {
        let row = sessions::Entity::find_by_id(id.to_string())
            .filter(sessions::Column::TokenHash.eq(token_hash.to_vec()))
            .filter(sessions::Column::ExpiresAtMs.gt(now_ms))
            .one(&self.conn)
            .await?;
        Ok(row.map(|m| SessionRow {
            id: m.id,
            user_id: m.user_id,
            expires_at_ms: m.expires_at_ms,
        }))
    }

    pub async fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        sessions::Entity::delete_by_id(id.to_string())
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn delete_sessions_for_user(&self, user_id: &str) -> anyhow::Result<u64> {
        let result = sessions::Entity::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }

    pub async fn prune_expired_sessions(&self, now_ms: i64) -> anyhow::Result<u64> {
        let result = sessions::Entity::delete_many()
            .filter(sessions::Column::ExpiresAtMs.lte(now_ms))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}
