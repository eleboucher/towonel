#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{
    ActiveValue, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, sea_query::Expr,
};

use super::Db;
use super::entities::api_keys;

pub struct NewApiKey<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub key_hash: &'a [u8],
    pub name: &'a str,
    pub expires_at_ms: Option<i64>,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub expires_at_ms: Option<i64>,
    pub last_used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

impl From<api_keys::Model> for ApiKeyRow {
    fn from(m: api_keys::Model) -> Self {
        Self {
            id: m.id,
            user_id: m.user_id,
            name: m.name,
            expires_at_ms: m.expires_at_ms,
            last_used_at_ms: m.last_used_at_ms,
            created_at_ms: m.created_at_ms,
        }
    }
}

impl Db {
    pub async fn insert_api_key(&self, k: NewApiKey<'_>) -> anyhow::Result<()> {
        let model = api_keys::ActiveModel {
            id: ActiveValue::Set(k.id.to_string()),
            user_id: ActiveValue::Set(k.user_id.to_string()),
            key_hash: ActiveValue::Set(k.key_hash.to_vec()),
            name: ActiveValue::Set(k.name.to_string()),
            expires_at_ms: ActiveValue::Set(k.expires_at_ms),
            last_used_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(k.now_ms),
        };
        api_keys::Entity::insert(model).exec(&self.conn).await?;
        Ok(())
    }

    /// Look up an unexpired key by its `sha256(secret)`. A key with a non-null
    /// `expires_at_ms` in the past is treated as absent.
    pub async fn find_valid_api_key(
        &self,
        key_hash: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<Option<ApiKeyRow>> {
        let row = api_keys::Entity::find()
            .filter(api_keys::Column::KeyHash.eq(key_hash.to_vec()))
            .filter(
                api_keys::Column::ExpiresAtMs
                    .is_null()
                    .or(api_keys::Column::ExpiresAtMs.gt(now_ms)),
            )
            .one(&self.conn)
            .await?;
        Ok(row.map(ApiKeyRow::from))
    }

    pub async fn list_api_keys_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKeyRow>> {
        let rows = api_keys::Entity::find()
            .filter(api_keys::Column::UserId.eq(user_id))
            .order_by_desc(api_keys::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        Ok(rows.into_iter().map(ApiKeyRow::from).collect())
    }

    pub async fn count_api_keys_for_user(&self, user_id: &str) -> anyhow::Result<u64> {
        let n = api_keys::Entity::find()
            .filter(api_keys::Column::UserId.eq(user_id))
            .count(&self.conn)
            .await?;
        Ok(n)
    }

    /// Delete a key only if it belongs to `user_id`. Returns the number of
    /// rows removed (0 when the key is missing or owned by someone else), so
    /// the handler can return 404 without a separate ownership read.
    pub async fn delete_api_key(&self, id: &str, user_id: &str) -> anyhow::Result<u64> {
        let result = api_keys::Entity::delete_many()
            .filter(api_keys::Column::Id.eq(id))
            .filter(api_keys::Column::UserId.eq(user_id))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }

    pub async fn touch_api_key_last_used(&self, id: &str, now_ms: i64) -> anyhow::Result<()> {
        api_keys::Entity::update_many()
            .col_expr(api_keys::Column::LastUsedAtMs, Expr::value(now_ms))
            .filter(api_keys::Column::Id.eq(id))
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}
