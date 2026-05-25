#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::login_challenges;

pub struct NewLoginChallenge<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub token_hash: &'a [u8],
    pub expires_at_ms: i64,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct LoginChallengeRow {
    pub id: String,
    pub user_id: String,
}

impl Db {
    pub async fn insert_login_challenge(&self, c: NewLoginChallenge<'_>) -> anyhow::Result<()> {
        let model = login_challenges::ActiveModel {
            id: ActiveValue::Set(c.id.to_string()),
            user_id: ActiveValue::Set(c.user_id.to_string()),
            token_hash: ActiveValue::Set(c.token_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(c.expires_at_ms),
            used_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(c.now_ms),
        };
        login_challenges::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_active_login_challenge(
        &self,
        id: &str,
        token_hash: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<Option<LoginChallengeRow>> {
        let row = login_challenges::Entity::find_by_id(id.to_string())
            .filter(login_challenges::Column::TokenHash.eq(token_hash.to_vec()))
            .filter(login_challenges::Column::UsedAtMs.is_null())
            .filter(login_challenges::Column::ExpiresAtMs.gt(now_ms))
            .one(&self.conn)
            .await?;
        Ok(row.map(|m| LoginChallengeRow {
            id: m.id,
            user_id: m.user_id,
        }))
    }

    /// Returns `true` iff the row was flipped from unused → used by this call.
    pub async fn consume_login_challenge(&self, id: &str, now_ms: i64) -> anyhow::Result<bool> {
        let result = login_challenges::Entity::update_many()
            .col_expr(
                login_challenges::Column::UsedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(login_challenges::Column::Id.eq(id))
            .filter(login_challenges::Column::UsedAtMs.is_null())
            .filter(login_challenges::Column::ExpiresAtMs.gt(now_ms))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn prune_expired_login_challenges(&self, now_ms: i64) -> anyhow::Result<u64> {
        let result = login_challenges::Entity::delete_many()
            .filter(login_challenges::Column::ExpiresAtMs.lte(now_ms))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}
