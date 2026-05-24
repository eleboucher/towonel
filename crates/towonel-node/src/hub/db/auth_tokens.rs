use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

use super::Db;
use super::entities::{email_verification_tokens, password_reset_tokens, users};

#[derive(Debug, Clone)]
pub struct AuthTokenRow {
    pub id: String,
    pub user_id: String,
}

pub struct NewAuthToken<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub token_hash: &'a [u8],
    pub expires_at_ms: i64,
    pub now_ms: i64,
}

impl Db {
    pub async fn insert_email_verification_token(&self, t: NewAuthToken<'_>) -> anyhow::Result<()> {
        let model = email_verification_tokens::ActiveModel {
            id: ActiveValue::Set(t.id.to_string()),
            user_id: ActiveValue::Set(t.user_id.to_string()),
            token_hash: ActiveValue::Set(t.token_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(t.expires_at_ms),
            consumed_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(t.now_ms),
        };
        email_verification_tokens::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_active_email_verification_token(
        &self,
        token_hash: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<Option<AuthTokenRow>> {
        let row = email_verification_tokens::Entity::find()
            .filter(email_verification_tokens::Column::TokenHash.eq(token_hash.to_vec()))
            .filter(email_verification_tokens::Column::ConsumedAtMs.is_null())
            .filter(email_verification_tokens::Column::ExpiresAtMs.gt(now_ms))
            .one(&self.conn)
            .await?;
        Ok(row.map(|m| AuthTokenRow {
            id: m.id,
            user_id: m.user_id,
        }))
    }

    pub async fn consume_email_verification_token_and_verify_user(
        &self,
        token_id: &str,
        user_id: &str,
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        let txn = self.conn.begin().await?;
        let consumed = email_verification_tokens::Entity::update_many()
            .col_expr(
                email_verification_tokens::Column::ConsumedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(email_verification_tokens::Column::Id.eq(token_id))
            .filter(email_verification_tokens::Column::ConsumedAtMs.is_null())
            .filter(email_verification_tokens::Column::ExpiresAtMs.gt(now_ms))
            .exec(&txn)
            .await?;
        if consumed.rows_affected == 0 {
            txn.rollback().await?;
            return Ok(false);
        }
        users::Entity::update_many()
            .col_expr(
                users::Column::EmailVerifiedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .col_expr(
                users::Column::UpdatedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(users::Column::Id.eq(user_id))
            .filter(users::Column::EmailVerifiedAtMs.is_null())
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(true)
    }

    pub async fn revoke_email_verification_tokens_for_user(
        &self,
        user_id: &str,
        now_ms: i64,
    ) -> anyhow::Result<u64> {
        let result = email_verification_tokens::Entity::update_many()
            .col_expr(
                email_verification_tokens::Column::ConsumedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(email_verification_tokens::Column::UserId.eq(user_id))
            .filter(email_verification_tokens::Column::ConsumedAtMs.is_null())
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }

    pub async fn insert_password_reset_token(&self, t: NewAuthToken<'_>) -> anyhow::Result<()> {
        let model = password_reset_tokens::ActiveModel {
            id: ActiveValue::Set(t.id.to_string()),
            user_id: ActiveValue::Set(t.user_id.to_string()),
            token_hash: ActiveValue::Set(t.token_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(t.expires_at_ms),
            consumed_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(t.now_ms),
        };
        password_reset_tokens::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_active_password_reset_token(
        &self,
        token_hash: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<Option<AuthTokenRow>> {
        let row = password_reset_tokens::Entity::find()
            .filter(password_reset_tokens::Column::TokenHash.eq(token_hash.to_vec()))
            .filter(password_reset_tokens::Column::ConsumedAtMs.is_null())
            .filter(password_reset_tokens::Column::ExpiresAtMs.gt(now_ms))
            .one(&self.conn)
            .await?;
        Ok(row.map(|m| AuthTokenRow {
            id: m.id,
            user_id: m.user_id,
        }))
    }

    pub async fn consume_password_reset_and_set_password(
        &self,
        token_id: &str,
        user_id: &str,
        password_hash: &str,
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        use super::entities::sessions;
        let txn = self.conn.begin().await?;
        let consumed = password_reset_tokens::Entity::update_many()
            .col_expr(
                password_reset_tokens::Column::ConsumedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(password_reset_tokens::Column::Id.eq(token_id))
            .filter(password_reset_tokens::Column::ConsumedAtMs.is_null())
            .filter(password_reset_tokens::Column::ExpiresAtMs.gt(now_ms))
            .exec(&txn)
            .await?;
        if consumed.rows_affected == 0 {
            txn.rollback().await?;
            return Ok(false);
        }
        users::Entity::update_many()
            .col_expr(
                users::Column::PasswordHash,
                sea_orm::sea_query::Expr::value(password_hash),
            )
            .col_expr(
                users::Column::UpdatedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(users::Column::Id.eq(user_id))
            .exec(&txn)
            .await?;
        sessions::Entity::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(true)
    }

    pub async fn revoke_password_reset_tokens_for_user(
        &self,
        user_id: &str,
        now_ms: i64,
    ) -> anyhow::Result<u64> {
        let result = password_reset_tokens::Entity::update_many()
            .col_expr(
                password_reset_tokens::Column::ConsumedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(password_reset_tokens::Column::UserId.eq(user_id))
            .filter(password_reset_tokens::Column::ConsumedAtMs.is_null())
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}
