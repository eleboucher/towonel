#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::user_totp;

#[derive(Debug, Clone)]
pub struct UserTotpRow {
    pub user_id: String,
    pub secret_encrypted: Vec<u8>,
    pub confirmed_at_ms: Option<i64>,
    pub last_used_step: Option<i64>,
}

impl From<user_totp::Model> for UserTotpRow {
    fn from(m: user_totp::Model) -> Self {
        Self {
            user_id: m.user_id,
            secret_encrypted: m.secret_encrypted,
            confirmed_at_ms: m.confirmed_at_ms,
            last_used_step: m.last_used_step,
        }
    }
}

impl Db {
    pub async fn find_user_totp(&self, user_id: &str) -> anyhow::Result<Option<UserTotpRow>> {
        let row = user_totp::Entity::find_by_id(user_id.to_string())
            .one(&self.conn)
            .await?;
        Ok(row.map(UserTotpRow::from))
    }

    pub async fn upsert_pending_totp(
        &self,
        user_id: &str,
        secret_encrypted: &[u8],
        now_ms: i64,
    ) -> anyhow::Result<()> {
        // Delete-then-insert: portable across SQLite and Postgres.
        user_totp::Entity::delete_by_id(user_id.to_string())
            .exec(&self.conn)
            .await?;
        let model = user_totp::ActiveModel {
            user_id: ActiveValue::Set(user_id.to_string()),
            secret_encrypted: ActiveValue::Set(secret_encrypted.to_vec()),
            confirmed_at_ms: ActiveValue::Set(None),
            last_used_step: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(now_ms),
        };
        user_totp::Entity::insert(model).exec(&self.conn).await?;
        Ok(())
    }

    /// Confirm TOTP and install backup codes atomically: either 2FA becomes
    /// enabled with a usable recovery set, or nothing changes. Returns `false`
    /// (no change) if 2FA was already confirmed.
    pub async fn confirm_totp_with_backup_codes(
        &self,
        user_id: &str,
        codes: &[super::user_backup_codes::NewBackupCode<'_>],
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        use sea_orm::TransactionTrait;

        use super::entities::user_backup_codes;
        let txn = self.conn.begin().await?;
        let result = user_totp::Entity::update_many()
            .col_expr(
                user_totp::Column::ConfirmedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(user_totp::Column::UserId.eq(user_id))
            .filter(user_totp::Column::ConfirmedAtMs.is_null())
            .exec(&txn)
            .await?;
        if result.rows_affected != 1 {
            txn.rollback().await?;
            return Ok(false);
        }
        user_backup_codes::Entity::delete_many()
            .filter(user_backup_codes::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;
        for c in codes {
            let model = user_backup_codes::ActiveModel {
                id: ActiveValue::Set(c.id.to_string()),
                user_id: ActiveValue::Set(c.user_id.to_string()),
                code_hash: ActiveValue::Set(c.code_hash.to_string()),
                used_at_ms: ActiveValue::Set(None),
                created_at_ms: ActiveValue::Set(c.now_ms),
            };
            user_backup_codes::Entity::insert(model).exec(&txn).await?;
        }
        txn.commit().await?;
        Ok(true)
    }

    /// Compare-and-swap the last-used TOTP step: only advances `last_used_step`
    /// when `step` is strictly newer than the stored value (or none stored yet).
    /// Returns `true` if this call won the update, `false` if the step was
    /// already consumed — which is how concurrent verifies of one code are
    /// collapsed to a single success (replay guard).
    pub async fn set_totp_last_used_step(&self, user_id: &str, step: i64) -> anyhow::Result<bool> {
        let result = user_totp::Entity::update_many()
            .col_expr(
                user_totp::Column::LastUsedStep,
                sea_orm::sea_query::Expr::value(step),
            )
            .filter(user_totp::Column::UserId.eq(user_id))
            .filter(
                user_totp::Column::LastUsedStep
                    .lt(step)
                    .or(user_totp::Column::LastUsedStep.is_null()),
            )
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn delete_user_totp(&self, user_id: &str) -> anyhow::Result<()> {
        user_totp::Entity::delete_by_id(user_id.to_string())
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}
