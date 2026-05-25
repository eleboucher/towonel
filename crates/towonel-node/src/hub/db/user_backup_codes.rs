#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

use super::Db;
use super::entities::user_backup_codes;

#[derive(Debug, Clone)]
pub struct BackupCodeRow {
    pub id: String,
    pub code_hash: String,
}

pub struct NewBackupCode<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub code_hash: &'a str,
    pub now_ms: i64,
}

impl Db {
    /// Atomically swap a user's backup codes; avoids a zero-codes window.
    pub async fn replace_backup_codes(
        &self,
        user_id: &str,
        codes: &[NewBackupCode<'_>],
    ) -> anyhow::Result<()> {
        use sea_orm::TransactionTrait;
        let txn = self.conn.begin().await?;
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
        Ok(())
    }

    pub async fn list_unused_backup_codes(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Vec<BackupCodeRow>> {
        let rows = user_backup_codes::Entity::find()
            .filter(user_backup_codes::Column::UserId.eq(user_id))
            .filter(user_backup_codes::Column::UsedAtMs.is_null())
            .all(&self.conn)
            .await?;
        Ok(rows
            .into_iter()
            .map(|m| BackupCodeRow {
                id: m.id,
                code_hash: m.code_hash,
            })
            .collect())
    }

    /// Returns `true` iff the row was flipped from unused → used by this call.
    pub async fn consume_backup_code(&self, id: &str, now_ms: i64) -> anyhow::Result<bool> {
        let result = user_backup_codes::Entity::update_many()
            .col_expr(
                user_backup_codes::Column::UsedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(user_backup_codes::Column::Id.eq(id))
            .filter(user_backup_codes::Column::UsedAtMs.is_null())
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn count_unused_backup_codes(&self, user_id: &str) -> anyhow::Result<u64> {
        let n = user_backup_codes::Entity::find()
            .filter(user_backup_codes::Column::UserId.eq(user_id))
            .filter(user_backup_codes::Column::UsedAtMs.is_null())
            .count(&self.conn)
            .await?;
        Ok(n)
    }

    pub async fn delete_backup_codes_for_user(&self, user_id: &str) -> anyhow::Result<u64> {
        let result = user_backup_codes::Entity::delete_many()
            .filter(user_backup_codes::Column::UserId.eq(user_id))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}
