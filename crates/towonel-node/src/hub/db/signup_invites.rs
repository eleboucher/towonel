#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ConnectionTrait, Statement};

use super::Db;

#[derive(Debug, Clone)]
pub struct ClaimedInvite {
    pub code: String,
    pub role: String,
}

impl Db {
    /// One-shot atomic claim via a single `UPDATE`; concurrent callers either
    /// get the role or `None`. The placeholder `redeemed_by_user_id` is set
    /// so the signup handler can patch it once the new user row exists.
    pub async fn claim_signup_invite(
        &self,
        code: &str,
        sentinel: &str,
        now_ms: i64,
    ) -> anyhow::Result<Option<ClaimedInvite>> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_at_ms = $1,
                   redeemed_by_user_id = $2
             WHERE code = $3
               AND redeemed_at_ms IS NULL
               AND (expires_at_ms IS NULL OR expires_at_ms > $1)
            RETURNING code, role
            ",
            [now_ms.into(), sentinel.into(), code.into()],
        );
        let row = self.conn.query_one(stmt).await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(ClaimedInvite {
            code: row.try_get::<String>("", "code")?,
            role: row.try_get::<String>("", "role")?,
        }))
    }

    /// Replace the sentinel user-id placeholder with the real one once signup
    /// completes. Idempotent: only flips rows still holding the sentinel.
    pub async fn finalize_signup_invite(
        &self,
        code: &str,
        sentinel: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_by_user_id = $1
             WHERE code = $2
               AND redeemed_by_user_id = $3
            ",
            [user_id.into(), code.into(), sentinel.into()],
        );
        self.conn.execute(stmt).await?;
        Ok(())
    }

    /// Roll back a claim when the rest of the signup flow fails downstream.
    pub async fn release_signup_invite(&self, code: &str, sentinel: &str) -> anyhow::Result<()> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_at_ms = NULL,
                   redeemed_by_user_id = NULL
             WHERE code = $1
               AND redeemed_by_user_id = $2
            ",
            [code.into(), sentinel.into()],
        );
        self.conn.execute(stmt).await?;
        Ok(())
    }

    pub async fn insert_signup_invite(
        &self,
        code: &str,
        role: &str,
        expires_at_ms: Option<i64>,
        now_ms: i64,
    ) -> anyhow::Result<()> {
        use super::entities::signup_invites;
        use sea_orm::{ActiveValue, EntityTrait};

        let model = signup_invites::ActiveModel {
            code: ActiveValue::Set(code.to_string()),
            role: ActiveValue::Set(role.to_string()),
            created_at_ms: ActiveValue::Set(now_ms),
            expires_at_ms: ActiveValue::Set(expires_at_ms),
            redeemed_by_user_id: ActiveValue::Set(None),
            redeemed_at_ms: ActiveValue::Set(None),
        };
        signup_invites::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}
