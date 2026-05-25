#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ConnectionTrait, Statement};

use super::Db;

#[derive(Debug, Clone)]
pub struct ClaimedInvite {
    pub code: String,
    pub role: String,
    /// Returned so the signup handlers can refuse claims where the
    /// supplied email (password) or IdP-asserted email (OIDC) does not
    /// match what the invite was issued for. Without this binding, an
    /// invite-code holder can squat any email they like.
    pub recipient_email: Option<String>,
}

impl Db {
    /// One-shot atomic claim via a single `UPDATE`; concurrent callers either
    /// get the role or `None`. We mark the row "in-flight" with
    /// `redeemed_at_ms IS NOT NULL AND redeemed_by_user_id IS NULL` — the FK
    /// on `redeemed_by_user_id` forbids storing a sentinel string in that
    /// column, so the in-flight state is the absence of `redeemed_by_user_id`.
    pub async fn claim_signup_invite(
        &self,
        code: &str,
        now_ms: i64,
    ) -> anyhow::Result<Option<ClaimedInvite>> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_at_ms = $1
             WHERE code = $2
               AND redeemed_at_ms IS NULL
               AND (expires_at_ms IS NULL OR expires_at_ms > $1)
            RETURNING code, role, recipient_email
            ",
            [now_ms.into(), code.into()],
        );
        let row = self.conn.query_one(stmt).await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(ClaimedInvite {
            code: row.try_get::<String>("", "code")?,
            role: row.try_get::<String>("", "role")?,
            recipient_email: row.try_get::<Option<String>>("", "recipient_email")?,
        }))
    }

    /// Attach the real user id to a claimed-but-not-finalized invite.
    /// Idempotent: only flips rows still in the in-flight state, so a stray
    /// double-call after a successful finalize is a no-op.
    pub async fn finalize_signup_invite(&self, code: &str, user_id: &str) -> anyhow::Result<()> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_by_user_id = $1
             WHERE code = $2
               AND redeemed_at_ms IS NOT NULL
               AND redeemed_by_user_id IS NULL
            ",
            [user_id.into(), code.into()],
        );
        self.conn.execute(stmt).await?;
        Ok(())
    }

    /// Roll back a claim when the rest of the signup flow fails downstream.
    /// Only matches rows still in-flight (claimed but not finalized) so a
    /// stray release after finalize cannot un-redeem a real signup.
    pub async fn release_signup_invite(&self, code: &str) -> anyhow::Result<()> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            UPDATE signup_invites
               SET redeemed_at_ms = NULL
             WHERE code = $1
               AND redeemed_by_user_id IS NULL
            ",
            [code.into()],
        );
        self.conn.execute(stmt).await?;
        Ok(())
    }

    pub async fn insert_signup_invite(
        &self,
        code: &str,
        role: &str,
        expires_at_ms: Option<i64>,
        recipient_email: Option<&str>,
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
            recipient_email: ActiveValue::Set(recipient_email.map(super::users::normalize_email)),
        };
        signup_invites::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn list_signup_invites(&self) -> anyhow::Result<Vec<SignupInviteRow>> {
        use super::entities::signup_invites;
        use sea_orm::{EntityTrait, QueryOrder};
        let rows = signup_invites::Entity::find()
            .order_by_desc(signup_invites::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        Ok(rows
            .into_iter()
            .map(|m| SignupInviteRow {
                code: m.code,
                role: m.role,
                created_at_ms: m.created_at_ms,
                expires_at_ms: m.expires_at_ms,
                redeemed_by_user_id: m.redeemed_by_user_id,
                redeemed_at_ms: m.redeemed_at_ms,
                recipient_email: m.recipient_email,
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct SignupInviteRow {
    pub code: String,
    pub role: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub redeemed_by_user_id: Option<String>,
    pub redeemed_at_ms: Option<i64>,
    pub recipient_email: Option<String>,
}
