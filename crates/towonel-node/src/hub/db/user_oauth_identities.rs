#![allow(dead_code, reason = "consumed by OIDC routes once mounted")]

use sea_orm::{
    ActiveValue, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};

use super::Db;
use super::entities::{user_oauth_identities as oauth, users};

pub struct NewOauthIdentity<'a> {
    pub provider: &'a str,
    pub subject: &'a str,
    pub user_id: &'a str,
    pub email: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct OauthIdentityRow {
    pub provider: String,
    pub subject: String,
    pub user_id: String,
    pub email: Option<String>,
    pub linked_at_ms: i64,
}

impl From<oauth::Model> for OauthIdentityRow {
    fn from(m: oauth::Model) -> Self {
        Self {
            provider: m.provider,
            subject: m.subject,
            user_id: m.user_id,
            email: m.email,
            linked_at_ms: m.linked_at_ms,
        }
    }
}

impl Db {
    pub async fn find_oauth_identity(
        &self,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<Option<OauthIdentityRow>> {
        let row = oauth::Entity::find_by_id((provider.to_string(), subject.to_string()))
            .one(&self.conn)
            .await?;
        Ok(row.map(OauthIdentityRow::from))
    }

    pub async fn insert_oauth_identity(&self, i: NewOauthIdentity<'_>) -> anyhow::Result<()> {
        let model = oauth::ActiveModel {
            provider: ActiveValue::Set(i.provider.to_string()),
            subject: ActiveValue::Set(i.subject.to_string()),
            user_id: ActiveValue::Set(i.user_id.to_string()),
            email: ActiveValue::Set(i.email.map(super::users::normalize_email)),
            linked_at_ms: ActiveValue::Set(i.now_ms),
        };
        oauth::Entity::insert(model).exec(&self.conn).await?;
        Ok(())
    }

    /// Refresh `email` and `linked_at_ms` for an existing identity.
    /// No-op if the row doesn't exist.
    pub async fn touch_oauth_identity_email(
        &self,
        provider: &str,
        subject: &str,
        email: Option<&str>,
        now_ms: i64,
    ) -> anyhow::Result<()> {
        let normalized = email.map(super::users::normalize_email);
        oauth::Entity::update_many()
            .col_expr(
                oauth::Column::Email,
                sea_orm::sea_query::Expr::value(normalized.clone()),
            )
            .col_expr(
                oauth::Column::LinkedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn list_oauth_identities_for_user(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Vec<OauthIdentityRow>> {
        let rows = oauth::Entity::find()
            .filter(oauth::Column::UserId.eq(user_id))
            .all(&self.conn)
            .await?;
        Ok(rows.into_iter().map(OauthIdentityRow::from).collect())
    }

    /// Atomic check-and-delete: refuses if the result would leave the
    /// user with no sign-in method (empty password hash AND no other
    /// linked identity).
    pub async fn unlink_oauth_identity(
        &self,
        user_id: &str,
        provider: &str,
    ) -> anyhow::Result<UnlinkOutcome> {
        let txn = self.conn.begin().await?;

        let Some(row) = oauth::Entity::find()
            .filter(oauth::Column::UserId.eq(user_id))
            .filter(oauth::Column::Provider.eq(provider))
            .one(&txn)
            .await?
        else {
            txn.rollback().await?;
            return Ok(UnlinkOutcome::NotFound);
        };

        let Some(user) = users::Entity::find_by_id(user_id.to_string())
            .one(&txn)
            .await?
        else {
            txn.rollback().await?;
            return Ok(UnlinkOutcome::NotFound);
        };

        let others = oauth::Entity::find()
            .filter(oauth::Column::UserId.eq(user_id))
            .filter(oauth::Column::Provider.ne(provider))
            .count(&txn)
            .await?;
        if user.password_hash.is_empty() && others == 0 {
            txn.rollback().await?;
            return Ok(UnlinkOutcome::WouldLockOut);
        }

        let removed = OauthIdentityRow::from(row);
        oauth::Entity::delete_many()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(&removed.subject))
            .filter(oauth::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(UnlinkOutcome::Deleted(removed))
    }
}

pub enum UnlinkOutcome {
    Deleted(OauthIdentityRow),
    NotFound,
    WouldLockOut,
}

#[cfg(test)]
mod tests {
    use super::super::temp_db;
    use super::super::users::NewUser;
    use super::*;

    async fn insert_user_for_test(db: &Db, id: &str, email: &str) {
        db.insert_user(NewUser {
            id,
            email,
            password_hash: "argon2-placeholder",
            role: "user",
            email_verified_at_ms: Some(1000),
            now_ms: 1000,
        })
        .await
        .expect("insert_user");
    }

    #[tokio::test]
    async fn insert_normalizes_email() {
        let db = temp_db().await;
        insert_user_for_test(&db, "u-1", "alice@example.com").await;
        db.insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "10001",
            user_id: "u-1",
            email: Some("  Alice@Example.com  "),
            now_ms: 1100,
        })
        .await
        .expect("insert_oauth_identity");

        let row = db
            .find_oauth_identity("codeberg", "10001")
            .await
            .expect("find_oauth_identity")
            .expect("identity must exist");
        assert_eq!(row.email.as_deref(), Some("alice@example.com"));
    }

    #[tokio::test]
    async fn touch_updates_email_and_timestamp() {
        let db = temp_db().await;
        insert_user_for_test(&db, "u-1", "alice@example.com").await;
        db.insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "10001",
            user_id: "u-1",
            email: Some("alice@example.com"),
            now_ms: 1100,
        })
        .await
        .expect("insert_oauth_identity");

        db.touch_oauth_identity_email("codeberg", "10001", Some("Alice-Renamed@Example.com"), 2200)
            .await
            .expect("touch_oauth_identity_email");

        let row = db
            .find_oauth_identity("codeberg", "10001")
            .await
            .expect("find_oauth_identity")
            .expect("identity must exist");
        assert_eq!(row.email.as_deref(), Some("alice-renamed@example.com"));
        assert_eq!(row.linked_at_ms, 2200);
    }

    #[tokio::test]
    async fn unlink_only_deletes_caller_owned_row() {
        let db = temp_db().await;
        insert_user_for_test(&db, "u-1", "alice@example.com").await;
        insert_user_for_test(&db, "u-2", "bob@example.com").await;
        db.insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "10001",
            user_id: "u-1",
            email: Some("alice@example.com"),
            now_ms: 1100,
        })
        .await
        .unwrap();

        // u-2 can't unlink u-1's row by guessing (provider, subject).
        assert!(matches!(
            db.unlink_oauth_identity("u-2", "codeberg").await.unwrap(),
            UnlinkOutcome::NotFound,
        ));
        assert!(
            db.find_oauth_identity("codeberg", "10001")
                .await
                .unwrap()
                .is_some(),
            "row still present after foreign unlink attempt"
        );

        let UnlinkOutcome::Deleted(removed) =
            db.unlink_oauth_identity("u-1", "codeberg").await.unwrap()
        else {
            panic!("expected Deleted");
        };
        assert_eq!(removed.subject, "10001");
        assert!(
            db.find_oauth_identity("codeberg", "10001")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn unlink_refuses_self_lockout() {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let db = temp_db().await;
        insert_user_for_test(&db, "u-1", "alice@example.com").await;
        // OIDC-only: clear password hash.
        users::Entity::update_many()
            .col_expr(
                users::Column::PasswordHash,
                sea_orm::sea_query::Expr::value(""),
            )
            .filter(users::Column::Id.eq("u-1"))
            .exec(&db.conn)
            .await
            .unwrap();
        db.insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "10001",
            user_id: "u-1",
            email: Some("alice@example.com"),
            now_ms: 1100,
        })
        .await
        .unwrap();

        assert!(matches!(
            db.unlink_oauth_identity("u-1", "codeberg").await.unwrap(),
            UnlinkOutcome::WouldLockOut,
        ));
        assert!(
            db.find_oauth_identity("codeberg", "10001")
                .await
                .unwrap()
                .is_some(),
            "guard must not delete on refusal"
        );
    }

    #[tokio::test]
    async fn cannot_link_two_identities_at_same_provider() {
        let db = temp_db().await;
        insert_user_for_test(&db, "u-1", "alice@example.com").await;
        db.insert_oauth_identity(NewOauthIdentity {
            provider: "codeberg",
            subject: "personal-101",
            user_id: "u-1",
            email: Some("alice@example.com"),
            now_ms: 1100,
        })
        .await
        .expect("first insert");

        let err = db
            .insert_oauth_identity(NewOauthIdentity {
                provider: "codeberg",
                subject: "work-202",
                user_id: "u-1",
                email: Some("alice@work.example"),
                now_ms: 1200,
            })
            .await
            .expect_err("(user_id, provider) UNIQUE must reject");
        assert!(crate::hub::db::is_unique_violation(&err));
    }
}
