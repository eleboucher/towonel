#![allow(dead_code, reason = "consumed by OIDC routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::user_oauth_identities as oauth;

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
            email: ActiveValue::Set(i.email.map(str::to_string)),
            linked_at_ms: ActiveValue::Set(i.now_ms),
        };
        oauth::Entity::insert(model).exec(&self.conn).await?;
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
}
