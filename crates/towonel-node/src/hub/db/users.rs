#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::users;

pub struct NewUser<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub role: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub disabled_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

impl From<users::Model> for UserRow {
    fn from(m: users::Model) -> Self {
        Self {
            id: m.id,
            email: m.email,
            password_hash: m.password_hash,
            role: m.role,
            disabled_at_ms: m.disabled_at_ms,
            created_at_ms: m.created_at_ms,
        }
    }
}

impl Db {
    pub async fn insert_user(&self, u: NewUser<'_>) -> anyhow::Result<()> {
        let model = users::ActiveModel {
            id: ActiveValue::Set(u.id.to_string()),
            email: ActiveValue::Set(u.email.to_string()),
            password_hash: ActiveValue::Set(u.password_hash.to_string()),
            role: ActiveValue::Set(u.role.to_string()),
            disabled_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(u.now_ms),
            updated_at_ms: ActiveValue::Set(u.now_ms),
        };
        users::Entity::insert(model).exec(&self.conn).await?;
        Ok(())
    }

    pub async fn find_user_by_email(&self, email: &str) -> anyhow::Result<Option<UserRow>> {
        let row = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(&self.conn)
            .await?;
        Ok(row.map(UserRow::from))
    }

    pub async fn find_user_by_id(&self, id: &str) -> anyhow::Result<Option<UserRow>> {
        let row = users::Entity::find_by_id(id.to_string())
            .one(&self.conn)
            .await?;
        Ok(row.map(UserRow::from))
    }

    pub async fn set_user_role(&self, id: &str, role: &str, now_ms: i64) -> anyhow::Result<()> {
        users::Entity::update_many()
            .col_expr(users::Column::Role, sea_orm::sea_query::Expr::value(role))
            .col_expr(
                users::Column::UpdatedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(users::Column::Id.eq(id))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn disable_user(&self, id: &str, now_ms: i64) -> anyhow::Result<()> {
        users::Entity::update_many()
            .col_expr(
                users::Column::DisabledAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .col_expr(
                users::Column::UpdatedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(users::Column::Id.eq(id))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<UserRow>> {
        use sea_orm::QueryOrder;
        let rows = users::Entity::find()
            .order_by_desc(users::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        Ok(rows.into_iter().map(UserRow::from).collect())
    }
}
