#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use webauthn_rs::prelude::Passkey;

use super::Db;
use super::entities::user_passkeys;

pub struct NewPasskey<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub passkey: &'a Passkey,
    pub name: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: String,
    pub user_id: String,
    pub passkey: Passkey,
    pub name: String,
    pub created_at_ms: i64,
}

impl Db {
    pub async fn insert_passkey(&self, p: NewPasskey<'_>) -> anyhow::Result<()> {
        let passkey_json = serde_json::to_string(p.passkey)?;
        let model = user_passkeys::ActiveModel {
            id: ActiveValue::Set(p.id.to_string()),
            user_id: ActiveValue::Set(p.user_id.to_string()),
            passkey_json: ActiveValue::Set(passkey_json),
            name: ActiveValue::Set(p.name.to_string()),
            created_at_ms: ActiveValue::Set(p.now_ms),
        };
        user_passkeys::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_passkeys_for_user(&self, user_id: &str) -> anyhow::Result<Vec<PasskeyRow>> {
        let rows = user_passkeys::Entity::find()
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .all(&self.conn)
            .await?;
        rows.into_iter()
            .map(|m| {
                let passkey = serde_json::from_str(&m.passkey_json)?;
                Ok(PasskeyRow {
                    id: m.id,
                    user_id: m.user_id,
                    passkey,
                    name: m.name,
                    created_at_ms: m.created_at_ms,
                })
            })
            .collect()
    }

    pub async fn update_passkey(&self, id: &str, passkey: &Passkey) -> anyhow::Result<()> {
        let passkey_json = serde_json::to_string(passkey)?;
        user_passkeys::Entity::update_many()
            .col_expr(
                user_passkeys::Column::PasskeyJson,
                sea_orm::sea_query::Expr::value(passkey_json),
            )
            .filter(user_passkeys::Column::Id.eq(id))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn delete_passkey(&self, id: &str, user_id: &str) -> anyhow::Result<bool> {
        let result = user_passkeys::Entity::delete_many()
            .filter(user_passkeys::Column::Id.eq(id))
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn count_passkeys_for_user(&self, user_id: &str) -> anyhow::Result<u64> {
        let count = user_passkeys::Entity::find()
            .filter(user_passkeys::Column::UserId.eq(user_id))
            .count(&self.conn)
            .await?;
        Ok(count)
    }
}
