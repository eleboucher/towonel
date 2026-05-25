#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, EntityTrait};

use super::Db;
use super::entities::app_settings;

pub const USER_PORT_QUOTA_KEY: &str = "user_port_quota";
pub const DEFAULT_USER_PORT_QUOTA: i64 = 10;

impl Db {
    pub async fn get_setting_int(&self, key: &str) -> anyhow::Result<Option<i64>> {
        let row = app_settings::Entity::find_by_id(key.to_string())
            .one(&self.conn)
            .await?;
        Ok(row.and_then(|m| m.value_int))
    }

    pub async fn set_setting_int(&self, key: &str, value: i64, now_ms: i64) -> anyhow::Result<()> {
        let existing = app_settings::Entity::find_by_id(key.to_string())
            .one(&self.conn)
            .await?;
        if existing.is_some() {
            let active = app_settings::ActiveModel {
                key: ActiveValue::Unchanged(key.to_string()),
                value_int: ActiveValue::Set(Some(value)),
                updated_at_ms: ActiveValue::Set(now_ms),
            };
            app_settings::Entity::update(active)
                .exec(&self.conn)
                .await?;
        } else {
            let active = app_settings::ActiveModel {
                key: ActiveValue::Set(key.to_string()),
                value_int: ActiveValue::Set(Some(value)),
                updated_at_ms: ActiveValue::Set(now_ms),
            };
            app_settings::Entity::insert(active)
                .exec(&self.conn)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::db::temp_db;

    #[tokio::test]
    async fn default_quota_seeded_by_migration() {
        let db = temp_db().await;
        let v = db.get_setting_int(USER_PORT_QUOTA_KEY).await.unwrap();
        assert_eq!(v, Some(DEFAULT_USER_PORT_QUOTA));
    }

    #[tokio::test]
    async fn set_then_get_roundtrips() {
        let db = temp_db().await;
        db.set_setting_int(USER_PORT_QUOTA_KEY, 25, 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(
            db.get_setting_int(USER_PORT_QUOTA_KEY).await.unwrap(),
            Some(25)
        );
    }

    #[tokio::test]
    async fn set_inserts_a_brand_new_key() {
        let db = temp_db().await;
        db.set_setting_int("new_thing", 42, 1).await.unwrap();
        assert_eq!(db.get_setting_int("new_thing").await.unwrap(), Some(42));
    }

    #[tokio::test]
    async fn unknown_key_returns_none() {
        let db = temp_db().await;
        assert_eq!(db.get_setting_int("does_not_exist").await.unwrap(), None);
    }
}
