use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use super::Db;
use super::entities::hub_signing_keys;

#[derive(Debug, Clone)]
pub struct HubSigningKeyRow {
    pub kid: i64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by edge pubkey distribution in a later PR; the round-trip is asserted by tests today"
        )
    )]
    pub public_key: Vec<u8>,
    pub private_key_sealed: Vec<u8>,
}

impl From<hub_signing_keys::Model> for HubSigningKeyRow {
    fn from(m: hub_signing_keys::Model) -> Self {
        Self {
            kid: m.kid,
            public_key: m.public_key,
            private_key_sealed: m.private_key_sealed,
        }
    }
}

impl Db {
    /// Active row: `retired_at_ms IS NULL`, highest kid wins.
    pub async fn active_signing_key(&self) -> anyhow::Result<Option<HubSigningKeyRow>> {
        let row = hub_signing_keys::Entity::find()
            .filter(hub_signing_keys::Column::RetiredAtMs.is_null())
            .order_by_desc(hub_signing_keys::Column::Kid)
            .one(&self.conn)
            .await?;
        Ok(row.map(Into::into))
    }

    /// Highest kid across all rows (retired or not), or `None` if the table is empty.
    pub async fn max_signing_key_kid(&self) -> anyhow::Result<Option<i64>> {
        let row = hub_signing_keys::Entity::find()
            .order_by_desc(hub_signing_keys::Column::Kid)
            .one(&self.conn)
            .await?;
        Ok(row.map(|r| r.kid))
    }

    /// Fails on PK conflict (concurrent inserter won the race for that kid).
    pub async fn insert_signing_key(
        &self,
        kid: i64,
        public_key: &[u8],
        sealed_seed: &[u8],
        created_at_ms: i64,
    ) -> anyhow::Result<()> {
        hub_signing_keys::ActiveModel {
            kid: ActiveValue::Set(kid),
            public_key: ActiveValue::Set(public_key.to_vec()),
            private_key_sealed: ActiveValue::Set(sealed_seed.to_vec()),
            created_at_ms: ActiveValue::Set(created_at_ms),
            retired_at_ms: ActiveValue::Set(None),
        }
        .insert(&self.conn)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hub::db::temp_db;

    #[tokio::test]
    async fn empty_returns_none() {
        let db = temp_db().await;
        assert!(db.active_signing_key().await.unwrap().is_none());
        assert!(db.max_signing_key_kid().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_then_active() {
        let db = temp_db().await;
        db.insert_signing_key(1, &[1u8; 16], &[2u8; 32], 100)
            .await
            .unwrap();
        // active_signing_key() filters on RetiredAtMs IS NULL, so a returned
        // row is implicitly active.
        let row = db.active_signing_key().await.unwrap().unwrap();
        assert_eq!(row.kid, 1);
        assert_eq!(db.max_signing_key_kid().await.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn second_insert_same_kid_fails() {
        let db = temp_db().await;
        db.insert_signing_key(5, &[0u8; 16], &[0u8; 32], 0)
            .await
            .unwrap();
        assert!(
            db.insert_signing_key(5, &[1u8; 16], &[1u8; 32], 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn two_active_rows_blocked_by_partial_unique() {
        let db = temp_db().await;
        db.insert_signing_key(1, &[0u8; 16], &[0u8; 32], 0)
            .await
            .unwrap();
        assert!(
            db.insert_signing_key(2, &[1u8; 16], &[1u8; 32], 1)
                .await
                .is_err(),
            "second active row must be rejected"
        );
    }
}
