pub(super) mod entities;
mod federation;
mod invites;
mod migration;
mod types;

pub use types::*;

use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    DbErr, EntityTrait, QueryFilter, QueryOrder,
};
use sea_orm_migration::MigratorTrait;
use turbo_common::config_entry::SignedConfigEntry;
use turbo_common::identity::{PQ_SIGNATURE_LEN, TenantId};

use migration::Migrator;

/// Returns true when `e` wraps a unique-constraint violation from the
/// underlying driver. Used by handlers to map duplicate-sequence inserts to
/// 409 / idempotent OK.
///
/// `SeaORM` surfaces this in two shapes depending on whether the query went
/// through the high-level `ActiveModel::insert` path or a raw `execute`, so
/// we check both. `SQLite` returns `SQLITE_CONSTRAINT_UNIQUE` (2067) and
/// Postgres returns SQLSTATE `23505`; both map to `sqlx`'s
/// `is_unique_violation()` under the hood.
pub fn is_unique_violation(e: &anyhow::Error) -> bool {
    let Some(db_err) = e.downcast_ref::<DbErr>() else {
        return false;
    };
    match db_err {
        DbErr::Exec(sea_orm::RuntimeErr::SqlxError(sqlx_err))
        | DbErr::Query(sea_orm::RuntimeErr::SqlxError(sqlx_err)) => {
            if let sea_orm::sqlx::Error::Database(db) = sqlx_err {
                db.is_unique_violation()
            } else {
                false
            }
        }
        DbErr::RecordNotInserted => true,
        _ => false,
    }
}

/// Storage layer for signed config entries, invites, and federated state.
/// Backed by `SQLite` or `PostgreSQL` depending on the URL scheme passed to
/// [`Db::open`].
pub struct Db {
    pub(crate) conn: DatabaseConnection,
}

impl Db {
    /// Open (or create) the database at `url` and apply any pending
    /// migrations. `url` accepts `sqlite://...` or `postgres://...`.
    /// `max_open` and `max_idle` configure the connection pool.
    pub async fn open(url: &str, max_open: u32, max_idle: u32) -> anyhow::Result<Self> {
        let mut opts = ConnectOptions::new(url.to_string());
        opts.max_connections(max_open).min_connections(max_idle);
        let conn = Database::connect(opts).await?;
        Migrator::up(&conn, None).await?;
        Ok(Self { conn })
    }

    /// Insert a verified entry. The caller must verify the signature before calling this.
    pub async fn insert(&self, entry: &SignedConfigEntry, sequence: u64) -> anyhow::Result<()> {
        let model = entities::entries::ActiveModel {
            tenant_id: ActiveValue::Set(entry.tenant_id.as_bytes().to_vec()),
            sequence: ActiveValue::Set(sequence.cast_signed()),
            payload_cbor: ActiveValue::Set(entry.payload_cbor.clone()),
            signature: ActiveValue::Set(entry.signature.to_vec()),
        };
        model.insert(&self.conn).await?;
        Ok(())
    }

    /// Get all entries for a tenant, ordered by sequence ascending.
    pub async fn get_entries(
        &self,
        tenant_id: &TenantId,
    ) -> anyhow::Result<Vec<SignedConfigEntry>> {
        let rows = entities::entries::Entity::find()
            .filter(entities::entries::Column::TenantId.eq(tenant_id.as_bytes().to_vec()))
            .order_by_asc(entities::entries::Column::Sequence)
            .all(&self.conn)
            .await?;
        rows.into_iter().map(model_to_entry).collect()
    }

    /// Get all entries across all tenants, ordered by `tenant_id` and sequence ascending.
    pub async fn get_all_entries(&self) -> anyhow::Result<Vec<SignedConfigEntry>> {
        let rows = entities::entries::Entity::find()
            .order_by_asc(entities::entries::Column::TenantId)
            .order_by_asc(entities::entries::Column::Sequence)
            .all(&self.conn)
            .await?;
        rows.into_iter().map(model_to_entry).collect()
    }
}

fn model_to_entry(model: entities::entries::Model) -> anyhow::Result<SignedConfigEntry> {
    let tenant_arr: [u8; 32] = model
        .tenant_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("tenant_id in DB is not 32 bytes"))?;
    let signature_arr: [u8; PQ_SIGNATURE_LEN] = model
        .signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature in DB is not {PQ_SIGNATURE_LEN} bytes"))?;
    Ok(SignedConfigEntry {
        tenant_id: TenantId::from_bytes(&tenant_arr),
        payload_cbor: model.payload_cbor,
        signature: Box::new(signature_arr),
    })
}

/// Convert a 32-byte tenant id to its DB storage form.
pub(super) fn tenant_id_bytes(id: &TenantId) -> Vec<u8> {
    id.as_bytes().to_vec()
}

/// Parse a BLOB column back into a fixed-size array.
pub(super) fn bytes_to_array<const N: usize>(bytes: Vec<u8>, ctx: &str) -> anyhow::Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{ctx} in DB is not {N} bytes"))
}

/// Create an in-memory Db for tests. Exposed at `pub(crate)` so both the
/// db-layer tests and the api-layer tests (in `hub/api.rs`) share a single
/// migration-aware constructor instead of reimplementing the setup.
#[cfg(test)]
pub(super) async fn temp_db() -> Db {
    // One connection only — shared `sqlite::memory:` pools across
    // multiple connections would create separate databases.
    let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
    opts.max_connections(1).min_connections(1);
    let conn = Database::connect(opts).await.unwrap();
    Migrator::up(&conn, None).await.unwrap();
    Db { conn }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turbo_common::config_entry::{ConfigOp, ConfigPayload};
    use turbo_common::identity::TenantKeypair;

    fn make_signed_entry(kp: &TenantKeypair, seq: u64) -> SignedConfigEntry {
        let payload = ConfigPayload {
            version: 1,
            tenant_id: kp.id(),
            sequence: seq,
            timestamp: 1_700_000_000 + seq,
            op: ConfigOp::UpsertHostname {
                hostname: format!("app{seq}.example.com"),
            },
        };
        SignedConfigEntry::sign(&payload, kp).unwrap()
    }

    #[tokio::test]
    async fn insert_and_retrieve() {
        let db = temp_db().await;
        let kp = TenantKeypair::generate();
        let entry = make_signed_entry(&kp, 1);

        db.insert(&entry, 1).await.unwrap();

        let entries = db.get_entries(&kp.id()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].payload_cbor, entry.payload_cbor);
        assert_eq!(entries[0].signature, entry.signature);
        assert_eq!(entries[0].tenant_id, kp.id());
    }

    #[tokio::test]
    async fn entries_ordered_by_sequence() {
        let db = temp_db().await;
        let kp = TenantKeypair::generate();

        for seq in [3, 1, 5, 2, 4] {
            let entry = make_signed_entry(&kp, seq);
            db.insert(&entry, seq).await.unwrap();
        }

        let entries = db.get_entries(&kp.id()).await.unwrap();
        assert_eq!(entries.len(), 5);

        for (i, entry) in entries.iter().enumerate() {
            let payload = entry.verify(kp.public_key()).unwrap();
            assert_eq!(payload.sequence, (i as u64) + 1);
        }
    }

    #[tokio::test]
    async fn duplicate_sequence_rejected() {
        let db = temp_db().await;
        let kp = TenantKeypair::generate();

        let entry = make_signed_entry(&kp, 1);
        db.insert(&entry, 1).await.unwrap();

        let entry2 = make_signed_entry(&kp, 1);
        let result = db.insert(&entry2, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn different_tenants_isolated() {
        let db = temp_db().await;
        let kp1 = TenantKeypair::generate();
        let kp2 = TenantKeypair::generate();

        let entry1 = make_signed_entry(&kp1, 1);
        let entry2 = make_signed_entry(&kp2, 1);

        db.insert(&entry1, 1).await.unwrap();
        db.insert(&entry2, 1).await.unwrap();

        let entries1 = db.get_entries(&kp1.id()).await.unwrap();
        let entries2 = db.get_entries(&kp2.id()).await.unwrap();

        assert_eq!(entries1.len(), 1);
        assert_eq!(entries2.len(), 1);
        assert_eq!(entries1[0].tenant_id, kp1.id());
        assert_eq!(entries2[0].tenant_id, kp2.id());
    }
}
