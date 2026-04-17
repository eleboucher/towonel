mod federation;
mod invites;
mod types;

pub use types::*;

use std::path::Path;

use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use turbo_common::config_entry::SignedConfigEntry;
use turbo_common::identity::TenantId;

/// SQL migrations embedded from `crates/turbo-node/migrations/` at compile
/// time. sqlx tracks applied migrations in `_sqlx_migrations` and refuses
/// to run a migration whose checksum has changed since it was first
/// applied, so a shipped migration cannot be edited in place.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Returns true when `e` wraps a `sqlx` UNIQUE-constraint violation.
/// Used by handlers to map duplicate-sequence inserts to 409 / idempotent OK.
pub fn is_unique_violation(e: &anyhow::Error) -> bool {
    if let Some(sqlx::Error::Database(db)) = e.downcast_ref::<sqlx::Error>() {
        db.is_unique_violation()
    } else {
        false
    }
}

/// `SQLite` storage layer for signed config entries.
pub struct Db {
    pool: sqlx::SqlitePool,
}

impl Db {
    /// Open (or create) the `SQLite` database at `path` and apply any
    /// pending migrations.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        MIGRATOR.run(&pool).await?;

        Ok(Self { pool })
    }

    /// Insert a verified entry. The caller must verify the signature before calling this.
    pub async fn insert(&self, entry: &SignedConfigEntry, sequence: u64) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO entries (tenant_id, sequence, payload_cbor, signature) VALUES ($1, $2, $3, $4)",
        )
        .bind(entry.tenant_id.as_bytes().as_slice())
        .bind(sequence.cast_signed())
        .bind(&entry.payload_cbor)
        .bind(entry.signature.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all entries for a tenant, ordered by sequence ascending.
    pub async fn get_entries(
        &self,
        tenant_id: &TenantId,
    ) -> anyhow::Result<Vec<SignedConfigEntry>> {
        let rows = sqlx::query(
            "SELECT tenant_id, payload_cbor, signature FROM entries WHERE tenant_id = $1 ORDER BY sequence ASC",
        )
        .bind(tenant_id.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_entry).collect()
    }

    /// Get all entries across all tenants, ordered by `tenant_id` and sequence ascending.
    pub async fn get_all_entries(&self) -> anyhow::Result<Vec<SignedConfigEntry>> {
        let rows = sqlx::query(
            "SELECT tenant_id, payload_cbor, signature FROM entries ORDER BY tenant_id, sequence ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_entry).collect()
    }
}

/// Extract a fixed-size byte array from a BLOB column.
fn blob<const N: usize>(row: &sqlx::sqlite::SqliteRow, col: &str) -> anyhow::Result<[u8; N]> {
    let v: Vec<u8> = row.get(col);
    v.try_into()
        .map_err(|_| anyhow::anyhow!("{col} in DB is not {N} bytes"))
}

/// Extract an optional fixed-size byte array from a nullable BLOB column.
fn blob_opt<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    col: &str,
) -> anyhow::Result<Option<[u8; N]>> {
    match row.try_get::<Option<Vec<u8>>, _>(col)? {
        Some(v) => {
            Ok(Some(v.try_into().map_err(|_| {
                anyhow::anyhow!("{col} in DB is not {N} bytes")
            })?))
        }
        None => Ok(None),
    }
}

/// Extract an i64 column as u64.
fn ms(row: &sqlx::sqlite::SqliteRow, col: &str) -> u64 {
    row.get::<i64, _>(col).cast_unsigned()
}

/// Extract an optional i64 column as Option<u64>.
fn ms_opt(row: &sqlx::sqlite::SqliteRow, col: &str) -> anyhow::Result<Option<u64>> {
    Ok(row.try_get::<Option<i64>, _>(col)?.map(i64::cast_unsigned))
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<SignedConfigEntry> {
    Ok(SignedConfigEntry {
        tenant_id: TenantId::from_bytes(&blob::<32>(row, "tenant_id")?),
        payload_cbor: row.get("payload_cbor"),
        signature: Box::new(blob(row, "signature")?),
    })
}

/// Create an in-memory Db for tests. Exposed at `pub(crate)` so both the
/// db-layer tests and the api-layer tests (in `hub/api.rs`) share a single
/// migration-aware constructor instead of reimplementing the pool setup.
#[cfg(test)]
pub(crate) async fn temp_db() -> Db {
    // Use max_connections(1) so all queries share the same in-memory database.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Apply the same migrations the production `open()` path uses --
    // tests verify real schema, not a hand-maintained copy.
    MIGRATOR.run(&pool).await.unwrap();

    Db { pool }
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

        // Insert out of order
        for seq in [3, 1, 5, 2, 4] {
            let entry = make_signed_entry(&kp, seq);
            db.insert(&entry, seq).await.unwrap();
        }

        let entries = db.get_entries(&kp.id()).await.unwrap();
        assert_eq!(entries.len(), 5);

        // Verify they come back ordered by verifying each payload's sequence
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

        // Same tenant + sequence should fail (PRIMARY KEY constraint)
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
