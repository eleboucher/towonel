use sqlx::Row;
use turbo_common::identity::{PqPublicKey, TenantId};

use super::{Db, FederatedTenant};

impl Db {
    /// Insert a tenant learned from a peer hub. Idempotent on `tenant_id`
    /// — the first peer to announce a tenant wins; subsequent INSERTs are
    /// silently dropped (sqlx OR IGNORE).
    pub async fn insert_federated_tenant(
        &self,
        tenant: &FederatedTenant,
        source_peer_node_id: &[u8; 32],
    ) -> anyhow::Result<()> {
        let hostnames_json = serde_json::to_string(&tenant.hostnames)?;
        sqlx::query(
            "INSERT OR IGNORE INTO federated_tenants \
             (tenant_id, pq_public_key, hostnames_json, registered_at_ms, source_peer_node_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.tenant_id.as_bytes().as_slice())
        .bind(tenant.pq_public_key.as_bytes().as_slice())
        .bind(&hostnames_json)
        .bind(tenant.registered_at_ms.cast_signed())
        .bind(source_peer_node_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Tenants federated from peers, used at hub boot to populate the
    /// in-memory `OwnershipPolicy`.
    pub async fn list_federated_tenants(&self) -> anyhow::Result<Vec<FederatedTenant>> {
        let rows = sqlx::query(
            "SELECT tenant_id, pq_public_key, hostnames_json, registered_at_ms \
             FROM federated_tenants",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let tenant_bytes: Vec<u8> = row.get("tenant_id");
                let pq_bytes: Vec<u8> = row.get("pq_public_key");
                let hostnames_json: String = row.get("hostnames_json");
                let tenant_arr: [u8; 32] = tenant_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("federated tenant_id is not 32 bytes"))?;
                let pq_public_key = PqPublicKey::from_slice(&pq_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid federated pq_public_key: {e}"))?;
                let hostnames: Vec<String> = serde_json::from_str(&hostnames_json)?;
                Ok(FederatedTenant {
                    tenant_id: TenantId::from_bytes(&tenant_arr),
                    pq_public_key,
                    hostnames,
                    registered_at_ms: row.get::<i64, _>("registered_at_ms").cast_unsigned(),
                })
            })
            .collect()
    }
}
