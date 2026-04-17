use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue, EntityTrait, TransactionTrait};
use turbo_common::identity::{PqPublicKey, TenantId};

use super::entities::{federated_tenant_hostnames, federated_tenants};
use super::{Db, FederatedTenant, bytes_to_array, tenant_id_bytes};

impl Db {
    /// Insert a tenant learned from a peer hub. Idempotent on `tenant_id` —
    /// the first peer to announce a tenant wins; subsequent inserts are
    /// dropped via `ON CONFLICT DO NOTHING`. Hostnames land in the
    /// normalized `federated_tenant_hostnames` child table.
    pub async fn insert_federated_tenant(
        &self,
        tenant: &FederatedTenant,
        source_peer_node_id: &[u8; 32],
    ) -> anyhow::Result<()> {
        let txn = self.conn.begin().await?;

        let parent = federated_tenants::ActiveModel {
            tenant_id: ActiveValue::Set(tenant_id_bytes(&tenant.tenant_id)),
            pq_public_key: ActiveValue::Set(tenant.pq_public_key.as_bytes().to_vec()),
            registered_at_ms: ActiveValue::Set(tenant.registered_at_ms.cast_signed()),
            source_peer_node_id: ActiveValue::Set(source_peer_node_id.to_vec()),
        };
        let result = federated_tenants::Entity::insert(parent)
            .on_conflict(
                OnConflict::column(federated_tenants::Column::TenantId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&txn)
            .await;
        // SeaORM returns DbErr::RecordNotInserted when a do_nothing() conflict
        // drops the row. That's the intended idempotent path — swallow it.
        match result {
            Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {}
            Err(e) => return Err(e.into()),
        }

        let host_rows: Vec<federated_tenant_hostnames::ActiveModel> = tenant
            .hostnames
            .iter()
            .map(|h| federated_tenant_hostnames::ActiveModel {
                tenant_id: ActiveValue::Set(tenant_id_bytes(&tenant.tenant_id)),
                hostname_lower: ActiveValue::Set(h.to_lowercase()),
                hostname: ActiveValue::Set(h.clone()),
            })
            .collect();
        if !host_rows.is_empty() {
            // Child rows are equally idempotent: if the parent already
            // existed, the same (tenant_id, hostname_lower) pair is also
            // expected to already exist, so skip conflicts silently.
            federated_tenant_hostnames::Entity::insert_many(host_rows)
                .on_conflict(
                    OnConflict::columns([
                        federated_tenant_hostnames::Column::TenantId,
                        federated_tenant_hostnames::Column::HostnameLower,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(&txn)
                .await
                .or_else(|e| match e {
                    sea_orm::DbErr::RecordNotInserted => Ok(sea_orm::InsertResult {
                        last_insert_id: Default::default(),
                    }),
                    other => Err(other),
                })?;
        }

        txn.commit().await?;
        Ok(())
    }

    /// Tenants federated from peers, used at hub boot to populate the
    /// in-memory `OwnershipPolicy`.
    pub async fn list_federated_tenants(&self) -> anyhow::Result<Vec<FederatedTenant>> {
        let rows = federated_tenants::Entity::find()
            .find_with_related(federated_tenant_hostnames::Entity)
            .all(&self.conn)
            .await?;

        rows.into_iter()
            .map(|(parent, hns)| {
                let tenant_arr = bytes_to_array::<32>(parent.tenant_id, "federated tenant_id")?;
                let pq_public_key = PqPublicKey::from_slice(&parent.pq_public_key)
                    .map_err(|e| anyhow::anyhow!("invalid federated pq_public_key: {e}"))?;
                Ok(FederatedTenant {
                    tenant_id: TenantId::from_bytes(&tenant_arr),
                    pq_public_key,
                    hostnames: hns.into_iter().map(|h| h.hostname).collect(),
                    registered_at_ms: parent.registered_at_ms.cast_unsigned(),
                })
            })
            .collect()
    }
}
