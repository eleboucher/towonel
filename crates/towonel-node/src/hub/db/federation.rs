use std::collections::{HashMap, HashSet};

use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use towonel_common::identity::{PqPublicKey, TenantId};

use super::entities::{federated_tenant_hostnames, federated_tenants, federation_push_state};
use super::{Db, FederatedTenant, bytes_to_array, tenant_id_bytes};

/// Per-peer snapshot of what this hub has already federated out.
#[derive(Debug, Default, Clone)]
pub struct FederationPushState {
    pub tenants: HashSet<TenantId>,
    pub removals: HashSet<TenantId>,
    pub entry_seq: HashMap<TenantId, u64>,
}

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
            let result = federated_tenant_hostnames::Entity::insert_many(host_rows)
                .on_conflict(
                    OnConflict::columns([
                        federated_tenant_hostnames::Column::TenantId,
                        federated_tenant_hostnames::Column::HostnameLower,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(&txn)
                .await;
            match result {
                Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {}
                Err(e) => return Err(e.into()),
            }
        }

        txn.commit().await?;
        Ok(())
    }

    /// Load what we've already pushed to `peer`. Used by `run_peer` at
    /// startup so a hub restart does not redundantly re-push every tenant,
    /// removal, and entry to every peer.
    pub async fn load_federation_push_state(
        &self,
        peer_node_id: &[u8; 32],
    ) -> anyhow::Result<FederationPushState> {
        let rows = federation_push_state::Entity::find()
            .filter(federation_push_state::Column::PeerNodeId.eq(peer_node_id.to_vec()))
            .all(&self.conn)
            .await?;

        let mut state = FederationPushState::default();
        for row in rows {
            let arr = bytes_to_array::<32>(row.tenant_id, "push_state tenant_id")?;
            let tid = TenantId::from_bytes(&arr);
            if row.tenant_pushed {
                state.tenants.insert(tid);
            }
            if row.removal_pushed {
                state.removals.insert(tid);
            }
            if row.last_sent_sequence > 0 {
                state
                    .entry_seq
                    .insert(tid, row.last_sent_sequence.cast_unsigned());
            }
        }
        Ok(state)
    }

    /// Batch UPSERT: mark many tenants as pushed to `peer_node_id` in a
    /// single `INSERT ... ON CONFLICT DO UPDATE`. No-op on empty input.
    pub async fn mark_federation_tenants_pushed_batch(
        &self,
        peer_node_id: &[u8; 32],
        tenant_ids: &[TenantId],
    ) -> anyhow::Result<()> {
        batch_upsert_push_state(&self.conn, peer_node_id, tenant_ids, BatchMark::Tenant).await
    }

    pub async fn mark_federation_removals_pushed_batch(
        &self,
        peer_node_id: &[u8; 32],
        tenant_ids: &[TenantId],
    ) -> anyhow::Result<()> {
        batch_upsert_push_state(&self.conn, peer_node_id, tenant_ids, BatchMark::Removal).await
    }

    pub async fn mark_federation_entries_pushed_batch(
        &self,
        peer_node_id: &[u8; 32],
        items: &[(TenantId, u64)],
    ) -> anyhow::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let rows: Vec<federation_push_state::ActiveModel> = items
            .iter()
            .map(|(tid, seq)| federation_push_state::ActiveModel {
                peer_node_id: ActiveValue::Set(peer_node_id.to_vec()),
                tenant_id: ActiveValue::Set(tenant_id_bytes(tid)),
                tenant_pushed: ActiveValue::Set(false),
                removal_pushed: ActiveValue::Set(false),
                last_sent_sequence: ActiveValue::Set(seq.cast_signed()),
            })
            .collect();
        federation_push_state::Entity::insert_many(rows)
            .on_conflict(
                OnConflict::columns([
                    federation_push_state::Column::PeerNodeId,
                    federation_push_state::Column::TenantId,
                ])
                .update_column(federation_push_state::Column::LastSentSequence)
                .to_owned(),
            )
            .exec(&self.conn)
            .await?;
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

enum BatchMark {
    Tenant,
    Removal,
}

async fn batch_upsert_push_state(
    conn: &sea_orm::DatabaseConnection,
    peer_node_id: &[u8; 32],
    tenant_ids: &[TenantId],
    mark: BatchMark,
) -> anyhow::Result<()> {
    if tenant_ids.is_empty() {
        return Ok(());
    }
    let (tenant_flag, removal_flag, column) = match mark {
        BatchMark::Tenant => (true, false, federation_push_state::Column::TenantPushed),
        BatchMark::Removal => (false, true, federation_push_state::Column::RemovalPushed),
    };
    let rows: Vec<federation_push_state::ActiveModel> = tenant_ids
        .iter()
        .map(|tid| federation_push_state::ActiveModel {
            peer_node_id: ActiveValue::Set(peer_node_id.to_vec()),
            tenant_id: ActiveValue::Set(tenant_id_bytes(tid)),
            tenant_pushed: ActiveValue::Set(tenant_flag),
            removal_pushed: ActiveValue::Set(removal_flag),
            last_sent_sequence: ActiveValue::Set(0),
        })
        .collect();
    federation_push_state::Entity::insert_many(rows)
        .on_conflict(
            OnConflict::columns([
                federation_push_state::Column::PeerNodeId,
                federation_push_state::Column::TenantId,
            ])
            .update_column(column)
            .to_owned(),
        )
        .exec(conn)
        .await?;
    Ok(())
}
