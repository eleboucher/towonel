use std::collections::HashSet;

use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use towonel_common::identity::{AgentId, TenantId};

use super::entities::agent_liveness;
use super::{Db, bytes_to_array, tenant_id_bytes};

impl Db {
    /// UPSERT the `(tenant_id, agent_id)` liveness row to `now_ms`. A missing
    /// row is created; an existing one has its `last_seen_ms` bumped.
    pub async fn bump_agent_liveness(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        let model = agent_liveness::ActiveModel {
            tenant_id: ActiveValue::Set(tenant_id_bytes(tenant_id)),
            agent_id: ActiveValue::Set(agent_id.as_bytes().to_vec()),
            last_seen_ms: ActiveValue::Set(now_ms.cast_signed()),
        };
        agent_liveness::Entity::insert(model)
            .on_conflict(
                OnConflict::columns([
                    agent_liveness::Column::TenantId,
                    agent_liveness::Column::AgentId,
                ])
                .update_column(agent_liveness::Column::LastSeenMs)
                .to_owned(),
            )
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    /// Delete rows older than `cutoff_ms`. Returns the number of rows pruned
    /// so callers can decide whether to trigger a route rebuild.
    pub async fn prune_agent_liveness(&self, cutoff_ms: u64) -> anyhow::Result<u64> {
        let result = agent_liveness::Entity::delete_many()
            .filter(agent_liveness::Column::LastSeenMs.lt(cutoff_ms.cast_signed()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }

    /// Every `(tenant, agent)` pair whose `last_seen_ms >= cutoff_ms`.
    pub async fn live_agents(
        &self,
        cutoff_ms: u64,
    ) -> anyhow::Result<HashSet<(TenantId, AgentId)>> {
        let rows = agent_liveness::Entity::find()
            .filter(agent_liveness::Column::LastSeenMs.gte(cutoff_ms.cast_signed()))
            .all(&self.conn)
            .await?;
        rows.into_iter()
            .map(|row| {
                let tenant_arr = bytes_to_array::<32>(row.tenant_id, "agent_liveness.tenant_id")?;
                let agent_arr = bytes_to_array::<32>(row.agent_id, "agent_liveness.agent_id")?;
                let tenant_id = TenantId::from_bytes(&tenant_arr);
                let agent_id = AgentId::from_bytes(&agent_arr)
                    .map_err(|e| anyhow::anyhow!("invalid agent_id in liveness row: {e}"))?;
                Ok((tenant_id, agent_id))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::temp_db;
    use towonel_common::identity::{AgentKeypair, TenantKeypair};

    #[tokio::test]
    async fn bump_inserts_and_upserts() {
        let db = temp_db().await;
        let tenant = TenantKeypair::generate();
        let agent = AgentKeypair::generate();

        db.bump_agent_liveness(&tenant.id(), &agent.id(), 1_000)
            .await
            .unwrap();

        let live = db.live_agents(0).await.unwrap();
        assert_eq!(live.len(), 1);
        assert!(live.contains(&(tenant.id(), agent.id())));

        db.bump_agent_liveness(&tenant.id(), &agent.id(), 5_000)
            .await
            .unwrap();
        let live_recent = db.live_agents(3_000).await.unwrap();
        assert_eq!(live_recent.len(), 1);
        let live_future = db.live_agents(10_000).await.unwrap();
        assert!(live_future.is_empty());
    }

    #[tokio::test]
    async fn prune_removes_stale_rows() {
        let db = temp_db().await;
        let tenant = TenantKeypair::generate();
        let a1 = AgentKeypair::generate();
        let a2 = AgentKeypair::generate();

        db.bump_agent_liveness(&tenant.id(), &a1.id(), 1_000)
            .await
            .unwrap();
        db.bump_agent_liveness(&tenant.id(), &a2.id(), 5_000)
            .await
            .unwrap();

        let pruned = db.prune_agent_liveness(3_000).await.unwrap();
        assert_eq!(pruned, 1);
        let live = db.live_agents(0).await.unwrap();
        assert!(live.contains(&(tenant.id(), a2.id())));
        assert!(!live.contains(&(tenant.id(), a1.id())));
    }
}
