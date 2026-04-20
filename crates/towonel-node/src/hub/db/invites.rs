use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, TransactionTrait,
};
use towonel_common::identity::{PqPublicKey, TenantId};
use towonel_common::invite::INVITE_ID_LEN;

use super::entities::{edge_invites, invite_hostnames, invites, tenant_removals};
use super::{
    Db, EdgeInviteRow, InviteRow, InviteStatus, PendingEdgeInvite, PendingInvite, RedeemedTenant,
    bytes_to_array, tenant_id_bytes,
};

impl Db {
    /// Persist a freshly created tenant invite. v2 invites bind the tenant
    /// identity at creation time, so `tenant_id` and `pq_public_key` are
    /// populated on insert (no redemption dance). Hostnames land in the
    /// normalized `invite_hostnames` child table.
    pub async fn insert_invite(&self, invite: &PendingInvite<'_>) -> anyhow::Result<()> {
        let txn = self.conn.begin().await?;

        invites::ActiveModel {
            invite_id: ActiveValue::Set(invite.invite_id.to_vec()),
            name: ActiveValue::Set(invite.name.to_string()),
            secret_hash: ActiveValue::Set(invite.secret_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(invite.expires_at_ms.map(u64::cast_signed)),
            status: ActiveValue::Set(InviteStatus::Pending.as_str().to_string()),
            tenant_id: ActiveValue::Set(Some(tenant_id_bytes(&invite.tenant_id))),
            tenant_pq_public_key: ActiveValue::Set(Some(invite.pq_public_key.as_bytes().to_vec())),
            created_at_ms: ActiveValue::Set(invite.created_at_ms.cast_signed()),
        }
        .insert(&txn)
        .await?;

        insert_hostnames(&txn, &invite.invite_id, invite.hostnames).await?;

        txn.commit().await?;
        Ok(())
    }

    pub async fn get_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<Option<InviteRow>> {
        let Some(model) = invites::Entity::find_by_id(invite_id.to_vec())
            .one(&self.conn)
            .await?
        else {
            return Ok(None);
        };
        let hostnames = load_invite_hostnames(&self.conn, invite_id).await?;
        Ok(Some(model_to_invite_row(model, hostnames)?))
    }

    pub async fn list_invites(&self) -> anyhow::Result<Vec<InviteRow>> {
        let rows = invites::Entity::find()
            .find_with_related(invite_hostnames::Entity)
            .order_by_desc(invites::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        rows.into_iter()
            .map(|(invite, hns)| {
                let hostnames = hns.into_iter().map(|h| h.hostname).collect();
                model_to_invite_row(invite, hostnames)
            })
            .collect()
    }

    pub async fn revoke_invite(&self, invite_id: &[u8; INVITE_ID_LEN]) -> anyhow::Result<bool> {
        let result = invites::Entity::update_many()
            .col_expr(
                invites::Column::Status,
                sea_orm::sea_query::Expr::value(InviteStatus::Revoked.as_str()),
            )
            .filter(invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(invites::Column::Status.ne(InviteStatus::Revoked.as_str()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Return the first hostname in `candidates_lower` that is already
    /// claimed by a non-revoked invite, or `None`. Must be called under the
    /// `AppState` invite lock so two concurrent create-invite calls can't
    /// both see "no conflict" and both insert.
    pub async fn any_active_invite_claims(
        &self,
        candidates_lower: &[String],
    ) -> anyhow::Result<Option<String>> {
        if candidates_lower.is_empty() {
            return Ok(None);
        }
        let hit = invite_hostnames::Entity::find()
            .join(
                JoinType::InnerJoin,
                invite_hostnames::Relation::Invite.def(),
            )
            .filter(invites::Column::Status.ne(InviteStatus::Revoked.as_str()))
            .filter(invite_hostnames::Column::HostnameLower.is_in(candidates_lower.to_vec()))
            .one(&self.conn)
            .await?;
        Ok(hit.map(|h| h.hostname_lower))
    }

    /// Record an operator decision to remove a tenant from service.
    /// Idempotent: repeat calls update `removed_at_ms` without erroring.
    pub async fn remove_tenant(
        &self,
        tenant_id: &TenantId,
        removed_at_ms: u64,
    ) -> anyhow::Result<()> {
        let model = tenant_removals::ActiveModel {
            tenant_id: ActiveValue::Set(tenant_id_bytes(tenant_id)),
            removed_at_ms: ActiveValue::Set(removed_at_ms.cast_signed()),
        };
        tenant_removals::Entity::insert(model)
            .on_conflict(
                OnConflict::column(tenant_removals::Column::TenantId)
                    .update_column(tenant_removals::Column::RemovedAtMs)
                    .to_owned(),
            )
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn list_tenant_removals(&self) -> anyhow::Result<Vec<TenantId>> {
        let rows = tenant_removals::Entity::find().all(&self.conn).await?;
        rows.into_iter()
            .map(|row| {
                let arr = bytes_to_array::<32>(row.tenant_id, "removed tenant_id")?;
                Ok(TenantId::from_bytes(&arr))
            })
            .collect()
    }

    /// All active (non-revoked) tenants registered via invites. The hub
    /// calls this at boot to rebuild the in-memory `OwnershipPolicy` so
    /// restart survives without a separate tenants table. v2 invites store
    /// the tenant identity at creation time, so even invites that have
    /// never seen a `/v1/bootstrap` call show up here.
    pub async fn list_active_tenants(&self) -> anyhow::Result<Vec<RedeemedTenant>> {
        let rows = invites::Entity::find()
            .filter(invites::Column::Status.ne(InviteStatus::Revoked.as_str()))
            .filter(invites::Column::TenantId.is_not_null())
            .filter(invites::Column::TenantPqPublicKey.is_not_null())
            .find_with_related(invite_hostnames::Entity)
            .all(&self.conn)
            .await?;

        rows.into_iter()
            .map(|(invite, hns)| {
                let tenant_bytes = invite
                    .tenant_id
                    .ok_or_else(|| anyhow::anyhow!("active invite missing tenant_id"))?;
                let pq_bytes = invite
                    .tenant_pq_public_key
                    .ok_or_else(|| anyhow::anyhow!("active invite missing tenant_pq_public_key"))?;
                let tenant_arr = bytes_to_array::<32>(tenant_bytes, "active tenant_id")?;
                let pq_public_key = PqPublicKey::from_slice(&pq_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid active pq_public_key: {e}"))?;
                Ok(RedeemedTenant {
                    tenant_id: TenantId::from_bytes(&tenant_arr),
                    hostnames: hns.into_iter().map(|h| h.hostname).collect(),
                    pq_public_key,
                })
            })
            .collect()
    }

    pub async fn insert_edge_invite(&self, invite: &PendingEdgeInvite<'_>) -> anyhow::Result<()> {
        edge_invites::ActiveModel {
            invite_id: ActiveValue::Set(invite.invite_id.to_vec()),
            name: ActiveValue::Set(invite.name.to_string()),
            secret_hash: ActiveValue::Set(invite.secret_hash.to_vec()),
            status: ActiveValue::Set(InviteStatus::Pending.as_str().to_string()),
            edge_node_id: ActiveValue::Set(invite.edge_node_id.to_vec()),
            created_at_ms: ActiveValue::Set(invite.created_at_ms.cast_signed()),
        }
        .insert(&self.conn)
        .await?;
        Ok(())
    }

    pub async fn list_edge_invites(&self) -> anyhow::Result<Vec<EdgeInviteRow>> {
        let rows = edge_invites::Entity::find()
            .order_by_desc(edge_invites::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        rows.into_iter().map(model_to_edge_invite_row).collect()
    }

    /// Revoke a pending edge invite. The next call to
    /// [`Self::edge_is_registered`] for that `node_id` returns false
    /// because the invite row is now `revoked`. Returns false if the
    /// invite was not pending (already revoked or missing).
    pub async fn revoke_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<bool> {
        let result = edge_invites::Entity::update_many()
            .col_expr(
                edge_invites::Column::Status,
                sea_orm::sea_query::Expr::value(InviteStatus::Revoked.as_str()),
            )
            .filter(edge_invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(edge_invites::Column::Status.eq(InviteStatus::Pending.as_str()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn edge_is_registered(&self, edge_node_id: &[u8; 32]) -> anyhow::Result<bool> {
        let Some(invite) = edge_invites::Entity::find()
            .filter(edge_invites::Column::EdgeNodeId.eq(edge_node_id.to_vec()))
            .one(&self.conn)
            .await?
        else {
            return Ok(false);
        };
        Ok(invite.status == InviteStatus::Pending.as_str())
    }

    /// Oldest-first so the first element is stable across scans.
    pub async fn list_trusted_edge_ids(&self) -> anyhow::Result<Vec<[u8; 32]>> {
        let rows = edge_invites::Entity::find()
            .filter(edge_invites::Column::Status.ne(InviteStatus::Revoked.as_str()))
            .order_by_asc(edge_invites::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        rows.into_iter()
            .map(|m| bytes_to_array::<32>(m.edge_node_id, "edge_node_id"))
            .collect()
    }
}

async fn insert_hostnames(
    conn: &impl sea_orm::ConnectionTrait,
    invite_id: &[u8; INVITE_ID_LEN],
    hostnames: &[String],
) -> anyhow::Result<()> {
    if hostnames.is_empty() {
        return Ok(());
    }
    let rows: Vec<invite_hostnames::ActiveModel> = hostnames
        .iter()
        .map(|h| invite_hostnames::ActiveModel {
            invite_id: ActiveValue::Set(invite_id.to_vec()),
            hostname_lower: ActiveValue::Set(h.to_lowercase()),
            hostname: ActiveValue::Set(h.clone()),
        })
        .collect();
    invite_hostnames::Entity::insert_many(rows)
        .exec(conn)
        .await?;
    Ok(())
}

async fn load_invite_hostnames(
    conn: &sea_orm::DatabaseConnection,
    invite_id: &[u8; INVITE_ID_LEN],
) -> anyhow::Result<Vec<String>> {
    let rows = invite_hostnames::Entity::find()
        .filter(invite_hostnames::Column::InviteId.eq(invite_id.to_vec()))
        .all(conn)
        .await?;
    Ok(rows.into_iter().map(|r| r.hostname).collect())
}

fn model_to_invite_row(model: invites::Model, hostnames: Vec<String>) -> anyhow::Result<InviteRow> {
    let tenant_bytes = model.tenant_id.ok_or_else(|| {
        anyhow::anyhow!("invite row missing tenant_id (v1 data? rerun migration)")
    })?;
    let tenant_arr = bytes_to_array::<32>(tenant_bytes, "tenant_id")?;
    Ok(InviteRow {
        invite_id: bytes_to_array(model.invite_id, "invite_id")?,
        name: model.name,
        hostnames,
        secret_hash: bytes_to_array(model.secret_hash, "secret_hash")?,
        expires_at_ms: model.expires_at_ms.map(i64::cast_unsigned),
        status: InviteStatus::parse(&model.status)?,
        tenant_id: TenantId::from_bytes(&tenant_arr),
        created_at_ms: model.created_at_ms.cast_unsigned(),
    })
}

fn model_to_edge_invite_row(model: edge_invites::Model) -> anyhow::Result<EdgeInviteRow> {
    Ok(EdgeInviteRow {
        invite_id: bytes_to_array(model.invite_id, "invite_id")?,
        name: model.name,
        secret_hash: bytes_to_array(model.secret_hash, "secret_hash")?,
        status: InviteStatus::parse(&model.status)?,
        edge_node_id: bytes_to_array::<32>(model.edge_node_id, "edge_node_id")?,
        created_at_ms: model.created_at_ms.cast_unsigned(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::temp_db;
    use super::*;
    use std::sync::OnceLock;
    use towonel_common::identity::TenantKeypair;
    use towonel_common::invite::{InviteHashKey, hash_invite_secret};

    fn test_key() -> &'static InviteHashKey {
        static KEY: OnceLock<InviteHashKey> = OnceLock::new();
        KEY.get_or_init(InviteHashKey::generate)
    }

    struct PendingInput {
        id_byte: u8,
        name: String,
        hostnames: Vec<String>,
        secret: [u8; 32],
        expires_at_ms: Option<u64>,
        tenant: TenantKeypair,
    }

    fn input(id_byte: u8, name: &str, hostnames: &[&str]) -> PendingInput {
        PendingInput {
            id_byte,
            name: name.to_string(),
            hostnames: hostnames.iter().map(|s| (*s).to_string()).collect(),
            secret: [id_byte ^ 0xaa; 32],
            expires_at_ms: Some(2_000_000_000_000),
            tenant: TenantKeypair::generate(),
        }
    }

    async fn insert(db: &Db, i: &PendingInput) -> [u8; INVITE_ID_LEN] {
        let pending = PendingInvite {
            invite_id: [i.id_byte; INVITE_ID_LEN],
            name: &i.name,
            hostnames: &i.hostnames,
            secret_hash: hash_invite_secret(test_key(), &i.secret),
            tenant_id: i.tenant.id(),
            pq_public_key: i.tenant.public_key(),
            expires_at_ms: i.expires_at_ms,
            created_at_ms: 1_700_000_000_000,
        };
        db.insert_invite(&pending).await.unwrap();
        pending.invite_id
    }

    #[tokio::test]
    async fn invite_insert_and_get_binds_tenant() {
        let db = temp_db().await;
        let i = input(1, "alice", &["app.alice.example.eu"]);
        let id = insert(&db, &i).await;

        let row = db.get_invite(&id).await.unwrap().unwrap();
        assert_eq!(row.invite_id, id);
        assert_eq!(row.name, "alice");
        assert_eq!(row.hostnames, i.hostnames);
        assert_eq!(row.secret_hash, hash_invite_secret(test_key(), &i.secret));
        assert_eq!(row.status, InviteStatus::Pending);
        assert_eq!(row.expires_at_ms, Some(2_000_000_000_000));
        assert_eq!(row.tenant_id, i.tenant.id());
    }

    #[tokio::test]
    async fn invite_without_expiry_persists_as_null() {
        let db = temp_db().await;
        let mut i = input(1, "forever", &["f.example.eu"]);
        i.expires_at_ms = None;
        let id = insert(&db, &i).await;

        let row = db.get_invite(&id).await.unwrap().unwrap();
        assert_eq!(row.expires_at_ms, None);
    }

    #[tokio::test]
    async fn invite_duplicate_id_rejected() {
        let db = temp_db().await;
        let a = input(7, "a", &["app.example.eu"]);
        let b = input(7, "b", &["other.example.eu"]);
        insert(&db, &a).await;
        let pending = PendingInvite {
            invite_id: [7; INVITE_ID_LEN],
            name: &b.name,
            hostnames: &b.hostnames,
            secret_hash: hash_invite_secret(test_key(), &b.secret),
            tenant_id: b.tenant.id(),
            pq_public_key: b.tenant.public_key(),
            expires_at_ms: b.expires_at_ms,
            created_at_ms: 1_700_000_000_001,
        };
        assert!(db.insert_invite(&pending).await.is_err());
    }

    #[tokio::test]
    async fn invite_list_returns_all() {
        let db = temp_db().await;
        for id in [1u8, 2, 3] {
            let i = input(id, "t", &["a.example.eu"]);
            insert(&db, &i).await;
        }
        let rows = db.list_invites().await.unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn revoke_flips_status_and_is_not_idempotent() {
        let db = temp_db().await;
        let i = input(8, "t", &["h.example.eu"]);
        let id = insert(&db, &i).await;

        assert!(db.revoke_invite(&id).await.unwrap());
        let row = db.get_invite(&id).await.unwrap().unwrap();
        assert_eq!(row.status, InviteStatus::Revoked);
        assert!(!db.revoke_invite(&id).await.unwrap());
    }

    #[tokio::test]
    async fn any_active_invite_claims_matches_case_insensitively() {
        let db = temp_db().await;
        let i = input(20, "alice", &["App.Alice.Example.EU"]);
        insert(&db, &i).await;

        let got = db
            .any_active_invite_claims(&["app.alice.example.eu".to_string()])
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("app.alice.example.eu"));

        let got = db
            .any_active_invite_claims(&["other.example.eu".to_string()])
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn any_active_invite_claims_ignores_revoked() {
        let db = temp_db().await;
        let i = input(21, "t", &["revoked.example.eu"]);
        let id = insert(&db, &i).await;
        db.revoke_invite(&id).await.unwrap();

        let got = db
            .any_active_invite_claims(&["revoked.example.eu".to_string()])
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn tenant_removal_roundtrip() {
        let db = temp_db().await;
        let t1 = TenantKeypair::generate();
        let t2 = TenantKeypair::generate();

        db.remove_tenant(&t1.id(), 1_700_000_000_000).await.unwrap();
        db.remove_tenant(&t2.id(), 1_700_000_000_001).await.unwrap();

        let removals = db.list_tenant_removals().await.unwrap();
        assert_eq!(removals.len(), 2);
        assert!(removals.contains(&t1.id()));
        assert!(removals.contains(&t2.id()));
    }

    #[tokio::test]
    async fn tenant_removal_is_idempotent() {
        let db = temp_db().await;
        let tenant = TenantKeypair::generate();

        db.remove_tenant(&tenant.id(), 100).await.unwrap();
        db.remove_tenant(&tenant.id(), 200).await.unwrap();

        let removals = db.list_tenant_removals().await.unwrap();
        assert_eq!(removals.len(), 1);
    }

    #[tokio::test]
    async fn list_active_tenants_excludes_revoked() {
        let db = temp_db().await;
        let a = input(10, "alice", &["app.alice.example.eu"]);
        let b = input(11, "bob", &["app.bob.example.eu"]);
        let c = input(12, "charlie", &["app.charlie.example.eu"]);
        let a_id = insert(&db, &a).await;
        let _b_id = insert(&db, &b).await;
        let c_id = insert(&db, &c).await;

        db.revoke_invite(&c_id).await.unwrap();

        let tenants = db.list_active_tenants().await.unwrap();
        assert_eq!(tenants.len(), 2);
        let ids: std::collections::HashSet<_> = tenants.iter().map(|t| t.tenant_id).collect();
        assert!(ids.contains(&a.tenant.id()));
        assert!(ids.contains(&b.tenant.id()));
        assert!(!ids.contains(&c.tenant.id()));
        let _ = a_id; // silence unused
    }
}
