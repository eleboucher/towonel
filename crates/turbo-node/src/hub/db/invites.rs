use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, TransactionTrait,
};
use turbo_common::identity::{PqPublicKey, TenantId};
use turbo_common::invite::INVITE_ID_LEN;

use super::entities::{edge_invites, edges, invite_hostnames, invites, tenant_removals};
use super::{
    Db, EdgeInviteRow, InviteRow, InviteStatus, PendingEdgeInvite, PendingInvite, RedeemedTenant,
    bytes_to_array, tenant_id_bytes,
};

impl Db {
    /// Persist a fresh pending invite. Duplicate `invite_ids` fail via the
    /// PRIMARY KEY constraint. Hostnames are stored in the normalized
    /// `invite_hostnames` child table.
    pub async fn insert_invite(&self, invite: &PendingInvite<'_>) -> anyhow::Result<()> {
        let txn = self.conn.begin().await?;

        invites::ActiveModel {
            invite_id: ActiveValue::Set(invite.invite_id.to_vec()),
            name: ActiveValue::Set(invite.name.to_string()),
            secret_hash: ActiveValue::Set(invite.secret_hash.to_vec()),
            expires_at_ms: ActiveValue::Set(invite.expires_at_ms.cast_signed()),
            status: ActiveValue::Set(InviteStatus::Pending.as_str().to_string()),
            tenant_id: ActiveValue::Set(None),
            tenant_pq_public_key: ActiveValue::Set(None),
            redeemed_at_ms: ActiveValue::Set(None),
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

    /// Mark an invite as redeemed, recording the tenant that consumed it
    /// and their ML-DSA-65 public key.
    ///
    /// Returns true on success, false if the invite was already redeemed /
    /// revoked / missing — callers must treat a `false` return as the
    /// rejection path, not as an error.
    pub async fn redeem_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        tenant_id: &TenantId,
        pq_public_key: &PqPublicKey,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<bool> {
        let result = invites::Entity::update_many()
            .col_expr(
                invites::Column::Status,
                sea_orm::sea_query::Expr::value(InviteStatus::Redeemed.as_str()),
            )
            .col_expr(
                invites::Column::TenantId,
                sea_orm::sea_query::Expr::value(tenant_id_bytes(tenant_id)),
            )
            .col_expr(
                invites::Column::TenantPqPublicKey,
                sea_orm::sea_query::Expr::value(pq_public_key.as_bytes().to_vec()),
            )
            .col_expr(
                invites::Column::RedeemedAtMs,
                sea_orm::sea_query::Expr::value(redeemed_at_ms.cast_signed()),
            )
            .filter(invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(invites::Column::Status.eq(InviteStatus::Pending.as_str()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn re_redeem_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        tenant_id: &TenantId,
        pq_public_key: &PqPublicKey,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<()> {
        invites::Entity::update_many()
            .col_expr(
                invites::Column::TenantId,
                sea_orm::sea_query::Expr::value(tenant_id_bytes(tenant_id)),
            )
            .col_expr(
                invites::Column::TenantPqPublicKey,
                sea_orm::sea_query::Expr::value(pq_public_key.as_bytes().to_vec()),
            )
            .col_expr(
                invites::Column::RedeemedAtMs,
                sea_orm::sea_query::Expr::value(redeemed_at_ms.cast_signed()),
            )
            .filter(invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(invites::Column::Status.eq(InviteStatus::Redeemed.as_str()))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn revoke_invite(&self, invite_id: &[u8; INVITE_ID_LEN]) -> anyhow::Result<bool> {
        let result = invites::Entity::update_many()
            .col_expr(
                invites::Column::Status,
                sea_orm::sea_query::Expr::value(InviteStatus::Revoked.as_str()),
            )
            .filter(invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(invites::Column::Status.eq(InviteStatus::Pending.as_str()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Return the first hostname in `candidates_lower` that is already
    /// claimed by a pending invite, or `None`. Must be called under the
    /// `AppState` invite lock (see api.rs) — otherwise two concurrent
    /// create-invite calls can both see "no conflict" and both insert.
    pub async fn any_pending_invite_claims(
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
            .filter(invites::Column::Status.eq(InviteStatus::Pending.as_str()))
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

    /// All currently-removed tenants. Used at hub boot to filter the
    /// allowlist, and by tests.
    pub async fn list_tenant_removals(&self) -> anyhow::Result<Vec<TenantId>> {
        let rows = tenant_removals::Entity::find().all(&self.conn).await?;
        rows.into_iter()
            .map(|row| {
                let arr = bytes_to_array::<32>(row.tenant_id, "removed tenant_id")?;
                Ok(TenantId::from_bytes(&arr))
            })
            .collect()
    }

    /// Redeemed invites are the source of truth for dynamic tenants. The
    /// hub calls this at boot to populate the in-memory `OwnershipPolicy`
    /// so restart survives without a separate tenants table.
    pub async fn list_redeemed_tenants(&self) -> anyhow::Result<Vec<RedeemedTenant>> {
        let rows = invites::Entity::find()
            .filter(invites::Column::Status.eq(InviteStatus::Redeemed.as_str()))
            .filter(invites::Column::TenantId.is_not_null())
            .filter(invites::Column::TenantPqPublicKey.is_not_null())
            .find_with_related(invite_hostnames::Entity)
            .all(&self.conn)
            .await?;

        rows.into_iter()
            .map(|(invite, hns)| {
                // NULL filter above guarantees these are Some.
                let tenant_bytes = invite
                    .tenant_id
                    .ok_or_else(|| anyhow::anyhow!("redeemed invite missing tenant_id"))?;
                let pq_bytes = invite.tenant_pq_public_key.ok_or_else(|| {
                    anyhow::anyhow!("redeemed invite missing tenant_pq_public_key")
                })?;
                let tenant_arr = bytes_to_array::<32>(tenant_bytes, "redeemed tenant_id")?;
                let pq_public_key = PqPublicKey::from_slice(&pq_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid redeemed pq_public_key: {e}"))?;
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
            expires_at_ms: ActiveValue::Set(invite.expires_at_ms.cast_signed()),
            status: ActiveValue::Set(InviteStatus::Pending.as_str().to_string()),
            edge_node_id: ActiveValue::Set(None),
            redeemed_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(invite.created_at_ms.cast_signed()),
        }
        .insert(&self.conn)
        .await?;
        Ok(())
    }

    pub async fn get_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<Option<EdgeInviteRow>> {
        let model = edge_invites::Entity::find_by_id(invite_id.to_vec())
            .one(&self.conn)
            .await?;
        model.map(model_to_edge_invite_row).transpose()
    }

    pub async fn list_edge_invites(&self) -> anyhow::Result<Vec<EdgeInviteRow>> {
        let rows = edge_invites::Entity::find()
            .order_by_desc(edge_invites::Column::CreatedAtMs)
            .all(&self.conn)
            .await?;
        rows.into_iter().map(model_to_edge_invite_row).collect()
    }

    /// Atomically flip a pending edge invite to `redeemed` and register the
    /// edge's iroh `node_id`. Both rows land in the same transaction — either
    /// both succeed or neither. Returns false if the invite was not pending
    /// (already redeemed, revoked, or missing).
    pub async fn redeem_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        edge_node_id: &[u8; 32],
        name: &str,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<bool> {
        let txn = self.conn.begin().await?;

        let updated = edge_invites::Entity::update_many()
            .col_expr(
                edge_invites::Column::Status,
                sea_orm::sea_query::Expr::value(InviteStatus::Redeemed.as_str()),
            )
            .col_expr(
                edge_invites::Column::EdgeNodeId,
                sea_orm::sea_query::Expr::value(edge_node_id.to_vec()),
            )
            .col_expr(
                edge_invites::Column::RedeemedAtMs,
                sea_orm::sea_query::Expr::value(redeemed_at_ms.cast_signed()),
            )
            .filter(edge_invites::Column::InviteId.eq(invite_id.to_vec()))
            .filter(edge_invites::Column::Status.eq(InviteStatus::Pending.as_str()))
            .exec(&txn)
            .await?;
        if updated.rows_affected != 1 {
            txn.rollback().await?;
            return Ok(false);
        }

        let edge = edges::ActiveModel {
            edge_node_id: ActiveValue::Set(edge_node_id.to_vec()),
            name: ActiveValue::Set(name.to_string()),
            registered_at_ms: ActiveValue::Set(redeemed_at_ms.cast_signed()),
        };
        edges::Entity::insert(edge)
            .on_conflict(
                OnConflict::column(edges::Column::EdgeNodeId)
                    .update_columns([edges::Column::Name, edges::Column::RegisteredAtMs])
                    .to_owned(),
            )
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok(true)
    }

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

    /// Check if an edge is registered. Used for signature-auth on
    /// `/v1/routes/subscribe`.
    pub async fn edge_is_registered(&self, edge_node_id: &[u8; 32]) -> anyhow::Result<bool> {
        let model = edges::Entity::find_by_id(edge_node_id.to_vec())
            .one(&self.conn)
            .await?;
        Ok(model.is_some())
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
    conn: &DatabaseConnectionAlias,
    invite_id: &[u8; INVITE_ID_LEN],
) -> anyhow::Result<Vec<String>> {
    let rows = invite_hostnames::Entity::find()
        .filter(invite_hostnames::Column::InviteId.eq(invite_id.to_vec()))
        .all(conn)
        .await?;
    Ok(rows.into_iter().map(|r| r.hostname).collect())
}

type DatabaseConnectionAlias = sea_orm::DatabaseConnection;

fn model_to_invite_row(model: invites::Model, hostnames: Vec<String>) -> anyhow::Result<InviteRow> {
    Ok(InviteRow {
        invite_id: bytes_to_array(model.invite_id, "invite_id")?,
        name: model.name,
        hostnames,
        secret_hash: bytes_to_array(model.secret_hash, "secret_hash")?,
        expires_at_ms: model.expires_at_ms.cast_unsigned(),
        status: InviteStatus::parse(&model.status)?,
        tenant_id: model
            .tenant_id
            .map(|b| bytes_to_array::<32>(b, "tenant_id").map(|a| TenantId::from_bytes(&a)))
            .transpose()?,
        redeemed_at_ms: model.redeemed_at_ms.map(i64::cast_unsigned),
        created_at_ms: model.created_at_ms.cast_unsigned(),
    })
}

fn model_to_edge_invite_row(model: edge_invites::Model) -> anyhow::Result<EdgeInviteRow> {
    Ok(EdgeInviteRow {
        invite_id: bytes_to_array(model.invite_id, "invite_id")?,
        name: model.name,
        secret_hash: bytes_to_array(model.secret_hash, "secret_hash")?,
        expires_at_ms: model.expires_at_ms.cast_unsigned(),
        status: InviteStatus::parse(&model.status)?,
        edge_node_id: model
            .edge_node_id
            .map(|b| bytes_to_array::<32>(b, "edge_node_id"))
            .transpose()?,
        redeemed_at_ms: model.redeemed_at_ms.map(i64::cast_unsigned),
        created_at_ms: model.created_at_ms.cast_unsigned(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::temp_db;
    use super::*;
    use turbo_common::identity::TenantKeypair;
    use turbo_common::invite::hash_invite_secret;

    fn make_pending<'a>(
        id_byte: u8,
        name: &'a str,
        hostnames: &'a [String],
        secret: [u8; 32],
        expires_at_ms: u64,
    ) -> PendingInvite<'a> {
        PendingInvite {
            invite_id: [id_byte; INVITE_ID_LEN],
            name,
            hostnames,
            secret_hash: hash_invite_secret(&secret),
            expires_at_ms,
            created_at_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn invite_insert_and_get() {
        let db = temp_db().await;
        let hostnames = vec!["app.alice.example.eu".to_string()];
        let pending = make_pending(1, "alice", &hostnames, [0x42; 32], 2_000_000_000_000);

        db.insert_invite(&pending).await.unwrap();

        let row = db.get_invite(&pending.invite_id).await.unwrap().unwrap();
        assert_eq!(row.invite_id, pending.invite_id);
        assert_eq!(row.name, "alice");
        assert_eq!(row.hostnames, hostnames);
        assert_eq!(row.secret_hash, pending.secret_hash);
        assert_eq!(row.status, InviteStatus::Pending);
        assert_eq!(row.expires_at_ms, 2_000_000_000_000);
        assert!(row.tenant_id.is_none());
        assert!(row.redeemed_at_ms.is_none());
    }

    #[tokio::test]
    async fn invite_duplicate_id_rejected() {
        let db = temp_db().await;
        let hostnames = vec!["app.example.eu".to_string()];
        let pending = make_pending(7, "a", &hostnames, [1; 32], 2_000_000_000_000);

        db.insert_invite(&pending).await.unwrap();

        let dup = make_pending(7, "b", &hostnames, [2; 32], 2_000_000_000_000);
        assert!(db.insert_invite(&dup).await.is_err());
    }

    #[tokio::test]
    async fn invite_get_missing_returns_none() {
        let db = temp_db().await;
        assert!(db.get_invite(&[99; INVITE_ID_LEN]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invite_list_returns_all() {
        let db = temp_db().await;
        let hs = vec!["a.example.eu".to_string()];

        for id in [1, 2, 3] {
            let pending = make_pending(id, "t", &hs, [id; 32], 2_000_000_000_000);
            db.insert_invite(&pending).await.unwrap();
        }

        let rows = db.list_invites().await.unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn invite_redeem_happy_path() {
        let db = temp_db().await;
        let hostnames = vec!["app.alice.example.eu".to_string()];
        let pending = make_pending(3, "alice", &hostnames, [5; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        let tenant = TenantKeypair::generate();
        let ok = db
            .redeem_invite(
                &pending.invite_id,
                &tenant.id(),
                tenant.public_key(),
                1_700_001_000_000,
            )
            .await
            .unwrap();
        assert!(ok);

        let row = db.get_invite(&pending.invite_id).await.unwrap().unwrap();
        assert_eq!(row.status, InviteStatus::Redeemed);
        assert_eq!(row.tenant_id, Some(tenant.id()));
        assert_eq!(row.redeemed_at_ms, Some(1_700_001_000_000));
    }

    #[tokio::test]
    async fn invite_redeem_already_redeemed_returns_false() {
        let db = temp_db().await;
        let hs = vec!["h.example.eu".to_string()];
        let pending = make_pending(4, "t", &hs, [6; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        let t1 = TenantKeypair::generate();
        let t2 = TenantKeypair::generate();
        assert!(
            db.redeem_invite(&pending.invite_id, &t1.id(), t1.public_key(), 1)
                .await
                .unwrap()
        );
        assert!(
            !db.redeem_invite(&pending.invite_id, &t2.id(), t2.public_key(), 2)
                .await
                .unwrap()
        );

        let row = db.get_invite(&pending.invite_id).await.unwrap().unwrap();
        assert_eq!(row.tenant_id, Some(t1.id()));
    }

    #[tokio::test]
    async fn invite_redeem_revoked_returns_false() {
        let db = temp_db().await;
        let hs = vec!["h.example.eu".to_string()];
        let pending = make_pending(5, "t", &hs, [7; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        assert!(db.revoke_invite(&pending.invite_id).await.unwrap());

        let tenant = TenantKeypair::generate();
        assert!(
            !db.redeem_invite(&pending.invite_id, &tenant.id(), tenant.public_key(), 1)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn invite_redeem_missing_returns_false() {
        let db = temp_db().await;
        let tenant = TenantKeypair::generate();
        assert!(
            !db.redeem_invite(&[0xff; INVITE_ID_LEN], &tenant.id(), tenant.public_key(), 1,)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn invite_revoke_happy_path() {
        let db = temp_db().await;
        let hs = vec!["h.example.eu".to_string()];
        let pending = make_pending(8, "t", &hs, [8; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        assert!(db.revoke_invite(&pending.invite_id).await.unwrap());
        let row = db.get_invite(&pending.invite_id).await.unwrap().unwrap();
        assert_eq!(row.status, InviteStatus::Revoked);

        assert!(!db.revoke_invite(&pending.invite_id).await.unwrap());
    }

    #[tokio::test]
    async fn invite_revoke_redeemed_returns_false() {
        let db = temp_db().await;
        let hs = vec!["h.example.eu".to_string()];
        let pending = make_pending(9, "t", &hs, [9; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        let tenant = TenantKeypair::generate();
        assert!(
            db.redeem_invite(&pending.invite_id, &tenant.id(), tenant.public_key(), 1)
                .await
                .unwrap()
        );

        assert!(!db.revoke_invite(&pending.invite_id).await.unwrap());
    }

    #[tokio::test]
    async fn any_pending_invite_claims_matches_case_insensitively() {
        let db = temp_db().await;

        let hs = vec!["App.Alice.Example.EU".to_string()];
        let pending = make_pending(20, "alice", &hs, [20; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        let got = db
            .any_pending_invite_claims(&["app.alice.example.eu".to_string()])
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("app.alice.example.eu"));

        let got = db
            .any_pending_invite_claims(&["other.example.eu".to_string()])
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn any_pending_invite_claims_ignores_redeemed_and_revoked() {
        let db = temp_db().await;

        let hs = vec!["held.example.eu".to_string()];
        let inv = make_pending(21, "t", &hs, [21; 32], 2_000_000_000_000);
        db.insert_invite(&inv).await.unwrap();

        let tenant = TenantKeypair::generate();
        db.redeem_invite(&inv.invite_id, &tenant.id(), tenant.public_key(), 1)
            .await
            .unwrap();

        let got = db
            .any_pending_invite_claims(&["held.example.eu".to_string()])
            .await
            .unwrap();
        assert!(got.is_none());

        let hs2 = vec!["revoked.example.eu".to_string()];
        let inv2 = make_pending(22, "t2", &hs2, [22; 32], 2_000_000_000_000);
        db.insert_invite(&inv2).await.unwrap();
        db.revoke_invite(&inv2.invite_id).await.unwrap();
        let got = db
            .any_pending_invite_claims(&["revoked.example.eu".to_string()])
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
    async fn invite_list_redeemed_tenants_returns_only_redeemed() {
        let db = temp_db().await;

        let hs_alice = vec!["app.alice.example.eu".to_string()];
        let hs_bob = vec!["app.bob.example.eu".to_string()];
        let hs_pending = vec!["app.charlie.example.eu".to_string()];

        let a = make_pending(10, "alice", &hs_alice, [10; 32], 2_000_000_000_000);
        let b = make_pending(11, "bob", &hs_bob, [11; 32], 2_000_000_000_000);
        let c = make_pending(12, "charlie", &hs_pending, [12; 32], 2_000_000_000_000);
        db.insert_invite(&a).await.unwrap();
        db.insert_invite(&b).await.unwrap();
        db.insert_invite(&c).await.unwrap();

        let t_alice = TenantKeypair::generate();
        let t_bob = TenantKeypair::generate();
        db.redeem_invite(&a.invite_id, &t_alice.id(), t_alice.public_key(), 1)
            .await
            .unwrap();
        db.redeem_invite(&b.invite_id, &t_bob.id(), t_bob.public_key(), 2)
            .await
            .unwrap();

        let tenants = db.list_redeemed_tenants().await.unwrap();
        assert_eq!(tenants.len(), 2);
        let by_id: std::collections::HashMap<_, _> = tenants
            .into_iter()
            .map(|t| (t.tenant_id, (t.hostnames, t.pq_public_key)))
            .collect();
        assert_eq!(
            by_id.get(&t_alice.id()),
            Some(&(hs_alice, t_alice.public_key().clone()))
        );
        assert_eq!(
            by_id.get(&t_bob.id()),
            Some(&(hs_bob, t_bob.public_key().clone()))
        );
    }
}
