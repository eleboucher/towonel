use sqlx::Row;
use turbo_common::identity::{PqPublicKey, TenantId};
use turbo_common::invite::INVITE_ID_LEN;

use super::{Db, blob, blob_opt, ms, ms_opt};
use super::{EdgeInviteRow, InviteRow, InviteStatus, PendingEdgeInvite, PendingInvite, RedeemedTenant};

impl Db {
    /// Persist a fresh pending invite. Duplicate invite_ids fail via the
    /// PRIMARY KEY constraint.
    pub async fn insert_invite(&self, invite: &PendingInvite<'_>) -> anyhow::Result<()> {
        let hostnames_json = serde_json::to_string(invite.hostnames)?;
        sqlx::query(
            "INSERT INTO invites \
             (invite_id, name, hostnames_json, secret_hash, expires_at_ms, status, created_at_ms) \
             VALUES ($1, $2, $3, $4, $5, 'pending', $6)",
        )
        .bind(invite.invite_id.as_slice())
        .bind(invite.name)
        .bind(&hostnames_json)
        .bind(invite.secret_hash.as_slice())
        .bind(invite.expires_at_ms as i64)
        .bind(invite.created_at_ms as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<Option<InviteRow>> {
        let row = sqlx::query(
            "SELECT invite_id, name, hostnames_json, secret_hash, expires_at_ms, status, \
                    tenant_id, redeemed_at_ms, created_at_ms \
             FROM invites WHERE invite_id = $1",
        )
        .bind(invite_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_invite).transpose()
    }

    pub async fn list_invites(&self) -> anyhow::Result<Vec<InviteRow>> {
        let rows = sqlx::query(
            "SELECT invite_id, name, hostnames_json, secret_hash, expires_at_ms, status, \
                    tenant_id, redeemed_at_ms, created_at_ms \
             FROM invites ORDER BY created_at_ms DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_invite).collect()
    }

    /// Mark an invite as redeemed, recording the tenant that consumed it
    /// and their ML-DSA-65 public key.
    ///
    /// Returns true on success, false if the invite was already redeemed /
    /// revoked / missing -- callers must treat a `false` return as the
    /// rejection path, not as an error.
    pub async fn redeem_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        tenant_id: &TenantId,
        pq_public_key: &PqPublicKey,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE invites \
             SET status = 'redeemed', tenant_id = $1, tenant_pq_public_key = $2, \
                 redeemed_at_ms = $3 \
             WHERE invite_id = $4 AND status = 'pending'",
        )
        .bind(tenant_id.as_bytes().as_slice())
        .bind(pq_public_key.as_bytes().as_slice())
        .bind(redeemed_at_ms as i64)
        .bind(invite_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn re_redeem_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        tenant_id: &TenantId,
        pq_public_key: &PqPublicKey,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE invites \
             SET tenant_id = $1, tenant_pq_public_key = $2, redeemed_at_ms = $3 \
             WHERE invite_id = $4 AND status = 'redeemed'",
        )
        .bind(tenant_id.as_bytes().as_slice())
        .bind(pq_public_key.as_bytes().as_slice())
        .bind(redeemed_at_ms as i64)
        .bind(invite_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_invite(&self, invite_id: &[u8; INVITE_ID_LEN]) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE invites SET status = 'revoked' \
             WHERE invite_id = $1 AND status = 'pending'",
        )
        .bind(invite_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Return the first hostname in `candidates_lower` that is already
    /// claimed by a pending invite, or `None`. Must be called under the
    /// AppState invite lock (see api.rs) — otherwise two concurrent
    /// create-invite calls can both see "no conflict" and both insert.
    pub async fn any_pending_invite_claims(
        &self,
        candidates_lower: &[String],
    ) -> anyhow::Result<Option<String>> {
        let rows = sqlx::query("SELECT hostnames_json FROM invites WHERE status = 'pending'")
            .fetch_all(&self.pool)
            .await?;
        for row in &rows {
            let json: String = row.get("hostnames_json");
            let stored: Vec<String> = serde_json::from_str(&json)?;
            for pending in stored {
                let pending_lower = pending.to_lowercase();
                if candidates_lower.contains(&pending_lower) {
                    return Ok(Some(pending_lower));
                }
            }
        }
        Ok(None)
    }

    /// Record an operator decision to remove a tenant from service.
    /// Idempotent: repeat calls update `removed_at_ms` without erroring.
    pub async fn remove_tenant(
        &self,
        tenant_id: &TenantId,
        removed_at_ms: u64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tenant_removals (tenant_id, removed_at_ms) VALUES ($1, $2) \
             ON CONFLICT(tenant_id) DO UPDATE SET removed_at_ms = excluded.removed_at_ms",
        )
        .bind(tenant_id.as_bytes().as_slice())
        .bind(removed_at_ms as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All currently-removed tenants. Used at hub boot to filter the
    /// allowlist, and by tests.
    pub async fn list_tenant_removals(&self) -> anyhow::Result<Vec<TenantId>> {
        let rows = sqlx::query("SELECT tenant_id FROM tenant_removals")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let bytes: Vec<u8> = row.get("tenant_id");
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("removed tenant_id is not 32 bytes"))?;
                Ok(TenantId::from_bytes(&arr))
            })
            .collect()
    }

    /// Redeemed invites are the source of truth for dynamic tenants. The
    /// hub calls this at boot to populate the in-memory `OwnershipPolicy`
    /// so restart survives without a separate tenants table.
    pub async fn list_redeemed_tenants(&self) -> anyhow::Result<Vec<RedeemedTenant>> {
        let rows = sqlx::query(
            "SELECT tenant_id, hostnames_json, tenant_pq_public_key FROM invites \
             WHERE status = 'redeemed' AND tenant_id IS NOT NULL \
                                      AND tenant_pq_public_key IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let tenant_bytes: Vec<u8> = row.get("tenant_id");
                let hostnames_json: String = row.get("hostnames_json");
                let pq_bytes: Vec<u8> = row.get("tenant_pq_public_key");

                let tenant_arr: [u8; 32] = tenant_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("redeemed tenant_id is not 32 bytes"))?;
                let tenant_id = TenantId::from_bytes(&tenant_arr);
                let hostnames: Vec<String> = serde_json::from_str(&hostnames_json)?;
                let pq_public_key = PqPublicKey::from_slice(&pq_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid redeemed pq_public_key: {e}"))?;
                Ok(RedeemedTenant {
                    tenant_id,
                    hostnames,
                    pq_public_key,
                })
            })
            .collect()
    }

    pub async fn insert_edge_invite(&self, invite: &PendingEdgeInvite<'_>) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO edge_invites \
             (invite_id, name, secret_hash, expires_at_ms, status, created_at_ms) \
             VALUES ($1, $2, $3, $4, 'pending', $5)",
        )
        .bind(invite.invite_id.as_slice())
        .bind(invite.name)
        .bind(invite.secret_hash.as_slice())
        .bind(invite.expires_at_ms as i64)
        .bind(invite.created_at_ms as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<Option<EdgeInviteRow>> {
        let row = sqlx::query(
            "SELECT invite_id, name, secret_hash, expires_at_ms, status, \
                    edge_node_id, redeemed_at_ms, created_at_ms \
             FROM edge_invites WHERE invite_id = $1",
        )
        .bind(invite_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_edge_invite).transpose()
    }

    pub async fn list_edge_invites(&self) -> anyhow::Result<Vec<EdgeInviteRow>> {
        let rows = sqlx::query(
            "SELECT invite_id, name, secret_hash, expires_at_ms, status, \
                    edge_node_id, redeemed_at_ms, created_at_ms \
             FROM edge_invites ORDER BY created_at_ms DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_edge_invite).collect()
    }

    /// Atomically flip a pending edge invite to `redeemed` and register the
    /// edge's iroh node_id. Both rows land in the same implicit transaction
    /// — either both succeed or neither. Returns false if the invite was not
    /// pending (already redeemed, revoked, or missing).
    pub async fn redeem_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
        edge_node_id: &[u8; 32],
        name: &str,
        redeemed_at_ms: u64,
    ) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE edge_invites \
             SET status = 'redeemed', edge_node_id = $1, redeemed_at_ms = $2 \
             WHERE invite_id = $3 AND status = 'pending'",
        )
        .bind(edge_node_id.as_slice())
        .bind(redeemed_at_ms as i64)
        .bind(invite_id.as_slice())
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO edges (edge_node_id, name, registered_at_ms) VALUES ($1, $2, $3) \
             ON CONFLICT(edge_node_id) DO UPDATE \
                 SET name = excluded.name, registered_at_ms = excluded.registered_at_ms",
        )
        .bind(edge_node_id.as_slice())
        .bind(name)
        .bind(redeemed_at_ms as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn revoke_edge_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE edge_invites SET status = 'revoked' \
             WHERE invite_id = $1 AND status = 'pending'",
        )
        .bind(invite_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Check if an edge is registered. Used for signature-auth on
    /// `/v1/routes/subscribe`.
    pub async fn edge_is_registered(&self, edge_node_id: &[u8; 32]) -> anyhow::Result<bool> {
        let row = sqlx::query("SELECT 1 AS present FROM edges WHERE edge_node_id = $1 LIMIT 1")
            .bind(edge_node_id.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}

fn row_to_invite(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<InviteRow> {
    let hostnames_json: String = row.get("hostnames_json");
    Ok(InviteRow {
        invite_id: blob(row, "invite_id")?,
        name: row.get("name"),
        hostnames: serde_json::from_str(&hostnames_json)?,
        secret_hash: blob(row, "secret_hash")?,
        expires_at_ms: ms(row, "expires_at_ms"),
        status: InviteStatus::parse(row.get("status"))?,
        tenant_id: blob_opt::<32>(row, "tenant_id")?.map(|b| TenantId::from_bytes(&b)),
        redeemed_at_ms: ms_opt(row, "redeemed_at_ms")?,
        created_at_ms: ms(row, "created_at_ms"),
    })
}

fn row_to_edge_invite(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<EdgeInviteRow> {
    Ok(EdgeInviteRow {
        invite_id: blob(row, "invite_id")?,
        name: row.get("name"),
        secret_hash: blob(row, "secret_hash")?,
        expires_at_ms: ms(row, "expires_at_ms"),
        status: InviteStatus::parse(row.get("status"))?,
        edge_node_id: blob_opt(row, "edge_node_id")?,
        redeemed_at_ms: ms_opt(row, "redeemed_at_ms")?,
        created_at_ms: ms(row, "created_at_ms"),
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

        // Same invite_id with different payload -- PRIMARY KEY violation.
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

        // tenant_id must still point at the first redeemer, not the second.
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

        // Revoking twice must be a no-op returning false.
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

        // Redeemed invites cannot be revoked -- the tenant is already registered.
        assert!(!db.revoke_invite(&pending.invite_id).await.unwrap());
    }

    #[tokio::test]
    async fn any_pending_invite_claims_matches_case_insensitively() {
        let db = temp_db().await;

        let hs = vec!["App.Alice.Example.EU".to_string()];
        let pending = make_pending(20, "alice", &hs, [20; 32], 2_000_000_000_000);
        db.insert_invite(&pending).await.unwrap();

        // Lookup with a lowercased candidate must match the mixed-case stored row.
        let got = db
            .any_pending_invite_claims(&["app.alice.example.eu".to_string()])
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("app.alice.example.eu"));

        // Non-overlapping: returns None.
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

        // A redeemed invite should NOT show up here -- redeemed invites are
        // covered by the in-memory policy, not by this DB scan.
        let tenant = TenantKeypair::generate();
        db.redeem_invite(&inv.invite_id, &tenant.id(), tenant.public_key(), 1)
            .await
            .unwrap();

        let got = db
            .any_pending_invite_claims(&["held.example.eu".to_string()])
            .await
            .unwrap();
        assert!(got.is_none());

        // Revoked invites also don't count.
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

        // Repeat calls must not error (ON CONFLICT update).
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
        // c is left pending.

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
