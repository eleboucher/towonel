use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, Statement,
};
use towonel_common::identity::TenantId;

use super::entities::port_reservations;
use super::{Db, tenant_id_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl PortProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortReservationRow {
    #[expect(
        dead_code,
        reason = "stable row id; surfaced once a row-level API needs it"
    )]
    pub id: [u8; 16],
    pub tenant_id: TenantId,
    pub ip_address: Option<String>,
    pub port: u16,
    pub protocol: PortProtocol,
    pub label: Option<String>,
    pub claimed_at_ms: u64,
}

pub struct NewPortReservation<'a> {
    pub tenant_id: TenantId,
    pub ip_address: Option<&'a str>,
    pub port: u16,
    pub protocol: PortProtocol,
    pub label: Option<&'a str>,
    pub claimed_at_ms: u64,
}

impl Db {
    pub async fn insert_port_reservation(
        &self,
        row: &NewPortReservation<'_>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;

        port_reservations::ActiveModel {
            id: ActiveValue::Set(id.to_vec()),
            tenant_id: ActiveValue::Set(tenant_id_bytes(&row.tenant_id)),
            ip_address: ActiveValue::Set(row.ip_address.map(str::to_string)),
            port: ActiveValue::Set(i32::from(row.port)),
            protocol: ActiveValue::Set(row.protocol.as_str().to_string()),
            label: ActiveValue::Set(row.label.map(str::to_string)),
            claimed_at_ms: ActiveValue::Set(row.claimed_at_ms.cast_signed()),
        }
        .insert(&self.conn)
        .await?;

        Ok(id)
    }

    pub async fn delete_port_reservation(
        &self,
        tenant_id: &TenantId,
        ip_address: Option<&str>,
        port: u16,
        protocol: PortProtocol,
    ) -> anyhow::Result<bool> {
        let mut query = port_reservations::Entity::delete_many()
            .filter(port_reservations::Column::TenantId.eq(tenant_id_bytes(tenant_id)))
            .filter(port_reservations::Column::Port.eq(i32::from(port)))
            .filter(port_reservations::Column::Protocol.eq(protocol.as_str()));
        query = match ip_address {
            Some(ip) => query.filter(port_reservations::Column::IpAddress.eq(ip)),
            None => query.filter(port_reservations::Column::IpAddress.is_null()),
        };
        let result = query.exec(&self.conn).await?;
        Ok(result.rows_affected == 1)
    }

    pub async fn list_port_reservations(
        &self,
        tenant_id: Option<&TenantId>,
    ) -> anyhow::Result<Vec<PortReservationRow>> {
        let mut query =
            port_reservations::Entity::find().order_by_asc(port_reservations::Column::ClaimedAtMs);
        if let Some(t) = tenant_id {
            query = query.filter(port_reservations::Column::TenantId.eq(tenant_id_bytes(t)));
        }
        let rows = query.all(&self.conn).await?;
        rows.into_iter().map(model_to_row).collect()
    }

    /// Sum across every tenant the user owns — quota is global, not per-tenant.
    pub async fn count_port_reservations_for_user(&self, user_id: &str) -> anyhow::Result<i64> {
        let backend = self.conn.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            r"
            SELECT COUNT(*) AS n
              FROM port_reservations pr
              JOIN tenant_ownership t ON t.tenant_id = pr.tenant_id
             WHERE t.user_id = $1
            ",
            [user_id.into()],
        );
        let row = self
            .conn
            .query_one(stmt)
            .await?
            .ok_or_else(|| anyhow::anyhow!("COUNT(*) returned no row"))?;
        Ok(row.try_get::<i64>("", "n")?)
    }

    pub async fn tenant_owns_port(
        &self,
        tenant_id: &TenantId,
        port: u16,
        protocol: PortProtocol,
    ) -> anyhow::Result<bool> {
        let hit = port_reservations::Entity::find()
            .filter(port_reservations::Column::TenantId.eq(tenant_id_bytes(tenant_id)))
            .filter(port_reservations::Column::Port.eq(i32::from(port)))
            .filter(port_reservations::Column::Protocol.eq(protocol.as_str()))
            .one(&self.conn)
            .await?;
        Ok(hit.is_some())
    }

    pub async fn find_port_reservations(
        &self,
        tenant_id: &TenantId,
        port: u16,
        protocol: PortProtocol,
    ) -> anyhow::Result<Vec<PortReservationRow>> {
        let rows = port_reservations::Entity::find()
            .filter(port_reservations::Column::TenantId.eq(tenant_id_bytes(tenant_id)))
            .filter(port_reservations::Column::Port.eq(i32::from(port)))
            .filter(port_reservations::Column::Protocol.eq(protocol.as_str()))
            .all(&self.conn)
            .await?;
        rows.into_iter().map(model_to_row).collect()
    }
}

fn model_to_row(model: port_reservations::Model) -> anyhow::Result<PortReservationRow> {
    let id: [u8; 16] = model
        .id
        .try_into()
        .map_err(|_| anyhow::anyhow!("port_reservations.id in DB is not 16 bytes"))?;
    let tenant_arr: [u8; 32] = model
        .tenant_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("port_reservations.tenant_id in DB is not 32 bytes"))?;
    let port = u16::try_from(model.port)
        .map_err(|_| anyhow::anyhow!("port_reservations.port out of u16 range"))?;
    let protocol = PortProtocol::parse(&model.protocol)
        .ok_or_else(|| anyhow::anyhow!("unknown protocol in DB: {}", model.protocol))?;
    Ok(PortReservationRow {
        id,
        tenant_id: TenantId::from_bytes(&tenant_arr),
        ip_address: model.ip_address,
        port,
        protocol,
        label: model.label,
        claimed_at_ms: model.claimed_at_ms.cast_unsigned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::db::temp_db;
    use towonel_common::identity::TenantKeypair;

    fn tenant() -> TenantId {
        TenantKeypair::generate().id()
    }

    #[tokio::test]
    async fn insert_and_list_shared_ip() {
        let db = temp_db().await;
        let t = tenant();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t,
            ip_address: None,
            port: 22000,
            protocol: PortProtocol::Tcp,
            label: Some("ssh"),
            claimed_at_ms: 1_700_000_000,
        })
        .await
        .unwrap();

        let rows = db.list_port_reservations(Some(&t)).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].port, 22000);
        assert_eq!(rows[0].protocol, PortProtocol::Tcp);
        assert_eq!(rows[0].ip_address, None);
        assert_eq!(rows[0].label.as_deref(), Some("ssh"));
    }

    #[tokio::test]
    async fn duplicate_shared_slot_rejected() {
        let db = temp_db().await;
        let t1 = tenant();
        let t2 = tenant();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t1,
            ip_address: None,
            port: 22000,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();

        let err = db
            .insert_port_reservation(&NewPortReservation {
                tenant_id: t2,
                ip_address: None,
                port: 22000,
                protocol: PortProtocol::Tcp,
                label: None,
                claimed_at_ms: 2,
            })
            .await
            .unwrap_err();
        assert!(super::super::is_unique_violation(&err));
    }

    #[tokio::test]
    async fn tcp_and_udp_namespaces_are_separate() {
        let db = temp_db().await;
        let t = tenant();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t,
            ip_address: None,
            port: 53,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t,
            ip_address: None,
            port: 53,
            protocol: PortProtocol::Udp,
            label: None,
            claimed_at_ms: 2,
        })
        .await
        .unwrap();
        assert_eq!(db.list_port_reservations(Some(&t)).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn count_for_user_sums_across_their_tenants() {
        use crate::hub::db::tenant_ownership::NewTenantOwnership;
        use crate::hub::db::users::NewUser;
        let db = temp_db().await;
        // tenant_ownership has FK → users.id.
        for (id, email) in [("alice", "alice@x.test"), ("bob", "bob@x.test")] {
            db.insert_user(NewUser {
                id,
                email,
                password_hash: "x",
                role: "user",
                email_verified_at_ms: Some(1),
                now_ms: 1,
            })
            .await
            .unwrap();
        }
        let t1 = tenant();
        let t2 = tenant();
        let t_other = tenant();
        db.insert_tenant_ownership(NewTenantOwnership {
            user_id: "alice",
            tenant_id: t1.as_bytes(),
            invite_id: &[0u8; 16],
            display_name: "t1",
            now_ms: 1,
        })
        .await
        .unwrap();
        db.insert_tenant_ownership(NewTenantOwnership {
            user_id: "alice",
            tenant_id: t2.as_bytes(),
            invite_id: &[1u8; 16],
            display_name: "t2",
            now_ms: 1,
        })
        .await
        .unwrap();
        db.insert_tenant_ownership(NewTenantOwnership {
            user_id: "bob",
            tenant_id: t_other.as_bytes(),
            invite_id: &[2u8; 16],
            display_name: "t_other",
            now_ms: 1,
        })
        .await
        .unwrap();
        // Two reservations on alice's tenants, one on bob's.
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t1,
            ip_address: None,
            port: 30_000,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t2,
            ip_address: None,
            port: 30_001,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t_other,
            ip_address: None,
            port: 30_002,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();
        assert_eq!(
            db.count_port_reservations_for_user("alice").await.unwrap(),
            2
        );
        assert_eq!(db.count_port_reservations_for_user("bob").await.unwrap(), 1);
        assert_eq!(
            db.count_port_reservations_for_user("nobody").await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn delete_scoped_to_tenant() {
        let db = temp_db().await;
        let t1 = tenant();
        let t2 = tenant();
        db.insert_port_reservation(&NewPortReservation {
            tenant_id: t1,
            ip_address: None,
            port: 22000,
            protocol: PortProtocol::Tcp,
            label: None,
            claimed_at_ms: 1,
        })
        .await
        .unwrap();

        let removed = db
            .delete_port_reservation(&t2, None, 22000, PortProtocol::Tcp)
            .await
            .unwrap();
        assert!(!removed, "other tenant must not be able to release");
        assert_eq!(db.list_port_reservations(None).await.unwrap().len(), 1);

        let removed = db
            .delete_port_reservation(&t1, None, 22000, PortProtocol::Tcp)
            .await
            .unwrap();
        assert!(removed);
        assert_eq!(db.list_port_reservations(None).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn remove_tenant_cascades_to_port_reservations() {
        use super::super::tenant_ownership::NewTenantOwnership;
        use super::super::types::PendingInvite;
        use super::super::users::NewUser;
        use towonel_common::invite::INVITE_ID_LEN;

        let db = temp_db().await;
        let tenant_kp = TenantKeypair::generate();
        let now_ms_i = 1_700_000_000_000i64;
        let now_ms_u = now_ms_i.cast_unsigned();

        db.insert_user(NewUser {
            id: "testuser",
            email: "test@example.com",
            password_hash: "x",
            role: "user",
            email_verified_at_ms: Some(now_ms_i),
            now_ms: now_ms_i,
        })
        .await
        .unwrap();

        let invite = PendingInvite {
            invite_id: [42u8; INVITE_ID_LEN],
            name: "test",
            secret_hash: [1u8; 32],
            expires_at_ms: None,
            tenant_id: tenant_kp.id(),
            pq_public_key: tenant_kp.public_key(),
            created_at_ms: now_ms_u,
            hostnames: &[],
            region: None,
            failover_regions: &[],
        };
        db.insert_invite(&invite).await.unwrap();

        db.insert_tenant_ownership(NewTenantOwnership {
            user_id: "testuser",
            tenant_id: tenant_kp.id().as_bytes(),
            invite_id: &[42u8; INVITE_ID_LEN],
            display_name: "test",
            now_ms: now_ms_i,
        })
        .await
        .unwrap();

        db.insert_port_reservation(&NewPortReservation {
            tenant_id: tenant_kp.id(),
            ip_address: None,
            port: 22000,
            protocol: PortProtocol::Tcp,
            label: Some("ssh"),
            claimed_at_ms: now_ms_u,
        })
        .await
        .unwrap();

        assert_eq!(db.list_port_reservations(None).await.unwrap().len(), 1);

        db.remove_tenant(&tenant_kp.id(), now_ms_u).await.unwrap();

        assert_eq!(
            db.list_port_reservations(None).await.unwrap().len(),
            0,
            "port reservations should cascade-delete when tenant is removed"
        );
    }
}
