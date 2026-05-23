#![allow(dead_code, reason = "consumed by web routes once mounted")]

use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};

use super::Db;
use super::entities::tenant_ownership;

pub struct NewTenantOwnership<'a> {
    pub user_id: &'a str,
    pub tenant_id: &'a [u8],
    pub invite_id: &'a [u8],
    pub display_name: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct TenantOwnershipRow {
    pub user_id: String,
    pub tenant_id: Vec<u8>,
    pub invite_id: Vec<u8>,
    pub display_name: String,
    pub created_at_ms: i64,
}

impl Db {
    pub async fn insert_tenant_ownership(&self, o: NewTenantOwnership<'_>) -> anyhow::Result<()> {
        let model = tenant_ownership::ActiveModel {
            user_id: ActiveValue::Set(o.user_id.to_string()),
            tenant_id: ActiveValue::Set(o.tenant_id.to_vec()),
            invite_id: ActiveValue::Set(o.invite_id.to_vec()),
            display_name: ActiveValue::Set(o.display_name.to_string()),
            created_at_ms: ActiveValue::Set(o.now_ms),
        };
        tenant_ownership::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_tenant_ownership_by_invite(
        &self,
        user_id: &str,
        invite_id: &[u8],
    ) -> anyhow::Result<Option<TenantOwnershipRow>> {
        let row = tenant_ownership::Entity::find()
            .filter(tenant_ownership::Column::UserId.eq(user_id))
            .filter(tenant_ownership::Column::InviteId.eq(invite_id.to_vec()))
            .one(&self.conn)
            .await?;
        Ok(row.map(into_row))
    }

    pub async fn list_invite_ids_for_user(&self, user_id: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let rows = tenant_ownership::Entity::find()
            .filter(tenant_ownership::Column::UserId.eq(user_id))
            .all(&self.conn)
            .await?;
        Ok(rows.into_iter().map(|r| r.invite_id).collect())
    }

    pub async fn delete_tenant_ownership_by_invite(&self, invite_id: &[u8]) -> anyhow::Result<u64> {
        let result = tenant_ownership::Entity::delete_many()
            .filter(tenant_ownership::Column::InviteId.eq(invite_id.to_vec()))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}

fn into_row(m: tenant_ownership::Model) -> TenantOwnershipRow {
    TenantOwnershipRow {
        user_id: m.user_id,
        tenant_id: m.tenant_id,
        invite_id: m.invite_id,
        display_name: m.display_name,
        created_at_ms: m.created_at_ms,
    }
}
