use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "federated_tenant_hostnames")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub hostname_lower: String,
    pub hostname: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::federated_tenants::Entity",
        from = "Column::TenantId",
        to = "super::federated_tenants::Column::TenantId",
        on_delete = "Cascade"
    )]
    Tenant,
}

impl Related<super::federated_tenants::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Tenant.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
