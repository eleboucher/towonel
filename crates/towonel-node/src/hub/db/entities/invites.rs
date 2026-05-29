use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "invites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub invite_id: Vec<u8>,
    pub name: String,
    pub secret_hash: Vec<u8>,
    pub expires_at_ms: Option<i64>,
    pub status: String,
    pub tenant_id: Option<Vec<u8>>,
    pub tenant_pq_public_key: Option<Vec<u8>>,
    pub created_at_ms: i64,
    #[sea_orm(column_type = "Json")]
    pub hostnames: Json,
    /// Region this invite's agents belong to. `None` resolves to `EU`.
    pub region: Option<String>,
    /// Extra regions whose edges the agent also dials for failover.
    #[sea_orm(column_type = "Json")]
    pub failover_regions: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn hostnames_vec(&self) -> Vec<String> {
        if let sea_orm::JsonValue::Array(arr) = &self.hostnames {
            arr.iter()
                .filter_map(|v| {
                    v.as_str().map(String::from).or_else(|| {
                        tracing::warn!(
                            "non-string hostname element in invite {:?}",
                            self.invite_id
                        );
                        None
                    })
                })
                .collect()
        } else {
            tracing::warn!(
                "invite {} has non-array hostnames: {:?}",
                hex::encode(&self.invite_id),
                self.hostnames
            );
            Vec::new()
        }
    }

    pub fn failover_regions_vec(&self) -> Vec<String> {
        if let sea_orm::JsonValue::Array(arr) = &self.failover_regions {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            Vec::new()
        }
    }
}
