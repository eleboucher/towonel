use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

/// One OIDC identity per (`user_id`, provider). Fails if existing
/// duplicates would violate it; operator picks which to keep.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        if matches!(backend, DatabaseBackend::MySql) {
            return Err(DbErr::Migration(
                "MySQL backend is not supported".to_string(),
            ));
        }

        let dups = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT user_id, provider, COUNT(*) AS c \
                 FROM user_oauth_identities \
                 GROUP BY user_id, provider \
                 HAVING COUNT(*) > 1"
                    .to_string(),
            ))
            .await?;
        if !dups.is_empty() {
            return Err(DbErr::Migration(format!(
                "user_oauth_identities has {} (user_id, provider) duplicate group(s); \
                 resolve manually before this migration can run",
                dups.len(),
            )));
        }

        manager
            .create_index(
                Index::create()
                    .name("uniq_user_oauth_identities_user_provider")
                    .table(UserOauthIdentities::Table)
                    .col(UserOauthIdentities::UserId)
                    .col(UserOauthIdentities::Provider)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("uniq_user_oauth_identities_user_provider")
                    .table(UserOauthIdentities::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum UserOauthIdentities {
    Table,
    Provider,
    UserId,
}
