use sea_orm_migration::prelude::*;

mod m20260422_000000_initial;
mod m20260424_000000_federation_push_state;
mod m20260428_000000_invite_v2;
mod m20260428_000001_agent_liveness;
mod m20260428_000002_edge_invite_v2;
mod m20260428_000003_drop_federation_push_state;
mod m20260522_000000_hub_signing_keys;
mod m20260523_000000_user_accounts;
mod m20260523_000001_admin_actions_widen_actor_kind;
mod m20260524_000000_drop_edge_invites;
mod m20260524_000001_port_reservations;
mod m20260601_000000_hub_init_canary;
mod m20260612_000000_user_oauth_identities;
mod m20260613_000000_drop_agent_liveness;
mod m20260615_000000_invite_status_claimed;
mod m20260616_000000_email_verification;
mod m20260616_000001_password_reset_tokens;
mod m20260616_000002_signup_invite_recipient;
mod m20260616_000003_lowercase_emails;
mod m20260616_000004_oauth_one_per_provider;
mod m20260617_000000_app_settings;
mod m20260618_000000_user_2fa;
mod m20260619_000000_user_passkeys;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260422_000000_initial::Migration),
            Box::new(m20260424_000000_federation_push_state::Migration),
            Box::new(m20260428_000000_invite_v2::Migration),
            Box::new(m20260428_000001_agent_liveness::Migration),
            Box::new(m20260428_000002_edge_invite_v2::Migration),
            Box::new(m20260428_000003_drop_federation_push_state::Migration),
            Box::new(m20260522_000000_hub_signing_keys::Migration),
            Box::new(m20260523_000000_user_accounts::Migration),
            Box::new(m20260523_000001_admin_actions_widen_actor_kind::Migration),
            Box::new(m20260524_000000_drop_edge_invites::Migration),
            Box::new(m20260524_000001_port_reservations::Migration),
            Box::new(m20260601_000000_hub_init_canary::Migration),
            Box::new(m20260612_000000_user_oauth_identities::Migration),
            Box::new(m20260613_000000_drop_agent_liveness::Migration),
            Box::new(m20260615_000000_invite_status_claimed::Migration),
            Box::new(m20260616_000000_email_verification::Migration),
            Box::new(m20260616_000001_password_reset_tokens::Migration),
            Box::new(m20260616_000002_signup_invite_recipient::Migration),
            Box::new(m20260616_000003_lowercase_emails::Migration),
            Box::new(m20260616_000004_oauth_one_per_provider::Migration),
            Box::new(m20260617_000000_app_settings::Migration),
            Box::new(m20260618_000000_user_2fa::Migration),
            Box::new(m20260619_000000_user_passkeys::Migration),
        ]
    }
}
