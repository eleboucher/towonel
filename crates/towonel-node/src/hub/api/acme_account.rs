use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use serde::Serialize;
use tracing::warn;

use crate::hub::acme::CAA_VALIDATION_METHOD;

use super::{AppState, internal_error, json_ok, not_found};

#[derive(Serialize)]
struct PublicAcmeAccount {
    account_uri: String,
    caa_record: String,
}

pub(super) async fn get_acme_account(State(state): State<Arc<AppState>>) -> Response {
    let Some(tls) = state.tls.as_ref() else {
        return not_found("TLS is not configured on this hub");
    };
    let Some(email) = tls.acme_email.as_deref() else {
        return not_found("TLS is configured without an ACME email");
    };

    match crate::hub::acme::load_account_info(&tls.cert_dir, email, tls.acme_staging).await {
        Ok(Some(info)) => {
            let account_uri = info.account_uri;
            let caa_record = format!(
                "letsencrypt.org;validationmethods={CAA_VALIDATION_METHOD};accounturi={account_uri}"
            );
            json_ok(PublicAcmeAccount {
                account_uri,
                caa_record,
            })
        }
        Ok(None) => not_found("no ACME account is registered yet"),
        Err(e) => {
            warn!(error = %e, "failed to load ACME account info");
            internal_error()
        }
    }
}
