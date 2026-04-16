use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, info, warn};

use super::tls::CertStore;

pub type ChallengeTokens = Arc<RwLock<HashMap<String, String>>>;

const FAILURE_COOLDOWN: Duration = Duration::from_secs(300);

const ISSUANCE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AcmeCoordinator {
    account: Account,
    cert_store: CertStore,
    tokens: ChallengeTokens,
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    failures: Mutex<HashMap<String, Instant>>,
}

impl AcmeCoordinator {
    pub async fn new(
        cert_store: CertStore,
        tokens: ChallengeTokens,
        acme_email: String,
        staging: bool,
    ) -> anyhow::Result<Self> {
        let directory_url = if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let builder = Account::builder()?;
        let (account, _creds) = builder
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{acme_email}")],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                None,
            )
            .await?;
        info!(staging, "ACME account ready (on-demand mode)");

        Ok(Self {
            account,
            cert_store,
            tokens,
            inflight: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        })
    }

    pub async fn ensure_cert(&self, hostname: &str) -> anyhow::Result<()> {
        if self.cert_store.has_cert(hostname).await {
            return Ok(());
        }

        if let Some(ts) = self.failures.lock().await.get(hostname).copied()
            && ts.elapsed() < FAILURE_COOLDOWN
        {
            anyhow::bail!(
                "recent ACME failure for {hostname} (cooldown {}s remaining)",
                (FAILURE_COOLDOWN - ts.elapsed()).as_secs()
            );
        }

        let (notify, follower_wait) = {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(hostname) {
                Some(existing) => {
                    let notify = Arc::clone(existing);
                    (Some(notify), true)
                }
                None => {
                    let n = Arc::new(Notify::new());
                    inflight.insert(hostname.to_string(), Arc::clone(&n));
                    (Some(n), false)
                }
            }
        };

        if follower_wait {
            let notify = notify.expect("follower path always has a notify");
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cert_store.has_cert(hostname).await {
                return Ok(());
            }
            tokio::time::timeout(ISSUANCE_TIMEOUT, notified).await?;
            return if self.cert_store.has_cert(hostname).await {
                Ok(())
            } else {
                anyhow::bail!("ACME issuance failed for {hostname}")
            };
        }

        let notify = notify.expect("leader path always has a notify");

        let result = tokio::time::timeout(
            ISSUANCE_TIMEOUT,
            provision_cert(&self.account, hostname, &self.cert_store, &self.tokens),
        )
        .await;

        self.inflight.lock().await.remove(hostname);
        notify.notify_waiters();

        match result {
            Ok(Ok(())) => {
                self.cert_store.reload().await;
                self.failures.lock().await.remove(hostname);
                info!(%hostname, "ACME cert issued");
                Ok(())
            }
            Ok(Err(e)) => {
                self.failures
                    .lock()
                    .await
                    .insert(hostname.to_string(), Instant::now());
                warn!(%hostname, error = %e, "ACME issuance failed");
                Err(e)
            }
            Err(_) => {
                self.failures
                    .lock()
                    .await
                    .insert(hostname.to_string(), Instant::now());
                anyhow::bail!("ACME issuance timed out for {hostname}")
            }
        }
    }
}

pub async fn run_http01_server(listen_addr: &str, tokens: ChallengeTokens) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(listen = %listen_addr, "ACME HTTP-01 challenge server listening");

    let app = axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get({
                let tokens = tokens.clone();
                move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let tokens = tokens.clone();
                    async move {
                        let map = tokens.read().await;
                        match map.get(&token) {
                            Some(auth) => (
                                axum::http::StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                auth.clone(),
                            )
                                .into_response(),
                            None => {
                                (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                            }
                        }
                    }
                }
            }),
        )
        .fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                "not found",
            )
        });

    axum::serve(listener, app).await?;
    Ok(())
}

async fn provision_cert(
    account: &Account,
    hostname: &str,
    cert_store: &CertStore,
    tokens: &ChallengeTokens,
) -> anyhow::Result<()> {
    debug!(%hostname, "starting ACME order");
    let identifiers = [Identifier::Dns(hostname.to_string())];
    let order = &NewOrder::new(&identifiers);
    let mut order = account.new_order(order).await?;

    let mut issued_tokens: Vec<String> = Vec::new();
    let result = run_order(&mut order, hostname, cert_store, tokens, &mut issued_tokens).await;

    if !issued_tokens.is_empty() {
        let mut map = tokens.write().await;
        for token in issued_tokens {
            map.remove(&token);
        }
    }
    result
}

async fn run_order(
    order: &mut instant_acme::Order,
    hostname: &str,
    cert_store: &CertStore,
    tokens: &ChallengeTokens,
    issued_tokens: &mut Vec<String>,
) -> anyhow::Result<()> {
    let mut auths = order.authorizations();
    while let Some(result) = auths.next().await {
        let mut auth = result?;
        if auth.status == AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = auth
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no HTTP-01 challenge offered"))?;
        let key_auth = challenge.key_authorization().as_str().to_string();
        let token = challenge.token.clone();
        tokens.write().await.insert(token.clone(), key_auth);
        issued_tokens.push(token);
        challenge.set_ready().await?;
    }

    let retries = instant_acme::RetryPolicy::default();
    order.poll_ready(&retries).await?;
    let private_key_pem = order.finalize().await?;
    let cert_chain = order.poll_certificate(&retries).await?;

    let cert_path = cert_store.cert_dir().join(format!("{hostname}.crt"));
    let key_path = cert_store.cert_dir().join(format!("{hostname}.key"));
    tokio::fs::write(&cert_path, cert_chain.as_bytes()).await?;
    tokio::fs::write(&key_path, private_key_pem.as_bytes()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let key_path_clone = key_path.clone();
        tokio::task::spawn_blocking(move || std::fs::set_permissions(&key_path_clone, perms))
            .await
            .map_err(|e| anyhow::anyhow!("set_permissions join failed: {e}"))??;
    }

    debug!(%hostname, "cert written to disk");
    Ok(())
}
