use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use backon::{ExponentialBuilder, Retryable};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder,
};
use normpath::PathExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, OnceCell, RwLock};
use tracing::{debug, info, warn};

use super::tls::CertStore;

pub type ChallengeTokens = Arc<RwLock<HashMap<String, String>>>;

const FAILURE_COOLDOWN: Duration = Duration::from_mins(5);

/// Time budget for a single ACME order attempt. Three retry attempts with
/// exponential backoff and jitter can cap total wall time at roughly
/// `ATTEMPTS × ATTEMPT_TIMEOUT + cumulative backoff`.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: usize = 3;

/// Total wait the follower allows while the leader retries. Must be bigger
/// than `MAX_ATTEMPTS × ATTEMPT_TIMEOUT` plus backoff, or followers give up
/// before the leader can declare success.
const ISSUANCE_TIMEOUT: Duration = Duration::from_mins(3);

pub struct AcmeCoordinator {
    account: OnceCell<Account>,
    account_path: PathBuf,
    directory_url: String,
    acme_email: String,
    cert_store: CertStore,
    tokens: ChallengeTokens,
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    failures: Mutex<HashMap<String, Instant>>,
}

impl AcmeCoordinator {
    pub fn new(
        cert_store: CertStore,
        tokens: ChallengeTokens,
        acme_email: String,
        staging: bool,
    ) -> Self {
        let directory_url = if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };
        let account_path = cert_store.cert_dir().join("account.json");
        info!(
            staging,
            account_path = %account_path.display(),
            "ACME coordinator ready (lazy account; will register on first cert request)"
        );

        Self {
            account: OnceCell::new(),
            account_path,
            directory_url: directory_url.to_string(),
            acme_email,
            cert_store,
            tokens,
            inflight: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Lazily load (or create + persist) the LE account on first use.
    async fn account(&self) -> anyhow::Result<&Account> {
        self.account
            .get_or_try_init(|| async { self.load_or_create_account().await })
            .await
    }

    async fn load_or_create_account(&self) -> anyhow::Result<Account> {
        if let Ok(bytes) = tokio::fs::read(&self.account_path).await {
            let creds: AccountCredentials = serde_json::from_slice(&bytes)?;
            let account = Account::builder()?.from_credentials(creds).await?;
            info!(account_path = %self.account_path.display(), "ACME account loaded from disk");
            return Ok(account);
        }

        let (account, creds) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.acme_email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await?;

        let json = serde_json::to_vec(&creds)?;
        tokio::fs::write(&self.account_path, json).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = self.account_path.clone();
            tokio::task::spawn_blocking(move || {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            })
            .await
            .map_err(|e| anyhow::anyhow!("set_permissions join failed: {e}"))??;
        }
        info!(account_path = %self.account_path.display(), "ACME account registered and persisted");
        Ok(account)
    }

    pub async fn ensure_cert(&self, hostname: &str) -> anyhow::Result<()> {
        if self.cert_store.has_cert(hostname) {
            return Ok(());
        }

        if let Some(ts) = self.failures.lock().await.get(hostname).copied()
            && ts.elapsed() < FAILURE_COOLDOWN
        {
            // checked_sub is infallible here: ts.elapsed() < FAILURE_COOLDOWN
            #[allow(clippy::unwrap_used)]
            let remaining_secs = FAILURE_COOLDOWN
                .checked_sub(ts.elapsed())
                .unwrap()
                .as_secs();
            anyhow::bail!(
                "recent ACME failure for {hostname} (cooldown {remaining_secs}s remaining)",
            );
        }

        let (notify, follower_wait) = {
            let mut inflight = self.inflight.lock().await;
            // map_or_else cannot be used here: the closure would need to mutate inflight,
            // which conflicts with the immutable borrow from get(). Keep if-let.
            #[allow(clippy::option_if_let_else)]
            if let Some(existing) = inflight.get(hostname) {
                let notify = Arc::clone(existing);
                drop(inflight);
                (notify, true)
            } else {
                let n = Arc::new(Notify::new());
                inflight.insert(hostname.to_string(), Arc::clone(&n));
                drop(inflight);
                (n, false)
            }
        };

        if follower_wait {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cert_store.has_cert(hostname) {
                return Ok(());
            }
            tokio::time::timeout(ISSUANCE_TIMEOUT, notified).await?;
            return if self.cert_store.has_cert(hostname) {
                Ok(())
            } else {
                anyhow::bail!("ACME issuance failed for {hostname}")
            };
        }

        let result = match self.account().await {
            Ok(account) => {
                issue_with_retry(account, hostname, &self.cert_store, &self.tokens).await
            }
            Err(e) => Err(e),
        };

        // Reload the cert store before notify_waiters() so followers see has_cert() == true.
        let outcome = match result {
            Ok(()) => {
                self.cert_store.reload().await;
                self.failures.lock().await.remove(hostname);
                info!(%hostname, "ACME cert issued");
                Ok(())
            }
            Err(e) => {
                self.failures
                    .lock()
                    .await
                    .insert(hostname.to_string(), Instant::now());
                warn!(%hostname, error = %e, "ACME issuance failed after retries");
                Err(e)
            }
        };

        self.inflight.lock().await.remove(hostname);
        notify.notify_waiters();

        outcome
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
                        let auth = tokens.read().await.get(&token).cloned();
                        // map_or_else would not be cleaner here due to the tuple construction.
                        #[allow(clippy::option_if_let_else)]
                        if let Some(auth) = auth {
                            (
                                axum::http::StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                                auth,
                            )
                                .into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
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

/// Drive `provision_cert` with exponential backoff + jitter. A single
/// attempt is capped at [`ATTEMPT_TIMEOUT`]; the whole loop gives up after
/// [`MAX_ATTEMPTS`] transient failures.
async fn issue_with_retry(
    account: &Account,
    hostname: &str,
    cert_store: &CertStore,
    tokens: &ChallengeTokens,
) -> anyhow::Result<()> {
    let policy = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(2))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(MAX_ATTEMPTS - 1) // total attempts = initial + retries
        .with_jitter();

    (|| async {
        tokio::time::timeout(
            ATTEMPT_TIMEOUT,
            provision_cert(account, hostname, cert_store, tokens),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("ACME attempt timed out for {hostname}")))
    })
    .retry(policy)
    .notify(|err, dur| {
        warn!(%hostname, error = %err, ?dur, "ACME attempt failed; retrying");
    })
    .await
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

    let cert_path = safe_cert_path(cert_store.cert_dir(), hostname, "crt")?;
    let key_path = safe_cert_path(cert_store.cert_dir(), hostname, "key")?;
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

/// Join `<cert_dir>/<hostname>.<ext>` and verify via `normpath` that the
/// resulting path is still inside `cert_dir`. Rejects hostnames that contain
/// path traversal sequences (e.g. `../`), even though `validate_hostname`
/// already catches these upstream — belt-and-braces at the FS boundary.
fn safe_cert_path(
    cert_dir: &std::path::Path,
    hostname: &str,
    ext: &str,
) -> anyhow::Result<PathBuf> {
    let base = cert_dir.normalize()?;
    let candidate = base.as_path().join(format!("{hostname}.{ext}"));
    let normalized = candidate.normalize()?;
    if !normalized.as_path().starts_with(base.as_path()) {
        anyhow::bail!("refusing to write cert outside cert_dir for `{hostname}`");
    }
    Ok(normalized.into_path_buf())
}
