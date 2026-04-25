use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::response::IntoResponse;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Error as AcmeError,
    Identifier, LetsEncrypt, NewAccount, NewOrder, Problem,
};
use normpath::PathExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, OnceCell};
use tracing::{debug, info, warn};

use super::tls::CertStore;

/// Lock-free map of in-flight HTTP-01 challenge tokens → key authorizations.
/// Short-lived: entries are inserted before `challenge.set_ready()` and
/// removed once the order either succeeds or fails.
pub type ChallengeTokens = Arc<papaya::HashMap<String, String>>;

const FAILURE_COOLDOWN: Duration = Duration::from_mins(15);

/// LE rate-limit windows run 1h–168h; 24h covers most without back-to-back hits.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_hours(24);

/// Single attempt only — each retry runs `new_order` + `finalize` and a network
/// blip after `finalize` succeeds server-side would issue a duplicate cert
/// against LE's weekly per-identifier quota.
const ATTEMPT_TIMEOUT: Duration = Duration::from_mins(2);

/// Must exceed [`ATTEMPT_TIMEOUT`] so followers do not give up before the leader.
const ISSUANCE_TIMEOUT: Duration = Duration::from_mins(3);

pub struct AcmeCoordinator {
    account: OnceCell<Account>,
    account_path: PathBuf,
    directory_url: String,
    acme_email: String,
    cert_store: CertStore,
    tokens: ChallengeTokens,
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    /// Hostname → unix-second deadline before which a new attempt is denied.
    /// Mirrored on disk in `<cert_dir>/<hostname>.acme-failure` so cooldowns
    /// survive restarts.
    failures: Mutex<HashMap<String, u64>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FailureRecord {
    retry_after_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
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
        let failures = load_persisted_failures(cert_store.cert_dir());
        info!(
            staging,
            account_path = %account_path.display(),
            persisted_cooldowns = failures.len(),
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
            failures: Mutex::new(failures),
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
        validate_hostname(hostname)?;

        if self.cert_store.has_cert(hostname) {
            return Ok(());
        }

        // `inflight` gates one ensure_cert per hostname, so the cleanup
        // branch below cannot race a concurrent insert.
        let now = unix_now();
        let snapshot = self.failures.lock().await.get(hostname).copied();
        match snapshot {
            Some(retry_after) if now < retry_after => {
                anyhow::bail!(
                    "recent ACME failure for {hostname} (cooldown {}s remaining)",
                    retry_after - now,
                );
            }
            Some(_) => {
                self.failures.lock().await.remove(hostname);
                clear_persisted_failure(self.cert_store.cert_dir(), hostname).await;
            }
            None => {}
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
            Ok(account) => tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                provision_cert(account, hostname, &self.cert_store, &self.tokens),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("ACME attempt timed out for {hostname}"))),
            Err(e) => Err(e),
        };

        // Reload the cert store before notify_waiters() so followers see has_cert() == true.
        let outcome = match result {
            Ok(()) => {
                self.cert_store.reload().await;
                clear_persisted_failure(self.cert_store.cert_dir(), hostname).await;
                self.failures.lock().await.remove(hostname);
                info!(%hostname, "ACME cert issued");
                Ok(())
            }
            Err(e) => {
                let (cooldown, reason) = classify_failure(&e);
                let retry_after = unix_now() + cooldown.as_secs();
                // Persist before the in-memory write: on crash between the two,
                // we'd rather restart with a cooldown set than without one.
                if let Err(persist_err) =
                    persist_failure(self.cert_store.cert_dir(), hostname, retry_after, reason).await
                {
                    warn!(%hostname, error = %persist_err, "failed to persist ACME failure record");
                }
                self.failures
                    .lock()
                    .await
                    .insert(hostname.to_string(), retry_after);
                warn!(
                    %hostname,
                    error = %e,
                    cooldown_secs = cooldown.as_secs(),
                    reason,
                    "ACME issuance failed; cooling down before next attempt"
                );
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
                        let auth = tokens.pin().get(&token).cloned();
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

async fn provision_cert(
    account: &Account,
    hostname: &str,
    cert_store: &CertStore,
    tokens: &ChallengeTokens,
) -> anyhow::Result<()> {
    // Fail before contacting LE: a write error after `finalize()` would
    // issue an LE cert we cannot persist, burning a weekly quota slot.
    ensure_cert_dir_writable(cert_store.cert_dir()).await?;

    debug!(%hostname, "starting ACME order");
    let identifiers = [Identifier::Dns(hostname.to_string())];
    let order = &NewOrder::new(&identifiers);
    let mut order = account.new_order(order).await?;

    let mut issued_tokens: Vec<String> = Vec::new();
    let result = run_order(&mut order, hostname, cert_store, tokens, &mut issued_tokens).await;

    if !issued_tokens.is_empty() {
        let map = tokens.pin();
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
        tokens.pin().insert(token.clone(), key_auth);
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
        let key_path = key_path.clone();
        tokio::task::spawn_blocking(move || std::fs::set_permissions(&key_path, perms))
            .await
            .map_err(|e| anyhow::anyhow!("set_permissions join failed: {e}"))??;
    }

    debug!(%hostname, "cert written to disk");
    Ok(())
}

/// Validate hostname against RFC 952/1123: labels of `[A-Za-z0-9-]`, no
/// leading/trailing hyphens, total ≤ 253, each label ≤ 63. Guards against
/// SNI path traversal before the hostname touches the filesystem.
fn validate_hostname(hostname: &str) -> anyhow::Result<()> {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    anyhow::ensure!(
        !hostname.is_empty() && hostname.len() <= 253,
        "hostname length out of range"
    );
    for label in hostname.split('.') {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "hostname label length out of range"
        );
        anyhow::ensure!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "hostname label contains invalid character"
        );
        anyhow::ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "hostname label must not start or end with a hyphen"
        );
    }
    Ok(())
}

/// Join `<cert_dir>/<hostname>.<ext>`, verify the result stays inside `cert_dir`.
fn safe_cert_path(
    cert_dir: &std::path::Path,
    hostname: &str,
    ext: &str,
) -> anyhow::Result<PathBuf> {
    let base = cert_dir.normalize()?;
    let candidate = base.as_path().join(format!("{hostname}.{ext}"));
    if !candidate.starts_with(base.as_path()) {
        anyhow::bail!("refusing to write cert outside cert_dir for `{hostname}`");
    }
    Ok(candidate)
}

async fn ensure_cert_dir_writable(cert_dir: &Path) -> anyhow::Result<()> {
    let probe = cert_dir.join(".acme-probe");
    tokio::fs::write(&probe, b"")
        .await
        .with_context(|| format!("ACME cert_dir not writable: {}", cert_dir.display()))?;
    let _ = tokio::fs::remove_file(&probe).await;
    Ok(())
}

fn classify_failure(err: &anyhow::Error) -> (Duration, &'static str) {
    for cause in err.chain() {
        if let Some(AcmeError::Api(problem)) = cause.downcast_ref::<AcmeError>()
            && is_rate_limited(problem)
        {
            return (RATE_LIMIT_COOLDOWN, "rateLimited");
        }
    }
    (FAILURE_COOLDOWN, "other")
}

fn is_rate_limited(problem: &Problem) -> bool {
    problem.r#type.as_deref() == Some("urn:ietf:params:acme:error:rateLimited")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn failure_path(cert_dir: &Path, hostname: &str) -> anyhow::Result<PathBuf> {
    safe_cert_path(cert_dir, hostname, "acme-failure")
}

async fn persist_failure(
    cert_dir: &Path,
    hostname: &str,
    retry_after_unix: u64,
    reason: &str,
) -> anyhow::Result<()> {
    let path = failure_path(cert_dir, hostname)?;
    let body = serde_json::to_vec(&FailureRecord {
        retry_after_unix,
        reason: Some(reason.to_string()),
    })?;
    tokio::fs::write(&path, body)
        .await
        .with_context(|| format!("failed to persist ACME failure for {hostname}"))?;
    Ok(())
}

async fn clear_persisted_failure(cert_dir: &Path, hostname: &str) {
    let Ok(path) = failure_path(cert_dir, hostname) else {
        return;
    };
    if let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(%hostname, error = %e, "failed to remove ACME failure sidecar");
    }
}

fn load_persisted_failures(cert_dir: &Path) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let entries = match std::fs::read_dir(cert_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %cert_dir.display(), error = %e, "failed to scan cert_dir for ACME failure sidecars");
            return out;
        }
    };
    let now = unix_now();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("acme-failure") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // Reject crafted filenames before they reach the failures map.
        if validate_hostname(stem).is_err() {
            warn!(file = %path.display(), "skipping ACME failure sidecar with invalid hostname");
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<FailureRecord>(&bytes) else {
            warn!(file = %path.display(), "failed to parse ACME failure sidecar; removing");
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if record.retry_after_unix <= now {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        out.insert(stem.to_string(), record.retry_after_unix);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        FailureRecord, RATE_LIMIT_COOLDOWN, classify_failure, failure_path,
        load_persisted_failures, validate_hostname,
    };
    use instant_acme::{Error as AcmeError, Problem};
    use std::path::PathBuf;

    fn temp_cert_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("towonel-acme-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn rate_limit_problem() -> Problem {
        Problem {
            r#type: Some("urn:ietf:params:acme:error:rateLimited".to_string()),
            detail: Some("too many certificates".to_string()),
            status: Some(429),
            subproblems: vec![],
        }
    }

    #[test]
    fn classify_failure_picks_rate_limit_cooldown_for_le_rate_limit() {
        let err: anyhow::Error = AcmeError::Api(rate_limit_problem()).into();
        let (cooldown, reason) = classify_failure(&err);
        assert_eq!(cooldown, RATE_LIMIT_COOLDOWN);
        assert_eq!(reason, "rateLimited");
    }

    #[test]
    fn classify_failure_picks_default_cooldown_for_unrelated_errors() {
        let err = anyhow::anyhow!("disk full");
        let (cooldown, reason) = classify_failure(&err);
        assert_eq!(cooldown, super::FAILURE_COOLDOWN);
        assert_eq!(reason, "other");
    }

    #[test]
    fn classify_failure_unwraps_through_anyhow_context() {
        let err = anyhow::Error::from(AcmeError::Api(rate_limit_problem()))
            .context("provisioning towonel.example.com");
        let (cooldown, _) = classify_failure(&err);
        assert_eq!(cooldown, RATE_LIMIT_COOLDOWN);
    }

    #[test]
    fn load_persisted_failures_drops_expired_and_keeps_active_entries() {
        let dir = temp_cert_dir("load");

        let active = failure_path(&dir, "active.example.com").unwrap();
        let active_record = FailureRecord {
            retry_after_unix: super::unix_now() + 3600,
            reason: Some("rateLimited".to_string()),
        };
        std::fs::write(&active, serde_json::to_vec(&active_record).unwrap()).unwrap();

        let expired = failure_path(&dir, "expired.example.com").unwrap();
        std::fs::write(
            &expired,
            serde_json::to_vec(&FailureRecord {
                retry_after_unix: 1,
                reason: None,
            })
            .unwrap(),
        )
        .unwrap();

        let loaded = load_persisted_failures(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get("active.example.com").copied(),
            Some(active_record.retry_after_unix)
        );
        assert!(active.exists(), "active sidecar should be retained");
        assert!(!expired.exists(), "expired sidecar should be deleted");
    }

    #[test]
    fn load_persisted_failures_skips_unrelated_files() {
        let dir = temp_cert_dir("ignore");
        std::fs::write(dir.join("account.json"), b"{}").unwrap();
        std::fs::write(dir.join("foo.example.com.crt"), b"").unwrap();
        std::fs::write(dir.join("foo.example.com.key"), b"").unwrap();
        let loaded = load_persisted_failures(&dir);
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_persisted_failures_purges_corrupted_records() {
        let dir = temp_cert_dir("corrupt");
        let path = failure_path(&dir, "broken.example.com").unwrap();
        std::fs::write(&path, b"not json").unwrap();
        let loaded = load_persisted_failures(&dir);
        assert!(loaded.is_empty());
        assert!(!path.exists(), "corrupted sidecar should be deleted");
    }

    #[test]
    fn valid_hostnames_are_accepted() {
        for h in &[
            "example.com",
            "foo.bar.baz",
            "sub-domain.example.co.uk",
            "xn--nxasmq6b.com",
            "a",
            "example.com.", // trailing dot (FQDN)
        ] {
            assert!(validate_hostname(h).is_ok(), "expected valid: {h}");
        }
    }

    #[test]
    fn traversal_sequences_are_rejected() {
        for h in &[
            "../etc/passwd",
            "../../secret",
            "foo/../bar",
            "foo/bar",
            "foo\\bar",
            ".hidden",
            "foo..bar",
        ] {
            assert!(validate_hostname(h).is_err(), "expected invalid: {h}");
        }
    }

    #[test]
    fn special_characters_are_rejected() {
        for h in &[
            "foo bar",
            "foo%2e%2e",
            "foo\0bar",
            "foo@bar",
            "foo:bar",
            "-foo.com",
            "foo-.com",
        ] {
            assert!(validate_hostname(h).is_err(), "expected invalid: {h}");
        }
    }

    #[test]
    fn empty_and_oversized_hostnames_are_rejected() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname(&"a".repeat(254)).is_err());
        assert!(validate_hostname(&format!("{}.com", "a".repeat(64))).is_err());
    }
}
