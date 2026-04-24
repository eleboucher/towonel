use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct CertStore {
    inner: Arc<ArcSwap<CertMap>>,
    reload_lock: Arc<StdRwLock<()>>,
    cert_dir: PathBuf,
}

type CertMap = HashMap<String, Arc<CertifiedKey>>;

impl CertStore {
    pub fn new(cert_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(cert_dir)?;
        let store = Self {
            inner: Arc::new(ArcSwap::from_pointee(CertMap::new())),
            reload_lock: Arc::new(StdRwLock::new(())),
            cert_dir: cert_dir.to_path_buf(),
        };
        store.reload_blocking();
        Ok(store)
    }

    pub fn cert_dir(&self) -> &Path {
        &self.cert_dir
    }

    pub async fn reload(&self) {
        let cloned = self.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || cloned.reload_blocking()).await {
            warn!(error = %e, "cert store reload task failed; TLS store may be stale");
        }
    }

    fn reload_blocking(&self) {
        let _guard = self
            .reload_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut certs = CertMap::new();
        let entries = match std::fs::read_dir(&self.cert_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %self.cert_dir.display(), error = %e, "failed to read cert dir");
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("crt") {
                continue;
            }
            let hostname = match path.file_stem().and_then(|s| s.to_str()) {
                Some(h) => h.to_string(),
                None => continue,
            };
            let key_path = self.cert_dir.join(format!("{hostname}.key"));
            match load_certified_key(&path, &key_path) {
                Ok(ck) => {
                    debug!(%hostname, "loaded cert");
                    certs.insert(hostname, Arc::new(ck));
                }
                Err(e) => {
                    warn!(%hostname, error = %e, "failed to load cert pair");
                }
            }
        }

        let count = certs.len();
        self.inner.store(Arc::new(certs));
        info!(count, "cert store reloaded");
    }

    pub fn has_cert(&self, hostname: &str) -> bool {
        self.inner.load().contains_key(hostname)
    }

    /// Build a `rustls::ServerConfig` that resolves certs from this store.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let resolver = StoreResolver(Arc::clone(&self.inner));
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

#[derive(Debug)]
struct StoreResolver(Arc<ArcSwap<CertMap>>);

impl ResolvesServerCert for StoreResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.0.load().get(sni).cloned()
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;

    Ok(CertifiedKey::new(certs, signing_key))
}
