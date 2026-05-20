use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use certon::{
    AcmeIssuer, CacheOptions, CertCache, CertIssuer, CertResolver, Config, FileStorage,
    LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING, Solver, Storage,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// RFC 8737 `acmeIdentifier` extension OID.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

pub struct AcmeManager {
    config: Arc<Config>,
    server_config: Arc<rustls::ServerConfig>,
}

impl AcmeManager {
    pub fn new(cert_dir: &Path, acme_email: String, staging: bool) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(cert_dir).with_context(|| {
            format!("failed to create cert_dir {}", cert_dir.display())
        })?;

        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(cert_dir));
        let cache = CertCache::new(CacheOptions::default());

        // Solver and rustls resolver share one Arc so present()/cleanup()
        // mutate the same map the handshake reads from.
        let resolver: Arc<CertResolver> = Arc::new(CertResolver::new(Arc::clone(&cache)));
        let alpn_solver: Arc<dyn Solver> = Arc::new(EdgeAlpnSolver::new(Arc::clone(&resolver)));

        let ca = if staging {
            LETS_ENCRYPT_STAGING
        } else {
            LETS_ENCRYPT_PRODUCTION
        };
        let issuer = AcmeIssuer::builder()
            .ca(ca)
            .email(acme_email)
            .agreed(true)
            .storage(Arc::clone(&storage))
            .tlsalpn01_solver(alpn_solver)
            .disable_http_challenge(true)
            .disable_distributed_solvers(true)
            .build();
        let issuers: Vec<Arc<dyn CertIssuer>> = vec![Arc::new(issuer)];

        let config = Config::builder()
            .storage(storage)
            .cache(cache)
            .issuers(issuers)
            .build();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let mgr = Arc::new(Self {
            config: Arc::new(config),
            server_config: Arc::new(server_config),
        });

        // Detached: runs for the lifetime of the process.
        drop(certon::start_maintenance(&mgr.config));

        info!(cert_dir = %cert_dir.display(), staging, "ACME manager ready");
        Ok(mgr)
    }

    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.server_config)
    }

    pub async fn ensure_cert(&self, hostname: &str) -> anyhow::Result<()> {
        self.config
            .manage_sync(&[hostname.to_string()])
            .await
            .with_context(|| format!("ACME manage_sync failed for {hostname}"))?;
        // `obtain_cert_sync` (inside `manage_sync` on a fresh order) writes
        // the cert to storage but doesn't push it into the cache the rustls
        // resolver reads from. Without this load, the first handshake after
        // issuance still misses.
        if let Err(e) = self.config.cache_managed_certificate(hostname).await {
            warn!(%hostname, error = %e, "failed to refresh cert cache after manage_sync");
        }
        Ok(())
    }
}

struct EdgeAlpnSolver {
    resolver: Arc<CertResolver>,
}

impl EdgeAlpnSolver {
    const fn new(resolver: Arc<CertResolver>) -> Self {
        Self { resolver }
    }

    fn build_challenge_cert(
        domain: &str,
        key_auth: &str,
    ) -> anyhow::Result<Arc<CertifiedKey>> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();

        // RFC 8737: extension value is DER OCTET STRING wrapping SHA-256(key_auth).
        let digest = Sha256::digest(key_auth.as_bytes());
        let mut ext_value = Vec::with_capacity(2 + 32);
        ext_value.push(0x04); // OCTET STRING tag
        ext_value.push(0x20); // length 32
        ext_value.extend_from_slice(&digest);

        let oid: Vec<u64> = ACME_IDENTIFIER_OID.to_vec();
        let mut ext = CustomExtension::from_oid_content(&oid, ext_value);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);

        let cert = params.self_signed(&key_pair)?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
        Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
    }
}

#[async_trait]
impl Solver for EdgeAlpnSolver {
    async fn present(&self, domain: &str, _token: &str, key_auth: &str) -> certon::Result<()> {
        let cert = Self::build_challenge_cert(domain, key_auth)
            .map_err(|e| certon::Error::Other(e.to_string()))?;
        self.resolver
            .set_challenge_cert(domain.to_string(), cert)
            .await;
        debug!(%domain, "TLS-ALPN-01 challenge cert registered");
        Ok(())
    }

    async fn cleanup(&self, domain: &str, _token: &str, _key_auth: &str) -> certon::Result<()> {
        self.resolver.remove_challenge_cert(domain).await;
        debug!(%domain, "TLS-ALPN-01 challenge cert cleared");
        Ok(())
    }
}
