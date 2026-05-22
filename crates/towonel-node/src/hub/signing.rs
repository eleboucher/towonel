#![expect(
    clippy::map_err_ignore,
    reason = "TryInto length-mismatch errors carry no information beyond our message"
)]

use anyhow::Context;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use tracing::info;
use zeroize::Zeroizing;

use towonel_common::edge_cred::{EdgeCred, EdgeCredSig, Kid};
use towonel_common::identity::{PQ_SEED_LEN, PqPublicKey};
use towonel_common::kek::HubKek;

use super::db::Db;

/// The on-disk form is the 32-byte seed, sealed under the KEK; the
/// `priv_key` is re-derived from the seed on load. `priv_key` is boxed so
/// the struct stays small enough to hold across `.await` boundaries without
/// tripping `clippy::large_futures` (`ml-dsa-65` private keys are ~4 KiB).
pub struct HubSigner {
    kid: Kid,
    seed: Zeroizing<[u8; PQ_SEED_LEN]>,
    priv_key: Box<ml_dsa_65::PrivateKey>,
    public_key: PqPublicKey,
}

impl HubSigner {
    pub fn generate(kid: Kid) -> anyhow::Result<Self> {
        let mut seed = Zeroizing::new([0u8; PQ_SEED_LEN]);
        getrandom::fill(seed.as_mut_slice()).map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
        Ok(Self::from_seed(kid, seed))
    }

    pub fn from_seed(kid: Kid, seed: Zeroizing<[u8; PQ_SEED_LEN]>) -> Self {
        let (pub_key, priv_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        let public_key = PqPublicKey::from_bytes(pub_key.into_bytes());
        Self {
            kid,
            seed,
            priv_key: Box::new(priv_key),
            public_key,
        }
    }

    pub fn from_seed_bytes(kid: Kid, bytes: &[u8]) -> anyhow::Result<Self> {
        let arr: [u8; PQ_SEED_LEN] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("hub signing seed must be {PQ_SEED_LEN} bytes"))?;
        Ok(Self::from_seed(kid, Zeroizing::new(arr)))
    }

    #[must_use]
    pub const fn kid(&self) -> Kid {
        self.kid
    }

    #[must_use]
    pub const fn public_key(&self) -> &PqPublicKey {
        &self.public_key
    }

    #[must_use]
    pub fn seed(&self) -> &[u8; PQ_SEED_LEN] {
        &self.seed
    }

    pub fn sign_edge_cred(&self, cred: &EdgeCred) -> anyhow::Result<(Vec<u8>, EdgeCredSig)> {
        let bytes = cred.to_cbor()?;
        let sig = self
            .priv_key
            .try_sign(&bytes, b"")
            .map_err(|e| anyhow::anyhow!("ml-dsa-65 sign: {e}"))?;
        Ok((bytes, sig))
    }
}

impl std::fmt::Debug for HubSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

const SIGNING_KEY_INSERT_RETRIES: u32 = 8;

/// Concurrent hubs racing the first boot resolve via the kid PK conflict —
/// the loser sees a unique-violation and re-fetches the winner's row.
pub async fn get_or_create_active_signing_key(db: &Db, kek: &HubKek) -> anyhow::Result<HubSigner> {
    for attempt in 0..SIGNING_KEY_INSERT_RETRIES {
        if let Some(row) = db.active_signing_key().await? {
            let kid: Kid = row
                .kid
                .try_into()
                .map_err(|_| anyhow::anyhow!("kid {} does not fit in u32", row.kid))?;
            let seed_bytes = kek.unseal(&row.private_key_sealed).with_context(|| {
                format!(
                    "decrypt hub_signing_keys row kid={kid} — TOWONEL_HUB_KEK must \
                     match the value used when the row was sealed; a fresh KEK from \
                     a different host or rotated secret will fail here"
                )
            })?;
            return HubSigner::from_seed_bytes(kid, &seed_bytes);
        }

        let next_kid_i64 = db.max_signing_key_kid().await?.unwrap_or(0) + 1;
        let next_kid: Kid = next_kid_i64
            .try_into()
            .map_err(|_| anyhow::anyhow!("next kid {next_kid_i64} does not fit in u32"))?;
        let signer = HubSigner::generate(next_kid)?;
        let sealed = kek.seal(signer.seed())?;
        let now = towonel_common::time::now_ms();
        match db
            .insert_signing_key(
                next_kid_i64,
                signer.public_key().as_bytes().as_slice(),
                &sealed,
                now.try_into()
                    .map_err(|_| anyhow::anyhow!("clock skew: now_ms {now} does not fit in i64"))?,
            )
            .await
        {
            Ok(()) => {
                info!(kid = next_kid, "generated hub signing key");
                return Ok(signer);
            }
            Err(e) if super::db::is_unique_violation(&e) => {
                tracing::debug!(
                    kid = next_kid,
                    attempt,
                    "lost the signing-key insert race; re-reading"
                );
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!(
        "failed to acquire active signing key after {SIGNING_KEY_INSERT_RETRIES} attempts"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::edge_cred::{EDGE_CRED_NONCE_LEN, EDGE_CRED_VERSION, verify_edge_cred};
    use towonel_common::identity::{AgentKeypair, TenantKeypair};

    use crate::hub::db::temp_db;

    #[test]
    fn sign_verify_round_trip() {
        let signer = HubSigner::generate(7).unwrap();
        let agent = AgentKeypair::generate();
        let tenant = TenantKeypair::generate();
        let cred = EdgeCred {
            version: EDGE_CRED_VERSION,
            kid: signer.kid(),
            agent_id: agent.id(),
            tenant_id: tenant.id(),
            not_after_ms: 1_700_000_000_000,
            nonce: [9u8; EDGE_CRED_NONCE_LEN],
        };
        let (bytes, sig) = signer.sign_edge_cred(&cred).unwrap();
        assert!(verify_edge_cred(signer.public_key(), &bytes, &sig));
    }

    #[test]
    fn seed_round_trip_produces_same_pubkey() {
        let signer = HubSigner::generate(3).unwrap();
        let pubkey1 = *signer.public_key().as_bytes();
        let seed_bytes = *signer.seed();
        let signer2 = HubSigner::from_seed_bytes(3, &seed_bytes).unwrap();
        assert_eq!(*signer2.public_key().as_bytes(), pubkey1);
    }

    #[tokio::test]
    async fn get_or_create_inserts_on_empty_table() {
        let db = temp_db().await;
        let kek = HubKek::generate();
        let signer = get_or_create_active_signing_key(&db, &kek).await.unwrap();
        assert_eq!(signer.kid(), 1);
        let row = db.active_signing_key().await.unwrap().unwrap();
        assert_eq!(row.kid, 1);
        // The stored public_key column must match the in-memory signer's
        // pubkey (defends against a tampered BLOB silently going unnoticed).
        assert_eq!(row.public_key, signer.public_key().as_bytes().as_slice());
        // …and the unsealed seed must round-trip back to the same pubkey.
        let unsealed = kek.unseal(&row.private_key_sealed).unwrap();
        let reloaded = HubSigner::from_seed_bytes(1, &unsealed).unwrap();
        assert_eq!(
            reloaded.public_key().as_bytes(),
            signer.public_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn get_or_create_returns_existing_row() {
        let db = temp_db().await;
        let kek = HubKek::generate();
        let first = get_or_create_active_signing_key(&db, &kek).await.unwrap();
        let again = get_or_create_active_signing_key(&db, &kek).await.unwrap();
        assert_eq!(first.kid(), again.kid());
        assert_eq!(first.public_key().as_bytes(), again.public_key().as_bytes());
    }

    #[tokio::test]
    async fn wrong_kek_fails_to_unseal_existing_row() {
        let db = temp_db().await;
        let kek_a = HubKek::generate();
        get_or_create_active_signing_key(&db, &kek_a).await.unwrap();
        let kek_b = HubKek::generate();
        let err = get_or_create_active_signing_key(&db, &kek_b)
            .await
            .unwrap_err();
        // Operator-facing context must point at the KEK mismatch hypothesis.
        assert!(
            err.to_string().contains("TOWONEL_HUB_KEK")
                || err
                    .chain()
                    .any(|e| e.to_string().contains("TOWONEL_HUB_KEK")),
            "error chain should mention TOWONEL_HUB_KEK: {err:#}"
        );
    }

    #[tokio::test]
    async fn concurrent_boots_converge_on_one_kid() {
        let db = std::sync::Arc::new(temp_db().await);
        let kek = std::sync::Arc::new(HubKek::generate());
        let (a, b) = tokio::join!(
            {
                let db = std::sync::Arc::clone(&db);
                let kek = std::sync::Arc::clone(&kek);
                async move { get_or_create_active_signing_key(&db, &kek).await }
            },
            {
                let db = std::sync::Arc::clone(&db);
                let kek = std::sync::Arc::clone(&kek);
                async move { get_or_create_active_signing_key(&db, &kek).await }
            },
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a.kid(), b.kid(), "both boots must converge on the same kid");
        assert_eq!(
            *a.public_key().as_bytes(),
            *b.public_key().as_bytes(),
            "both boots must observe the same public key",
        );
    }
}
