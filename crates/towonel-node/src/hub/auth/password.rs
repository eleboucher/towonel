//! argon2id wrapper. Hashes encode their own parameters (PHC string format),
//! so future parameter bumps verify old hashes transparently.
#![allow(dead_code, reason = "consumed by web routes once mounted")]

use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, Version};

const MEMORY_KIB: u32 = 19_456; // 19 MiB — OWASP 2024 baseline
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

fn hasher() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("argon2 params constant-validated");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Returns a PHC-formatted hash, including salt + params, ready to store.
/// Runs on `spawn_blocking` because argon2 burns ~20 MiB + ~50 ms of CPU and
/// would otherwise block a tokio worker for the whole duration.
pub async fn hash(password: &str) -> anyhow::Result<String> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || hash_blocking(&password))
        .await
        .map_err(|e| anyhow::anyhow!("argon2 hash task panicked: {e}"))?
}

fn hash_blocking(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

/// Constant-time verify against a PHC-formatted hash. Returns `Ok(false)` on
/// a syntactically valid mismatch and an `Err` only on hash format problems.
/// Runs on `spawn_blocking` (see [`hash`]).
pub async fn verify(password: &str, phc: &str) -> anyhow::Result<bool> {
    let password = password.to_owned();
    let phc = phc.to_owned();
    tokio::task::spawn_blocking(move || verify_blocking(&password, &phc))
        .await
        .map_err(|e| anyhow::anyhow!("argon2 verify task panicked: {e}"))?
}

fn verify_blocking(password: &str, phc: &str) -> anyhow::Result<bool> {
    let parsed = argon2::password_hash::PasswordHash::new(phc)
        .map_err(|e| anyhow::anyhow!("invalid stored hash: {e}"))?;
    match hasher().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("argon2 verify: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let phc = hash("hunter2-the-second").await.unwrap();
        assert!(verify("hunter2-the-second", &phc).await.unwrap());
        assert!(!verify("hunter2-the-third", &phc).await.unwrap());
    }

    #[tokio::test]
    async fn different_salts_yield_different_hashes() {
        let a = hash("same-input").await.unwrap();
        let b = hash("same-input").await.unwrap();
        assert_ne!(a, b);
    }
}
