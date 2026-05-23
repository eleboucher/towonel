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
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

/// Constant-time verify against a PHC-formatted hash. Returns `Ok(false)` on
/// a syntactically valid mismatch and an `Err` only on hash format problems.
pub fn verify(password: &str, phc: &str) -> anyhow::Result<bool> {
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

    #[test]
    fn round_trip() {
        let phc = hash("hunter2-the-second").unwrap();
        assert!(verify("hunter2-the-second", &phc).unwrap());
        assert!(!verify("hunter2-the-third", &phc).unwrap());
    }

    #[test]
    fn different_salts_yield_different_hashes() {
        let a = hash("same-input").unwrap();
        let b = hash("same-input").unwrap();
        assert_ne!(a, b);
    }
}
