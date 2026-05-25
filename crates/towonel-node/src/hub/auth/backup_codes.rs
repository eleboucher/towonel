//! One-time backup codes hashed with argon2id; 10 per user, `XXXXX-XXXXX`.
#![allow(dead_code, reason = "consumed by web routes once mounted")]

use super::password;

const CODE_COUNT: usize = 10;
const HALF_LEN: usize = 5;
// Crockford-ish: no 0/O/1/I/L.
const ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

#[must_use]
pub fn generate_set() -> Vec<String> {
    (0..CODE_COUNT).map(|_| generate_one()).collect()
}

fn generate_one() -> String {
    let mut buf = [0u8; HALF_LEN * 2];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG failure is unrecoverable at this layer"
    )]
    getrandom::fill(&mut buf).expect("OS RNG failed");
    let mut out = String::with_capacity(HALF_LEN * 2 + 1);
    for (i, b) in buf.iter().enumerate() {
        if i == HALF_LEN {
            out.push('-');
        }
        let idx = (*b as usize) % ALPHABET.len();
        #[expect(
            clippy::indexing_slicing,
            reason = "idx is `% ALPHABET.len()` so always in bounds"
        )]
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[must_use]
pub fn normalise(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

pub async fn hash(code: &str) -> anyhow::Result<String> {
    password::hash(&normalise(code)).await
}

pub async fn verify(code: &str, phc: &str) -> anyhow::Result<bool> {
    password::verify(&normalise(code), phc).await
}

#[must_use]
pub fn looks_like_backup_code(input: &str) -> bool {
    let n = normalise(input);
    n.len() == HALF_LEN * 2 && n.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ten_codes() {
        let set = generate_set();
        assert_eq!(set.len(), 10);
        for c in &set {
            assert!(c.contains('-'));
            assert_eq!(c.len(), HALF_LEN * 2 + 1);
        }
    }

    #[test]
    fn codes_are_unique() {
        let set = generate_set();
        let unique: std::collections::HashSet<_> = set.iter().collect();
        assert_eq!(unique.len(), set.len());
    }

    #[test]
    fn normalise_strips_formatting() {
        assert_eq!(normalise("abcde-fghij"), "ABCDEFGHIJ");
        assert_eq!(normalise(" a B c D e \tF g h i j "), "ABCDEFGHIJ");
    }

    #[test]
    fn shape_check_accepts_real_codes() {
        for c in &generate_set() {
            assert!(looks_like_backup_code(c));
        }
    }

    #[test]
    fn shape_check_rejects_random_strings() {
        assert!(!looks_like_backup_code("123456"));
        assert!(!looks_like_backup_code("hello"));
        assert!(!looks_like_backup_code("ABCDEFGHIJK"));
    }

    #[tokio::test]
    async fn hash_and_verify_round_trip() {
        let code = "abcde-fghij";
        let phc = hash(code).await.unwrap();
        assert!(verify(code, &phc).await.unwrap());
        assert!(verify("ABCDEFGHIJ", &phc).await.unwrap());
        assert!(verify(" abcde - fghij ", &phc).await.unwrap());
        assert!(!verify("00000-00000", &phc).await.unwrap());
    }
}
