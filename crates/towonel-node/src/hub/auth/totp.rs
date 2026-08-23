//! RFC 6238 TOTP, ±1 step window, `last_used_step` replay guard.
#![allow(dead_code, reason = "consumed by web routes once mounted")]

use towonel_common::kek::HubKek;

pub const SECRET_BYTES: usize = 20;
pub const PERIOD_SECS: u64 = 30;
pub const DIGITS: u8 = 6;
const SKEW: u16 = 1;

#[derive(Debug)]
pub enum VerifyError {
    InvalidCode,
    Replayed,
    Internal,
}

#[must_use]
pub fn generate_secret() -> [u8; SECRET_BYTES] {
    let mut buf = [0u8; SECRET_BYTES];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG failure is unrecoverable at this layer"
    )]
    getrandom::fill(&mut buf).expect("OS RNG failed");
    buf
}

pub fn seal(secret: &[u8], kek: &HubKek) -> anyhow::Result<Vec<u8>> {
    kek.seal(secret)
}

pub fn unseal(blob: &[u8], kek: &HubKek) -> anyhow::Result<Vec<u8>> {
    kek.unseal(blob)
}

#[must_use]
pub fn secret_base32(secret: &[u8]) -> String {
    base32_encode_no_pad(secret)
}

#[must_use]
pub fn otpauth_url(secret: &[u8], account: &str, issuer: &str) -> String {
    let secret = secret_base32(secret);
    let issuer_enc = url_path_encode(issuer);
    let account_enc = url_path_encode(account);
    let issuer_q = url_path_encode(issuer);
    format!(
        "otpauth://totp/{issuer_enc}:{account_enc}?secret={secret}&issuer={issuer_q}\
         &algorithm=SHA1&digits=6&period=30"
    )
}

pub fn verify_code(
    secret: &[u8],
    code: &str,
    now_unix: u64,
    last_used_step: Option<u64>,
) -> Result<u64, VerifyError> {
    if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VerifyError::InvalidCode);
    }
    let totp = builder(secret)
        .build()
        .map_err(|_err| VerifyError::Internal)?;

    // `check` walks the ±SKEW window in constant time and hands back the step
    // that matched.
    let Some(step) = totp.check(code, now_unix) else {
        return Err(VerifyError::InvalidCode);
    };
    if let Some(last) = last_used_step
        && step <= last
    {
        return Err(VerifyError::Replayed);
    }
    Ok(step)
}

fn builder(secret: &[u8]) -> totp_rs::Builder {
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(SKEW)
        .with_step_duration(PERIOD_SECS)
        .with_secret(secret)
}

#[cfg(test)]
#[must_use]
pub fn generate_at(secret: &[u8], unix_time: u64) -> String {
    builder(secret)
        .build_noncompliant()
        .generate(unix_time)
        .to_string()
}

fn base32_encode_no_pad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            #[expect(
                clippy::indexing_slicing,
                reason = "idx masked to 5 bits, always < 32 = ALPHABET.len()"
            )]
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        #[expect(
            clippy::indexing_slicing,
            reason = "idx masked to 5 bits, always < 32 = ALPHABET.len()"
        )]
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn url_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            use std::fmt::Write;
            let mut buf = [0u8; 4];
            for &b in c.encode_utf8(&mut buf).as_bytes() {
                #[expect(clippy::unwrap_used, reason = "writing to a String cannot fail")]
                write!(out, "%{b:02X}").unwrap();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_length() {
        let s = generate_secret();
        assert_eq!(s.len(), SECRET_BYTES);
    }

    #[test]
    fn seal_unseal_round_trip() {
        let kek = HubKek::generate();
        let s = generate_secret();
        let sealed = seal(&s, &kek).unwrap();
        let unsealed = unseal(&sealed, &kek).unwrap();
        assert_eq!(unsealed, s);
    }

    #[test]
    fn verify_accepts_current_code() {
        let s = generate_secret();
        let now = 1_700_000_000u64;
        let code = generate_at(&s, now);
        let step = verify_code(&s, &code, now, None).unwrap();
        assert_eq!(step, now / PERIOD_SECS);
    }

    #[test]
    fn verify_accepts_previous_step() {
        let s = generate_secret();
        let now = 1_700_000_000u64;
        let code = generate_at(&s, now - PERIOD_SECS);
        let step = verify_code(&s, &code, now, None).unwrap();
        assert_eq!(step, (now - PERIOD_SECS) / PERIOD_SECS);
    }

    #[test]
    fn verify_rejects_replay() {
        let s = generate_secret();
        let now = 1_700_000_000u64;
        let code = generate_at(&s, now);
        let step = verify_code(&s, &code, now, None).unwrap();
        let err = verify_code(&s, &code, now, Some(step)).unwrap_err();
        assert!(matches!(err, VerifyError::Replayed));
    }

    #[test]
    fn verify_rejects_garbage() {
        let s = generate_secret();
        assert!(matches!(
            verify_code(&s, "abcdef", 1_700_000_000, None),
            Err(VerifyError::InvalidCode)
        ));
        assert!(matches!(
            verify_code(&s, "12345", 1_700_000_000, None),
            Err(VerifyError::InvalidCode)
        ));
    }

    #[test]
    fn base32_known_vector() {
        // RFC 4648 §10
        assert_eq!(base32_encode_no_pad(b"f"), "MY");
        assert_eq!(base32_encode_no_pad(b"foo"), "MZXW6");
        assert_eq!(base32_encode_no_pad(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn otpauth_url_shape() {
        let s = b"12345678901234567890";
        let url = otpauth_url(s, "alice@example.com", "Towonel");
        assert!(url.starts_with("otpauth://totp/Towonel:alice%40example.com?secret="));
        assert!(url.contains("algorithm=SHA1"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
    }
}
