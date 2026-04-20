//! Typed representation of the hub's JSON error envelope.

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
#[error("hub returned {status} ({code}): {message}")]
pub struct HubApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

#[derive(Deserialize)]
struct Envelope {
    error: Fields,
}

#[derive(Deserialize)]
struct Fields {
    code: String,
    message: String,
}

/// Parse `{"error":{"code","message"}}`. Returns `None` when `body` isn't
/// that shape, so callers can fall back to a generic message.
#[must_use]
pub fn parse(status: u16, body: &[u8]) -> Option<HubApiError> {
    serde_json::from_slice::<Envelope>(body)
        .ok()
        .map(|env| HubApiError {
            status,
            code: env.error.code,
            message: env.error.message,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_envelope() {
        let body = br#"{"error":{"code":"sequence_conflict","message":"seq taken"}}"#;
        let err = parse(409, body).unwrap();
        assert_eq!(err.status, 409);
        assert_eq!(err.code, "sequence_conflict");
        assert_eq!(err.message, "seq taken");
    }

    #[test]
    fn returns_none_on_unparsable_body() {
        assert!(parse(500, b"oh no, proxy").is_none());
    }
}
