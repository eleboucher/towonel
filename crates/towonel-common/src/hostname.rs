use std::borrow::Cow;

/// Returns `hostname` borrowed if already ASCII-lowercase, otherwise owned.
/// DNS hostnames are ASCII (IDN uses punycode), so the common case is borrow.
#[must_use]
pub fn ascii_lowercase_cow(hostname: &str) -> Cow<'_, str> {
    if hostname.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(hostname.to_ascii_lowercase())
    } else {
        Cow::Borrowed(hostname)
    }
}

/// Given a hostname, try an exact key lookup, then a single-level wildcard
/// (`*.example.eu` matches `app.example.eu`). Returns the value if found.
///
/// The `get` closure receives a lowercase key and returns `Some(V)` on hit.
pub fn wildcard_lookup<'m, V>(
    hostname: &str,
    get: impl Fn(&str) -> Option<&'m V>,
) -> Option<&'m V> {
    wildcard_lookup_ascii_lower(&ascii_lowercase_cow(hostname), get)
}

/// Same as [`wildcard_lookup`] but skips the lowercasing step; the caller has
/// already produced an ASCII-lowercase key.
pub fn wildcard_lookup_ascii_lower<'m, V>(
    lower: &str,
    get: impl Fn(&str) -> Option<&'m V>,
) -> Option<&'m V> {
    if let Some(v) = get(lower) {
        return Some(v);
    }
    if let Some(dot_pos) = lower.find('.') {
        #[expect(
            clippy::string_slice,
            reason = "dot_pos is a valid char boundary returned by find('.')"
        )]
        let suffix = &lower[dot_pos + 1..];
        let mut buf = [0u8; 257];
        if suffix.len() + 2 <= buf.len() {
            buf[0] = b'*';
            buf[1] = b'.';
            #[expect(
                clippy::indexing_slicing,
                reason = "guarded by suffix.len() + 2 <= buf.len() above"
            )]
            buf[2..2 + suffix.len()].copy_from_slice(suffix.as_bytes());
            #[expect(
                clippy::indexing_slicing,
                reason = "guarded by suffix.len() + 2 <= buf.len() above"
            )]
            let wildcard_bytes = &buf[..2 + suffix.len()];
            if let Ok(wildcard) = std::str::from_utf8(wildcard_bytes)
                && let Some(v) = get(wildcard)
            {
                return Some(v);
            }
        }
    }
    None
}

/// Validate a hostname or wildcard pattern against a simplified RFC 1123.
///
/// Accepts:
/// - `app.example.eu` (regular hostname)
/// - `*.example.eu`   (wildcard: `*` only as the first label)
///
/// Rejects:
/// - empty strings
/// - hostnames longer than 253 characters
/// - labels longer than 63 characters
/// - labels with characters outside `[a-zA-Z0-9-]` (except `*` as sole first label)
/// - labels starting or ending with a hyphen
/// - bare wildcards like `*` with no dots
pub fn validate_hostname(hostname: &str) -> Result<(), HostnameError> {
    // Normalize the same way every consumer (routing / TLS lookup keys) does.
    let lower = hostname.to_ascii_lowercase();
    if lower.is_empty() {
        return Err(HostnameError::Empty);
    }
    if lower.len() > 253 {
        return Err(HostnameError::TooLong(lower.len()));
    }

    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return Err(HostnameError::TooFewLabels);
    }

    // A wildcard must cover a real domain, not a public suffix: `*.example.eu`
    // is fine, `*.eu` would let one tenant claim an entire TLD.
    if labels.first() == Some(&"*") && labels.len() < 3 {
        return Err(HostnameError::WildcardTooBroad);
    }

    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() {
            return Err(HostnameError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(HostnameError::LabelTooLong(label.len()));
        }

        if i == 0 && *label == "*" {
            continue;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostnameError::InvalidLabel((*label).to_string()));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(HostnameError::InvalidLabel((*label).to_string()));
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HostnameError {
    #[error("hostname must not be empty")]
    Empty,
    #[error("hostname must have at least two labels (e.g. app.example.eu)")]
    TooFewLabels,
    #[error("wildcard must cover a domain, not a public suffix (e.g. *.example.eu, not *.eu)")]
    WildcardTooBroad,
    #[error("hostname exceeds 253 characters ({0})")]
    TooLong(usize),
    #[error("hostname contains an empty label (double dot or leading/trailing dot)")]
    EmptyLabel,
    #[error("hostname label exceeds 63 characters ({0})")]
    LabelTooLong(usize),
    #[error(
        "invalid hostname label: `{0}` (only a-z, 0-9, hyphen allowed; `*` only as first label)"
    )]
    InvalidLabel(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_hostnames() {
        validate_hostname("app.example.eu").unwrap();
        validate_hostname("a-b.c-d.example.eu").unwrap();
        validate_hostname("*.example.eu").unwrap();
        validate_hostname("sub.deep.example.eu").unwrap();
        validate_hostname("APP.EXAMPLE.EU").unwrap();
    }

    #[test]
    fn rejects_empty() {
        validate_hostname("").unwrap_err();
    }

    #[test]
    fn rejects_single_label() {
        validate_hostname("localhost").unwrap_err();
        validate_hostname("*").unwrap_err();
    }

    #[test]
    fn rejects_wildcard_at_public_suffix() {
        validate_hostname("*.eu").unwrap_err();
        validate_hostname("*.com").unwrap_err();
    }

    #[test]
    fn rejects_leading_trailing_dot() {
        validate_hostname(".example.eu").unwrap_err();
        validate_hostname("example.eu.").unwrap_err();
    }

    #[test]
    fn rejects_leading_trailing_hyphen() {
        validate_hostname("-bad.example.eu").unwrap_err();
        validate_hostname("bad-.example.eu").unwrap_err();
    }

    #[test]
    fn rejects_invalid_chars() {
        validate_hostname("sp ace.example.eu").unwrap_err();
        validate_hostname("under_score.example.eu").unwrap_err();
    }

    #[test]
    fn rejects_long_hostname() {
        let long = format!("{}.example.eu", "a".repeat(250));
        validate_hostname(&long).unwrap_err();
    }

    #[test]
    fn rejects_long_label() {
        let long = format!("{}.example.eu", "a".repeat(64));
        validate_hostname(&long).unwrap_err();
    }
}
