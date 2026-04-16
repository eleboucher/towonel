/// Given a hostname, try an exact key lookup, then a single-level wildcard
/// (`*.example.eu` matches `app.example.eu`). Returns the value if found.
///
/// The `get` closure receives a lowercase key and returns `Some(V)` on hit.
pub fn wildcard_lookup<'m, V>(
    hostname: &str,
    get: impl Fn(&str) -> Option<&'m V>,
) -> Option<&'m V> {
    let lower = hostname.to_lowercase();
    if let Some(v) = get(&lower) {
        return Some(v);
    }
    if let Some(dot_pos) = lower.find('.') {
        let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
        if let Some(v) = get(&wildcard) {
            return Some(v);
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
    let lower = hostname.to_lowercase();
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
        assert!(validate_hostname("app.example.eu").is_ok());
        assert!(validate_hostname("a-b.c-d.example.eu").is_ok());
        assert!(validate_hostname("*.example.eu").is_ok());
        assert!(validate_hostname("sub.deep.example.eu").is_ok());
        assert!(validate_hostname("APP.EXAMPLE.EU").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn rejects_single_label() {
        assert!(validate_hostname("localhost").is_err());
        assert!(validate_hostname("*").is_err());
    }

    #[test]
    fn rejects_leading_trailing_dot() {
        assert!(validate_hostname(".example.eu").is_err());
        assert!(validate_hostname("example.eu.").is_err());
    }

    #[test]
    fn rejects_leading_trailing_hyphen() {
        assert!(validate_hostname("-bad.example.eu").is_err());
        assert!(validate_hostname("bad-.example.eu").is_err());
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(validate_hostname("sp ace.example.eu").is_err());
        assert!(validate_hostname("under_score.example.eu").is_err());
    }

    #[test]
    fn rejects_long_hostname() {
        let long = format!("{}.example.eu", "a".repeat(250));
        assert!(validate_hostname(&long).is_err());
    }

    #[test]
    fn rejects_long_label() {
        let long = format!("{}.example.eu", "a".repeat(64));
        assert!(validate_hostname(&long).is_err());
    }
}
