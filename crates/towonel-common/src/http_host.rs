const MAX_HEADERS: usize = 64;

/// Lowercased routing host from a buffered HTTP request head.
///
/// Returns `None` (drop the connection) when routing could desync from the
/// origin: more than one `Host` header, or an absolute-form target whose
/// authority disagrees with `Host`.
#[must_use]
pub fn extract_host_header(buf: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(buf), Ok(httparse::Status::Complete(_))) {
        return None;
    }

    // Exactly one Host header, or we can't be sure which the origin honors.
    let mut hosts = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"));
    let value = hosts.next()?.value;
    if hosts.next().is_some() {
        return None;
    }

    let raw = std::str::from_utf8(value).ok()?.trim();
    let host = parse_authority_host(raw)?;

    // Absolute-form target authority must agree with Host. Origin-form targets
    // always begin with '/', so a leading '/' rules out absolute-form even when
    // the path or query legitimately embeds a "://" (e.g. `?next=https://...`).
    if let Some(path) = req.path
        && !path.starts_with('/')
        && let Some((_, scheme_rel)) = path.split_once("://")
        && let Some(authority) = scheme_rel.split(['/', '?', '#']).next()
        && !authority.is_empty()
    {
        let target_host = parse_authority_host(authority)?;
        if target_host != host {
            return None;
        }
    }

    Some(host)
}

/// Parse an `authority` (host[:port], IPv6 bracketed) into its lowercased,
/// unbracketed host.
fn parse_authority_host(raw: &str) -> Option<String> {
    let authority: http::uri::Authority = raw.parse().ok()?;
    let host = authority.host();
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    Some(unbracketed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_request_returns_host() {
        let req = b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\n\
                    Host: Example.COM:8080\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn ipv6_literal_keeps_brackets_contents() {
        let req = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("::1"));
    }

    #[test]
    fn incomplete_request_returns_none() {
        assert!(extract_host_header(b"GET / HTTP/1.1\r\nHost: examp").is_none());
    }

    #[test]
    fn missing_host_returns_none() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
        assert!(extract_host_header(req).is_none());
    }

    #[test]
    fn duplicate_host_header_rejected() {
        let req = b"GET / HTTP/1.1\r\nHost: a.example.eu\r\nHost: b.example.eu\r\n\r\n";
        assert!(extract_host_header(req).is_none());
    }

    #[test]
    fn absolute_form_matching_authority_ok() {
        let req = b"GET http://a.example.eu/path HTTP/1.1\r\nHost: a.example.eu\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("a.example.eu"));
    }

    #[test]
    fn absolute_form_mismatched_authority_rejected() {
        let req = b"GET http://b.example.eu/path HTTP/1.1\r\nHost: a.example.eu\r\n\r\n";
        assert!(extract_host_header(req).is_none());
    }

    #[test]
    fn origin_form_with_url_in_query_is_not_treated_as_absolute() {
        let req = b"GET /click?next=https://evil.example/path HTTP/1.1\r\n\
                    Host: a.example.eu\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("a.example.eu"));
    }

    #[test]
    fn origin_form_with_url_in_path_is_not_treated_as_absolute() {
        let req = b"GET /redirect/https://evil.example/ HTTP/1.1\r\n\
                    Host: a.example.eu\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("a.example.eu"));
    }
}
