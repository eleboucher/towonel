const MAX_HEADERS: usize = 64;

#[must_use]
pub fn extract_host_header(buf: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(buf), Ok(httparse::Status::Complete(_))) {
        return None;
    }
    let value = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))?
        .value;
    let raw = std::str::from_utf8(value).ok()?.trim();
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
}
