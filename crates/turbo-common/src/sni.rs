pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let ch = clienthello::parse_from_record(buf).ok()?;
    ch.server_name().map(|s| s.to_string())
}
