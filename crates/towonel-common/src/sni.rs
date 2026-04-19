/// Zero-copy SNI extractor: the returned `&str` borrows from `buf`.
///
/// `ClientHello::server_name` elides the lifetime to `&self`, which dies
/// with the parsed struct. We consume the struct and reach directly into
/// `ServerName::name: &'a [u8]` so the returned `&str` carries `buf`'s
/// lifetime.
#[must_use]
pub fn extract_sni(buf: &[u8]) -> Option<&str> {
    let ch = clienthello::parse_from_record(buf).ok()?;
    for ext in ch.extensions {
        if let clienthello::Extension::ServerName(names) = ext {
            for sn in names {
                if sn.name_type == 0x00 {
                    return std::str::from_utf8(sn.name).ok();
                }
            }
        }
    }
    None
}
