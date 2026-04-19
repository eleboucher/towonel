use std::sync::Arc;

use serde::Serialize;

/// Cap on how much of a peer error is retained. Keeps operator endpoints
/// bounded in memory even if the underlying reqwest error stringifies long.
const MAX_ERR_MESSAGE_LEN: usize = 256;

#[derive(Clone, Debug, Default, Serialize)]
pub struct PeerStatus {
    pub last_push_ok_ms: Option<u64>,
    pub last_push_err_ms: Option<u64>,
    pub last_err_message: Option<String>,
    pub entries_pushed: u64,
    pub tenants_pushed: u64,
    pub removals_pushed: u64,
}

impl PeerStatus {
    pub fn set_err_message(&mut self, msg: &str) {
        let truncated = if msg.len() > MAX_ERR_MESSAGE_LEN {
            let mut cut = MAX_ERR_MESSAGE_LEN;
            while !msg.is_char_boundary(cut) {
                cut -= 1;
            }
            format!("{}…", &msg[..cut])
        } else {
            msg.to_string()
        };
        self.last_err_message = Some(truncated);
    }
}

/// Per-peer federation push status, keyed by configured peer URL.
/// Lock-free reads via `papaya`; writers do get/mutate/insert.
pub type PeerStatusMap = Arc<papaya::HashMap<Arc<str>, PeerStatus>>;

#[must_use]
pub fn new_peer_status_map(peer_urls: &[String]) -> PeerStatusMap {
    let map = papaya::HashMap::with_capacity(peer_urls.len());
    {
        let pinned = map.pin();
        for url in peer_urls {
            pinned.insert(Arc::<str>::from(url.as_str()), PeerStatus::default());
        }
    }
    Arc::new(map)
}

/// Mutate the `PeerStatus` for `peer_url` (or insert a default first). The
/// closure runs against a cloned status that is then written back with
/// `insert`. Concurrent mutations race like last-writer-wins, which is
/// acceptable for observability counters.
pub fn mutate_peer_status(
    map: &PeerStatusMap,
    peer_url: &str,
    mutate: impl FnOnce(&mut PeerStatus),
) {
    let pinned = map.pin();
    let mut status = pinned.get(peer_url).cloned().unwrap_or_default();
    mutate(&mut status);
    // Hit the common case where the key already exists as Arc<str> without
    // allocating a new one; fall back to an owned Arc<str> on first write.
    if let Some(existing_key) = pinned.get_key_value(peer_url).map(|(k, _)| Arc::clone(k)) {
        pinned.insert(existing_key, status);
    } else {
        pinned.insert(Arc::<str>::from(peer_url), status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_error_is_not_truncated() {
        let mut s = PeerStatus::default();
        s.set_err_message("boom");
        assert_eq!(s.last_err_message.as_deref(), Some("boom"));
    }

    #[test]
    fn long_error_is_truncated_with_ellipsis() {
        let mut s = PeerStatus::default();
        let long = "x".repeat(1000);
        s.set_err_message(&long);
        let got = s.last_err_message.expect("some");
        assert!(got.ends_with('…'));
        assert!(got.chars().count() <= MAX_ERR_MESSAGE_LEN + 1);
    }

    #[test]
    fn truncation_respects_utf8_char_boundary() {
        let mut s = PeerStatus::default();
        // A multi-byte glyph straddling the cut point must not panic.
        let mut input = "a".repeat(MAX_ERR_MESSAGE_LEN - 1);
        input.push('é'); // 2 bytes, straddles MAX
        input.push_str(&"b".repeat(10));
        s.set_err_message(&input);
        assert!(s.last_err_message.is_some());
    }
}
