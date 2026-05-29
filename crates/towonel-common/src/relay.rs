use std::net::SocketAddr;

use iroh::{RelayMap, RelayMode, RelayUrl};
use tracing::warn;

/// On parse error, warns and falls back to `Disabled` so the binary still starts.
#[must_use]
pub fn relay_mode_from_env(var_name: &str) -> RelayMode {
    std::env::var(var_name)
        .ok()
        .as_deref()
        .map_or(RelayMode::Disabled, |url| {
            relay_mode_from_url(url, var_name)
        })
}

/// `source` is a label used in the warning log on parse failure.
#[must_use]
pub fn relay_mode_from_url(url: &str, source: &str) -> RelayMode {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return RelayMode::Disabled;
    }
    match RelayMap::try_from_iter([trimmed]) {
        Ok(map) => RelayMode::Custom(map),
        Err(e) => {
            warn!(source = source, url = trimmed, error = %e, "invalid relay URL; running without relay");
            RelayMode::Disabled
        }
    }
}

/// Parses a single relay URL, warning and returning `None` on failure.
/// `source` is a label used in the warning log on parse failure.
#[must_use]
pub fn relay_url_from_str(url: &str, source: &str) -> Option<RelayUrl> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<RelayUrl>() {
        Ok(relay) => Some(relay),
        Err(e) => {
            warn!(source = source, url = trimmed, error = %e, "invalid relay URL");
            None
        }
    }
}

// Unparsable entries are warned and skipped rather than failing startup.
#[must_use]
pub fn parse_extra_local_addrs(var_name: &str) -> Vec<SocketAddr> {
    let Ok(raw) = std::env::var(var_name) else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!(var = var_name, entry = s, error = %e, "skipping invalid socket address");
                None
            }
        })
        .collect()
}
