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

/// Accepts a comma-separated list of relay URLs. `source` is a label used in
/// the warning log on parse failure.
#[must_use]
pub fn relay_mode_from_url(url: &str, source: &str) -> RelayMode {
    let entries: Vec<&str> = url
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        return RelayMode::Disabled;
    }
    match RelayMap::try_from_iter(entries) {
        Ok(map) => RelayMode::Custom(map),
        Err(e) => {
            warn!(source = source, url = url, error = %e, "invalid relay URL(s); running without relay");
            RelayMode::Disabled
        }
    }
}

/// Parses a comma-separated list of relay URLs, warning and skipping any entry
/// that fails to parse. `source` is a label used in the warning log.
#[must_use]
pub fn relay_urls_from_str(url: &str, source: &str) -> Vec<RelayUrl> {
    url.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<RelayUrl>() {
            Ok(relay) => Some(relay),
            Err(e) => {
                warn!(source = source, url = s, error = %e, "invalid relay URL");
                None
            }
        })
        .collect()
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
