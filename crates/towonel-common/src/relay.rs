use std::str::FromStr;

use anyhow::Context;
use iroh::{RelayConfig, RelayMap, RelayMode, RelayUrl};

pub const RELAY_URLS_ENV: &str = "TOWONEL_IROH_RELAY_URLS";

pub fn relay_mode_from_env() -> anyhow::Result<RelayMode> {
    match std::env::var(RELAY_URLS_ENV) {
        Ok(v) => {
            if let Some(mode) = parse_relay_urls(&v)? {
                return Ok(mode);
            }
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(e) => return Err(e).with_context(|| format!("reading ${RELAY_URLS_ENV}")),
    }
    Ok(default_relay_mode())
}

fn default_relay_mode() -> RelayMode {
    let primary =
        RelayUrl::from_str("https://relay.towonel.erwanleboucher.dev/").expect("static URL");
    RelayMode::Custom(RelayMap::from_iter([
        RelayConfig::from(primary),
        iroh::defaults::prod::default_eu_relay(),
    ]))
}

fn parse_relay_urls(raw: &str) -> anyhow::Result<Option<RelayMode>> {
    let configs: Vec<RelayConfig> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            RelayUrl::from_str(s)
                .map(RelayConfig::from)
                .with_context(|| format!("invalid relay URL in ${RELAY_URLS_ENV}: {s:?}"))
        })
        .collect::<anyhow::Result<_>>()?;

    if configs.is_empty() {
        return Ok(None);
    }

    Ok(Some(RelayMode::Custom(RelayMap::from_iter(configs))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        assert!(matches!(parse_relay_urls(""), Ok(None)));
        assert!(matches!(parse_relay_urls(" , ,"), Ok(None)));
    }

    #[test]
    fn single_url_parses() {
        let mode = parse_relay_urls("https://euc1-1.relay.n0.iroh-canary.iroh.link/")
            .expect("parse")
            .expect("Some");
        assert!(matches!(mode, RelayMode::Custom(_)));
    }

    #[test]
    fn comma_list_parses() {
        let mode = parse_relay_urls(
            "https://euc1-1.relay.n0.iroh-canary.iroh.link/, https://euw1-1.example.test/",
        )
        .expect("parse")
        .expect("Some");
        assert!(matches!(mode, RelayMode::Custom(_)));
    }

    #[test]
    fn invalid_url_errors() {
        parse_relay_urls("not a url").unwrap_err();
    }
}
