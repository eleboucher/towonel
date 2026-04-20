pub mod auth;
pub mod config_entry;
pub mod hostname;
pub mod hub_error;
pub mod identity;
pub mod invite;
pub mod metrics;
pub mod ownership;
pub mod protocol;
pub mod random_name;
pub mod routing;
pub mod shutdown;
pub mod sni;
pub mod time;
pub mod tls_policy;
pub mod tunnel;

/// Standard CBOR content type used across all crates.
pub const CBOR_CONTENT_TYPE: &str = "application/cbor";

/// Standard JSON content type with charset, used by the hub API.
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// Plain JSON content type without charset, used by CLI/agents.
pub const JSON_CONTENT_TYPE_PLAIN: &str = "application/json";
