//! [`signature`] is `Authorization: Signature …` verification for inter-node
//! requests; [`password`] + [`session`] are the user-account primitives the
//! web routes use when `TOWONEL_HUB_WEB_ENABLED` is on.

pub mod password;
pub mod session;
pub mod signature;

pub use signature::verify_signature_header;
