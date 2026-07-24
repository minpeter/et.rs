#![forbid(unsafe_code)]

//! Command-line argument and host-string parsing for et.rs.
//!
//! Two host-string grammars exist, matching upstream exactly:
//! - [`parse_host_string`]: the *jumphost* grammar, bracket IPv6 notation.
//! - [`parse_positional_host`]: the `et` client positional grammar, which
//!   counts colons to disambiguate bare (unbracketed) IPv6 from a trailing port.

pub mod client;
pub mod host;
pub mod server;
