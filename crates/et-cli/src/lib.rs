#![forbid(unsafe_code)]

//! Command-line argument and host-string parsing for et.rs.
//!
//! Two host-string grammars exist, matching upstream exactly:
//! - [`parse_host_string`]: the *jumphost* grammar, bracket IPv6 notation.
//! - [`parse_positional_host`]: the `et` client positional grammar, which
//!   counts colons to disambiguate bare (unbracketed) IPv6 from a trailing port.

/// Short version string (`-V`), byte-compatible with upstream's
/// `et version X.Y.Z` output that scripts may parse.
pub const VERSION: &str = concat!("version ", env!("CARGO_PKG_VERSION"));

/// Long version string (`--version`), identifying the et.rs port.
pub const LONG_VERSION: &str = concat!(
    "version ",
    env!("CARGO_PKG_VERSION"),
    " (et.rs)\nA Rust port of Eternal Terminal\nhttps://github.com/minpeter/et.rs"
);

pub mod client;
pub mod host;
pub mod logging;
pub mod server;
pub mod tunnel;
