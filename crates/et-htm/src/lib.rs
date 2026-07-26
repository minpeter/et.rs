#![forbid(unsafe_code)]

//! Headless terminal multiplexer (`htm` / `htmd`), ported from upstream
//! `src/htm/`.
//!
//! - [`codes`] and [`framing`] reproduce the HTM wire protocol byte for byte.
//! - [`state`] is the tabs/splits/panes model with upstream's JSON shape.
//! - [`server`] is `htmd` (multiplexer daemon), [`client`] is `htm` (relay).

pub mod client;
pub mod codes;
pub mod framing;
pub mod server;
pub mod state;
pub mod terminal_handler;
