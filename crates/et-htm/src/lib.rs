#![forbid(unsafe_code)]

//! Headless terminal multiplexer (`htm` / `htmd`), ported from upstream
//! `src/htm/`.
//!
//! - [`codes`] and [`framing`] implement tmux extended control-mode framing.
//! - [`state`] owns server-assigned IDs, windows and pane screens.
//! - [`server`] is `htmd` (multiplexer daemon), [`client`] is `htm` (relay).

#[cfg(unix)]
pub mod client;
#[cfg(windows)]
#[path = "client_windows.rs"]
pub mod client;
pub mod codes;
pub mod control;
pub mod formats;
pub mod framing;
pub mod layout;
pub mod screen;
pub mod server;
pub mod state;
pub mod terminal_handler;

pub mod transport;
