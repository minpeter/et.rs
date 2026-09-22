//! Opt-in remote close when the local terminal hangs up (#837 / #707).
//!
//! Unix installs a `SIGHUP` flag. The client loop writes one `TERMINAL_CLOSE`
//! packet and then exits. The server delivers that marker to the matching
//! session and ends only that bridge.
//!
//! Windows has no `SIGHUP`. Closing a console window is delivered as
//! `CTRL_CLOSE_EVENT`, which needs `SetConsoleCtrlHandler`. This crate forbids
//! `unsafe`, and no existing dependency exposes that event without a callback
//! in our code, so the Windows loop only observes the same flag. ConPTY
//! sessions still honor a `TERMINAL_CLOSE` marker when a client sends one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use et_core::proto::TerminalPacketType;
use et_net::connection::Connection;

#[cfg(unix)]
use crate::error::ClientError;

fn shared() -> Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

pub fn pending() -> bool {
    shared().load(Ordering::Acquire)
}

/// Install the Unix hangup handler. The flag starts clear.
#[cfg(unix)]
pub fn install_sighup() -> Result<(), ClientError> {
    signal_hook::flag::register(signal_hook::consts::SIGHUP, shared()).map_err(|error| {
        crate::client_terminal::terminal_io("installing SIGHUP close handler", error)
    })?;
    Ok(())
}

/// Write `TERMINAL_CLOSE` once and report that the client loop should exit.
pub fn take_terminal_close(connection: &mut Connection) -> bool {
    if !shared().swap(false, Ordering::AcqRel) {
        return false;
    }
    let _ = connection.write_packet(TerminalPacketType::TerminalClose as u8, &[]);
    true
}
