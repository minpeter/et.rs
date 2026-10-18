//! Client-side bound on data written but not yet acknowledged by the server.
//!
//! The replay backup must hold every frame the server has not read. Kernel
//! socket buffers autotune far past the connected backup cap on fast links,
//! so without a bound a multi-tunnel upload pins the whole cap and can even
//! trim frames a recovery would still request. Once the server has proven it
//! acknowledges delivery (an et.rs keep-alive payload, see
//! [`et_core::keepalive`]), the client pauses its producers (stdin, forwarded
//! sockets) while [`MAX_UNACKNOWLEDGED_BYTES`] are outstanding; the data waits
//! in the producers' own kernel buffers instead of the replay heap. Upstream
//! C++ and legacy servers never acknowledge, so they are never gated.
//!
//! A client keep-alive goes out after every
//! [`et_core::keepalive::ACK_INTERVAL_BYTES`] written and the server echoes
//! each one with its reader sequence, so a gated client is released as soon
//! as the server reads its most recent keep-alive. If an acknowledgement
//! stops advancing for a whole keep-alive interval while gated (a relay
//! delivering another hop's sequence, or a stalled link), the gate turns
//! itself off for the rest of the session so it can never wedge forwarding.

use std::time::{Duration, Instant};

use et_core::backed_writer::MAX_UNACKNOWLEDGED_BYTES;
use et_net::connection::Connection;

#[derive(Default)]
pub(crate) struct DeliveryGate {
    disabled: bool,
    /// Acknowledged sequence observed when the current gated stretch began.
    stalled: Option<(i64, Instant)>,
}

impl DeliveryGate {
    /// Whether producers must pause before writing more data.
    pub(crate) fn blocked(&mut self, connection: &Connection, patience: Duration) -> bool {
        if !connection.connected() {
            self.stalled = None;
            return false;
        }
        self.check(connection.delivery_backlog(), Instant::now(), patience)
    }

    fn check(&mut self, backlog: Option<(i64, i64)>, now: Instant, patience: Duration) -> bool {
        if self.disabled {
            return false;
        }
        let Some((acknowledged, unacknowledged)) = backlog else {
            return false;
        };
        if unacknowledged < MAX_UNACKNOWLEDGED_BYTES {
            self.stalled = None;
            return false;
        }
        match self.stalled {
            Some((seen, since)) if seen == acknowledged => {
                if now.saturating_duration_since(since) >= patience {
                    self.disabled = true;
                    self.stalled = None;
                    return false;
                }
            }
            _ => self.stalled = Some((acknowledged, now)),
        }
        true
    }
}

#[cfg(test)]
#[path = "delivery_gate_tests.rs"]
mod tests;
