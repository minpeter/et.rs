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
//! as the server reads its most recent keep-alive. If the acknowledgement
//! stops advancing for a whole patience window while gated (a relay
//! delivering another hop's sequence, a saturated reverse direction, or a
//! stalled link), the gate releases producers so it can never wedge
//! forwarding. The release is not permanent: once an acknowledgement beyond
//! the one seen at release arrives, the gate re-arms and the bound applies
//! again, starting a fresh patience window if the backlog is still full. A
//! disconnect clears all stall state; the next connection is gated only
//! after its server acknowledges again.

use std::time::{Duration, Instant};

use et_core::backed_writer::MAX_UNACKNOWLEDGED_BYTES;
use et_net::connection::Connection;

#[derive(Default)]
pub(crate) struct DeliveryGate {
    /// Acknowledged sequence observed when the current gated stretch began.
    stalled: Option<(i64, Instant)>,
    /// Acknowledged sequence at which a stall released the gate; the gate
    /// stays open until an acknowledgement beyond it arrives.
    released: Option<i64>,
}

impl DeliveryGate {
    /// Whether producers must pause before writing more data.
    pub(crate) fn blocked(&mut self, connection: &Connection, patience: Duration) -> bool {
        self.observe(
            connection.connected(),
            connection.delivery_backlog(),
            Instant::now(),
            patience,
        )
    }

    /// When a stalled gate releases its producers unless acknowledgements
    /// advance first; the session loop must wake by then.
    #[cfg(unix)]
    pub(crate) fn release_at(&self, patience: Duration) -> Option<Instant> {
        self.stalled.map(|(_, since)| since + patience)
    }

    fn observe(
        &mut self,
        connected: bool,
        backlog: Option<(i64, i64)>,
        now: Instant,
        patience: Duration,
    ) -> bool {
        if !connected {
            self.stalled = None;
            self.released = None;
            return false;
        }
        self.check(backlog, now, patience)
    }

    fn check(&mut self, backlog: Option<(i64, i64)>, now: Instant, patience: Duration) -> bool {
        let Some((acknowledged, unacknowledged)) = backlog else {
            return false;
        };
        if let Some(released_at) = self.released {
            if acknowledged <= released_at {
                return false;
            }
            self.released = None;
        }
        if unacknowledged < MAX_UNACKNOWLEDGED_BYTES {
            self.stalled = None;
            return false;
        }
        match self.stalled {
            Some((seen, since)) if seen == acknowledged => {
                if now.saturating_duration_since(since) >= patience {
                    self.released = Some(acknowledged);
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
