//! Dead-link detection for the client session loops.
//!
//! Upstream `TerminalClient::run` keeps one keep-alive deadline and a
//! `waitingOnKeepalive` flag: when the deadline passes it writes an empty
//! `KEEP_ALIVE` and marks it outstanding; when the deadline passes again with
//! the probe still outstanding, it closes the socket and reconnects.
//! Upstream compares whole seconds strictly (`keepaliveTime < time(NULL)`,
//! `TerminalClient.cpp:687-688`), so each step fires on the first second
//! tick after the interval has passed: an idle upstream client probes every
//! interval + 1 s (6 s by default) and declares the link dead after two such
//! steps (12 s).
//!
//! This clock probes on upstream's cadence, interval + 1 s after the last
//! packet read, but keeps the verdict two intervals after it (10 s by
//! default), so the reply gets the rest of the second interval. The probe is
//! pulled earlier when that would leave the reply less than a second, which
//! keeps `--keepalive 1` probing every second as before. Two more
//! differences:
//!
//! - Any packet read is a sign of life: it clears an outstanding probe and
//!   restarts the interval. Upstream restarts the interval on terminal and
//!   forwarding packets read and clears the flag only on a keep-alive reply.
//! - Writing never moves the deadline. Upstream restarts the interval on
//!   every terminal or forwarding packet written, so typing into a dead link
//!   postpones the probe, and the verdict once a probe is outstanding, for as
//!   long as the typing goes on. A write proves nothing about the way back.
//!
//! As before, no verdict is taken while the loop is not reading the
//! transport (console output backpressure): the reply may be waiting unread.
//! The state lives in [`Cell`]s so the loop's reconnect callback can restart
//! the clock on a recovered transport while the loop holds it.

use std::cell::Cell;
use std::time::{Duration, Instant};

/// How much later than the interval upstream's whole-second comparison
/// sends its probe on an idle link.
const PROBE_LAG: Duration = Duration::from_secs(1);

/// The shortest time a probe gets for its reply when the probe is lagged.
const MIN_REPLY_WINDOW: Duration = Duration::from_secs(1);

pub(crate) struct KeepaliveClock {
    /// Quiet time after the last packet read before the probe goes out.
    probe_after: Duration,
    /// Time an outstanding probe gets for its reply: the verdict lands two
    /// intervals after the last packet read when the probe left on time.
    reply_window: Duration,
    /// When the next probe is due, or with a probe outstanding, when the
    /// link is declared dead.
    deadline: Cell<Instant>,
    probe_outstanding: Cell<bool>,
}

impl KeepaliveClock {
    pub(crate) fn new(interval: Duration, now: Instant) -> Self {
        let verdict = interval * 2;
        let probe_after = (interval + PROBE_LAG)
            .min(verdict.saturating_sub(MIN_REPLY_WINDOW))
            .max(interval);
        Self {
            probe_after,
            reply_window: verdict - probe_after,
            deadline: Cell::new(now + probe_after),
            probe_outstanding: Cell::new(false),
        }
    }

    /// A packet was read, or a recovered transport was installed.
    pub(crate) fn alive(&self, now: Instant) {
        self.deadline.set(now + self.probe_after);
        self.probe_outstanding.set(false);
    }

    /// A probe keep-alive was written at `now`.
    pub(crate) fn probe_sent(&self, now: Instant) {
        self.deadline.set(now + self.reply_window);
        self.probe_outstanding.set(true);
    }

    /// Whether a probe keep-alive is due.
    pub(crate) fn probe_due(&self, now: Instant) -> bool {
        !self.probe_outstanding.get() && now >= self.deadline.get()
    }

    /// Whether the link is dead: a probe stayed unanswered for its whole
    /// reply window while the loop was `reading` the transport.
    pub(crate) fn dead(&self, now: Instant, reading: bool) -> bool {
        reading && self.probe_outstanding.get() && now >= self.deadline.get()
    }

    /// When the loop must wake for this clock: for the verdict while
    /// `reading`, or for the next probe when it `can_probe` (no write is
    /// pending). `None` when nothing can happen until that changes. The
    /// Windows loop polls on a fixed cadence instead.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn wake_at(&self, reading: bool, can_probe: bool) -> Option<Instant> {
        let armed = if self.probe_outstanding.get() {
            reading
        } else {
            can_probe
        };
        armed.then(|| self.deadline.get())
    }
}

#[cfg(test)]
#[path = "keepalive_clock_tests.rs"]
mod tests;
