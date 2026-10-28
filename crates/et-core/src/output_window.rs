//! Server-side bound on terminal output a client has not acknowledged.
//!
//! A client whose console drains slower than the link stops reading its
//! socket while console output is pending, so the server's output waits in
//! the client's kernel receive queue. Linux autotunes that queue to several
//! MiB, and every keystroke echo waits behind all of it. Upstream
//! `TerminalServer` never gets there because its output loop runs near
//! 5 MB/s (`drainWriteBufferToClient` writes one 16 KiB `TERMINAL_BUFFER`
//! per writable check); et.rs keeps up with the link, so it holds queued
//! terminal output back once [`OutputWindow::window`] bytes of it are
//! written but not acknowledged. Held output stays in the session queue,
//! where Ctrl+C can still drop it. Other packets (keep-alive echoes, and
//! forwarded data, which has its own flow control) neither wait nor count.
//! Nothing on the wire changes: the bound only reads the delivery
//! acknowledgements an et.rs client already sends (see [`crate::keepalive`]).
//!
//! The window is one acknowledgement interval, [`ACK_INTERVAL_BYTES`],
//! plus room for the path: [`PIPE_GAIN`] times the bytes the client
//! acknowledges per round trip, and at least [`MIN_PIPE_BYTES`], as BBR
//! sizes its congestion window from a bandwidth-delay product. The rate is
//! the payload acknowledged over the span that delivery took to send and to
//! acknowledge, whichever is longer, so a burst of either cannot inflate it.
//! The round trip is seeded by the server ([`OutputWindow::seed_round_trip`],
//! the authentication handshake) and only lowered by the time from writing a
//! packet to its acknowledgement. Acknowledgement timing alone cannot tell
//! the path from the client's own backlog: a console-bound client
//! acknowledges a packet only after it waited in the receive queue, so those
//! samples would grow the window with the very queue it bounds. A
//! console-bound client therefore gets its consumption rate times the path
//! round trip, and a fast client on a long path gets the path's capacity.
//! Without a seed the window stays at its floor.
//!
//! The bound applies only to a client proven to acknowledge by volume, so it
//! cannot stall a peer that acknowledges less often:
//!
//! - Upstream C++ clients never acknowledge and are never bounded.
//! - The client must have read one of this server's acknowledgements: an
//!   et.rs client attaches its acknowledgement to a volume keep-alive only
//!   once it knows the server acknowledges.
//! - An acknowledgement must have left a whole window unacknowledged: only a
//!   client that acknowledges while it is still behind does that. et.rs
//!   clients before 0.0.36 acknowledge only when idle or drained.
//!
//! Once bounded, a reading client unblocks the window itself: it
//! acknowledges at least every [`ACK_INTERVAL_BYTES`] of payload read, and
//! the window is larger than that, so a client that read everything has
//! always acknowledged enough to reopen it. The bound counts payload bytes,
//! as the client does, so small packets cannot outgrow its count. As in the
//! client's upload gate, an acknowledgement that stays put for
//! [`PATIENCE`] while output is held releases the bound until an
//! acknowledgement beyond it arrives, so a foreign or lost acknowledgement
//! can never wedge output. A new transport starts unbounded until its first
//! acknowledgement and with a fresh path estimate.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::crypto::MAC_LEN;
use crate::keepalive::ACK_INTERVAL_BYTES;

/// Smallest room for the path, on top of the acknowledgement interval.
///
/// The client's receive queue holds at most the window, and a keystroke echo
/// waits behind it. With a 1 MiB window a `yes` flood on a local link keeps
/// that queue at 0.2 to 0.9 MB (echo p95 about 10 ms) where it used to grow
/// to 4 to 6 MB in a third of sessions; a 256 KiB pipe measured the same and
/// left no Ctrl+C gain on a 10 Mbit/s link, so the floor keeps twice the
/// acknowledgement interval of margin.
pub const MIN_PIPE_BYTES: u64 = 512 * 1024;
/// Room for the path as a multiple of the measured bandwidth-delay
/// product, BBR's congestion-window gain: the estimate lags a growing rate
/// and acknowledgements arrive in steps.
pub const PIPE_GAIN: u64 = 2;
/// Upper bound on the window. 16 MiB covers 1 Gbit/s at a 130 ms round
/// trip; the 1 MiB transport send buffer limits throughput long before.
pub const MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
/// How long held output waits on an acknowledgement that does not advance
/// before the bound releases. An et.rs client acknowledges what it read at
/// its next keep-alive probe, at most one maximum keep-alive interval plus
/// a second after its last read (6 s); waiting for two intervals means the
/// client is not reading, or its acknowledgements refer to something else.
pub const PATIENCE: Duration = Duration::from_secs(10);
/// Framing around each packet's payload in the writer's byte count: the
/// header and encryption flag, and the authentication tag.
const PACKET_OVERHEAD: i64 = 2 + MAC_LEN as i64;
/// Payload between write timestamps; one merged terminal packet. Terminal
/// bytes acknowledged are known to this granularity.
const MARK_SPACING: u64 = 16 * 1024;
/// Write timestamps per window, so their spacing grows with the window.
const MARKS_PER_WINDOW: u64 = 64;
/// Write timestamps kept; older ones only lose their round-trip sample.
const MAX_MARKS: usize = 256;
/// Recent bandwidth-delay samples; the window follows their maximum.
const PIPE_SAMPLES: usize = 8;

/// A timestamped write and the delivery state when it was written.
#[derive(Clone, Copy, Debug)]
struct Mark {
    sequence: i64,
    sent: Instant,
    /// Terminal payload written through this packet.
    terminal: u64,
    /// Payload acknowledged before this write, and when.
    delivered: u64,
    delivered_at: Instant,
    /// When the newest acknowledged write was sent, as of this write.
    first_sent: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct OutputWindow {
    marks: VecDeque<Mark>,
    since_mark: u64,
    /// Payload written, counted like the writer's unacknowledged bytes.
    written: u64,
    /// Payload acknowledged as of the latest acknowledgement.
    delivered: u64,
    /// Terminal output written, and acknowledged as far as the write
    /// timestamps tell.
    terminal_written: u64,
    terminal_delivered: u64,
    delivered_at: Option<Instant>,
    delivered_sent: Option<Instant>,
    min_rtt: Option<Duration>,
    pipe: [u64; PIPE_SAMPLES],
    next_pipe: usize,
    /// Sequence of the first keep-alive on this transport that carried this
    /// side's acknowledgement.
    ack_written: Option<i64>,
    /// The client has read one of this side's acknowledgements.
    peer_reads_acks: bool,
    /// The client acknowledged while a whole window was outstanding.
    armed: bool,
    /// An acknowledgement arrived on the current transport.
    acknowledged_here: bool,
    stalled: Option<(i64, Instant)>,
    released: Option<i64>,
}

impl OutputWindow {
    /// The state for a recovered transport of the same session: proof that
    /// the client acknowledges by volume carries over, the path estimate and
    /// any stall do not.
    pub fn for_new_transport(&self) -> Self {
        Self {
            written: self.written,
            delivered: self.delivered,
            terminal_written: self.terminal_written,
            terminal_delivered: self.terminal_delivered,
            peer_reads_acks: self.peer_reads_acks,
            armed: self.armed,
            ..Self::default()
        }
    }

    /// A clean round trip of this transport, measured outside the output
    /// stream (the server's authentication challenge and its reply).
    pub fn seed_round_trip(&mut self, rtt: Duration) {
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |min_rtt| min_rtt.min(rtt)));
    }

    /// Record a packet the writer committed as `sequence`; `terminal` for
    /// terminal output, `carries_ack` for a keep-alive carrying this side's
    /// acknowledgement.
    pub fn on_write(
        &mut self,
        sequence: i64,
        payload_len: usize,
        terminal: bool,
        carries_ack: bool,
        now: Instant,
    ) {
        let length = payload_len as u64;
        self.written = self.written.saturating_add(length);
        if terminal {
            self.terminal_written = self.terminal_written.saturating_add(length);
        }
        if carries_ack && self.ack_written.is_none() {
            self.ack_written = Some(sequence);
        }
        // A peer that never acknowledges (upstream C++) costs no timestamps.
        if !self.acknowledged_here {
            return;
        }
        let spacing = (self.window() / MARKS_PER_WINDOW).max(MARK_SPACING);
        if self.marks.is_empty() || self.since_mark >= spacing {
            if self.marks.len() == MAX_MARKS {
                self.marks.pop_front();
            }
            self.marks.push_back(Mark {
                sequence,
                sent: now,
                terminal: self.terminal_written,
                delivered: self.delivered,
                delivered_at: self.delivered_at.unwrap_or(now),
                first_sent: self.delivered_sent.unwrap_or(now),
            });
            self.since_mark = 0;
        }
        self.since_mark = self.since_mark.saturating_add(length);
    }

    /// Record an acknowledgement the writer accepted: the client read
    /// through `acknowledged`, leaving `unacknowledged` payload bytes.
    pub fn on_ack(&mut self, acknowledged: i64, unacknowledged: u64, now: Instant) {
        let delivered = self.written.saturating_sub(unacknowledged);
        let mut newest = None;
        while let Some(mark) = self.marks.front() {
            if mark.sequence > acknowledged {
                break;
            }
            newest = self.marks.pop_front();
        }
        if self.marks.is_empty() && self.marks.capacity() > MAX_MARKS / 4 {
            self.marks.shrink_to_fit();
        }
        if let (Some(mark), Some(seeded)) = (newest, self.min_rtt) {
            // Later than the seed whenever the packet waited in the client's
            // queue; earlier only when the seed itself was slow.
            let min_rtt = seeded.min(now.saturating_duration_since(mark.sent));
            self.min_rtt = Some(min_rtt);
            // A delivery cannot be faster than it was sent, nor than it was
            // acknowledged: the larger span drops bursts of either.
            let span = now
                .saturating_duration_since(mark.delivered_at)
                .max(mark.sent.saturating_duration_since(mark.first_sent));
            let bytes = delivered.saturating_sub(mark.delivered);
            if !span.is_zero() {
                let sample = u128::from(bytes) * min_rtt.as_nanos() / span.as_nanos();
                self.pipe[self.next_pipe] = u64::try_from(sample).unwrap_or(u64::MAX);
                self.next_pipe = (self.next_pipe + 1) % PIPE_SAMPLES;
            }
        }
        if let Some(mark) = newest {
            self.terminal_delivered = self.terminal_delivered.max(mark.terminal);
            self.delivered_sent = Some(mark.sent);
        }
        if delivered > self.delivered || self.delivered_at.is_none() {
            self.delivered = self.delivered.max(delivered);
            self.delivered_at = Some(now);
        }
        self.acknowledged_here = true;
        if self
            .ack_written
            .is_some_and(|sequence| acknowledged >= sequence)
        {
            self.peer_reads_acks = true;
        }
        if self.peer_reads_acks && self.unacknowledged_terminal(unacknowledged) >= self.window() {
            self.armed = true;
        }
    }

    /// Terminal payload bytes that hold terminal output back.
    pub fn window(&self) -> u64 {
        let pipe = self.pipe.iter().copied().max().unwrap_or(0);
        let pipe = pipe.saturating_mul(PIPE_GAIN).max(MIN_PIPE_BYTES);
        (ACK_INTERVAL_BYTES as u64)
            .saturating_add(pipe)
            .min(MAX_WINDOW_BYTES)
    }

    /// Terminal output not yet acknowledged, as far as the write timestamps
    /// tell, and never more than all `unacknowledged` payload: other
    /// packets (forwarded data has its own flow control) do not hold it
    /// back.
    fn unacknowledged_terminal(&self, unacknowledged: u64) -> u64 {
        self.terminal_written
            .saturating_sub(self.terminal_delivered)
            .min(unacknowledged)
    }

    /// Whether terminal output must wait for an acknowledgement: `Some`
    /// with the time the bound releases unless the acknowledgement
    /// advances first, `None` while output may go out.
    pub fn blocked(
        &mut self,
        acknowledged: i64,
        unacknowledged: u64,
        now: Instant,
    ) -> Option<Instant> {
        if !self.armed || !self.acknowledged_here {
            self.stalled = None;
            return None;
        }
        if let Some(released) = self.released {
            if acknowledged <= released {
                return None;
            }
            self.released = None;
        }
        if self.unacknowledged_terminal(unacknowledged) < self.window() {
            self.stalled = None;
            return None;
        }
        let since = match self.stalled {
            Some((seen, since)) if seen == acknowledged => {
                if now.saturating_duration_since(since) >= PATIENCE {
                    self.released = Some(acknowledged);
                    self.stalled = None;
                    return None;
                }
                since
            }
            _ => {
                self.stalled = Some((acknowledged, now));
                now
            }
        };
        Some(since + PATIENCE)
    }
}

/// Payload bytes behind a writer's delivery backlog: `unacknowledged_wire`
/// bytes in the packets after `acknowledged`, up to `sequence`.
pub fn unacknowledged_payload(acknowledged: i64, unacknowledged_wire: i64, sequence: i64) -> u64 {
    let packets = sequence.saturating_sub(acknowledged).max(0);
    let payload = unacknowledged_wire.saturating_sub(packets.saturating_mul(PACKET_OVERHEAD));
    u64::try_from(payload).unwrap_or(0)
}

#[cfg(test)]
#[path = "output_window_tests.rs"]
mod tests;
