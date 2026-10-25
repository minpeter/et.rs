use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::*;

const PACKET: u64 = 16 * 1024;
const ACK_INTERVAL: u64 = ACK_INTERVAL_BYTES as u64;

/// Write `count` terminal packets after `sequence`.
fn write(window: &mut OutputWindow, sequence: &mut i64, count: usize, now: Instant) {
    for _ in 0..count {
        *sequence += 1;
        window.on_write(*sequence, PACKET as usize, true, false, now);
    }
}

/// Write `count` forwarded-data packets after `sequence`.
fn forward(window: &mut OutputWindow, sequence: &mut i64, count: usize, now: Instant) {
    for _ in 0..count {
        *sequence += 1;
        window.on_write(*sequence, PACKET as usize, false, false, now);
    }
}

/// A window whose client has read this side's acknowledgement (written as
/// sequence 1) and then acknowledged while a whole window was outstanding.
fn armed(now: Instant) -> (OutputWindow, i64) {
    let mut window = OutputWindow::default();
    window.on_write(1, 8, false, true, now);
    let mut sequence = 1;
    let outstanding = (window.window() / PACKET) as usize + 1;
    write(&mut window, &mut sequence, outstanding + 1, now);
    window.on_ack(2, unacked(sequence, 2), now);
    assert!(window.armed);
    (window, sequence)
}

fn unacked(sequence: i64, acknowledged: i64) -> u64 {
    (sequence - acknowledged) as u64 * PACKET
}

#[test]
fn a_peer_that_never_acknowledges_is_never_bounded() {
    let now = Instant::now();
    let mut window = OutputWindow::default();
    let mut sequence = 0;
    write(&mut window, &mut sequence, 4096, now);
    assert_eq!(window.blocked(0, unacked(sequence, 0), now), None);
}

#[test]
fn acknowledgements_sent_before_the_client_read_ours_do_not_bound() {
    // A client attaches its acknowledgement to a volume keep-alive only once
    // it knows the server acknowledges, so the bound would wait on a
    // keep-alive probe.
    let now = Instant::now();
    let mut window = OutputWindow::default();
    let mut sequence = 0;
    write(&mut window, &mut sequence, 256, now);
    window.on_ack(1, unacked(sequence, 1), now);
    window.on_write(sequence + 1, 8, false, true, now);
    sequence += 1;
    write(&mut window, &mut sequence, 256, now);
    window.on_ack(2, unacked(sequence, 2), now);
    assert!(!window.armed);
    assert_eq!(window.blocked(2, unacked(sequence, 2), now), None);
}

#[test]
fn a_client_acknowledging_while_behind_is_bounded_at_the_window() {
    let now = Instant::now();
    let (mut window, sequence) = armed(now);
    let limit = window.window();
    assert_eq!(limit, ACK_INTERVAL + MIN_PIPE_BYTES);
    assert_eq!(window.blocked(2, limit, now), Some(now + PATIENCE));
    // Held output waits only while a whole window is outstanding.
    window.on_ack(sequence - 1, PACKET, now);
    assert_eq!(window.blocked(sequence - 1, PACKET, now), None);
    assert_eq!(window.blocked(sequence - 1, limit - 1, now), None);
}

#[test]
fn a_client_that_acknowledges_only_when_drained_stays_unbounded() {
    // et.rs before 0.0.36 acknowledges when idle or after draining its
    // socket, never while a window is still on its way.
    let now = Instant::now();
    let mut window = OutputWindow::default();
    window.on_write(1, 8, false, true, now);
    let mut sequence = 1;
    for _ in 0..8 {
        write(&mut window, &mut sequence, 128, now);
        window.on_ack(sequence - 2, unacked(sequence, sequence - 2), now);
    }
    assert!(window.peer_reads_acks);
    assert!(!window.armed);
    write(&mut window, &mut sequence, 4096, now);
    assert_eq!(window.blocked(sequence - 4096, unacked(4096, 0), now), None);
}

#[test]
fn forwarded_data_does_not_hold_terminal_output() {
    // Given: a bounded client that acknowledged all terminal output.
    let now = Instant::now();
    let (mut window, mut sequence) = armed(now);
    write(&mut window, &mut sequence, 1, now);
    window.on_ack(sequence, 0, now);
    let acknowledged = sequence;
    // When: a download through a forwarded port leaves several windows
    // unacknowledged.
    forward(&mut window, &mut sequence, 256, now);
    let behind = unacked(sequence, acknowledged);
    // Then: terminal output still goes out, until terminal output itself
    // fills the window.
    assert_eq!(window.blocked(acknowledged, behind, now), None);
    let fill = (window.window() / PACKET) as usize;
    write(&mut window, &mut sequence, fill, now);
    let behind = unacked(sequence, acknowledged);
    assert!(window.blocked(acknowledged, behind, now).is_some());
}

#[test]
fn a_stalled_acknowledgement_releases_until_it_advances() {
    let start = Instant::now();
    let (mut window, sequence) = armed(start);
    let held = unacked(sequence, 2);
    assert_eq!(window.blocked(2, held, start), Some(start + PATIENCE));
    let later = start + PATIENCE / 2;
    assert_eq!(window.blocked(2, held, later), Some(start + PATIENCE));
    let expired = start + PATIENCE;
    assert_eq!(window.blocked(2, held, expired), None);
    // Released: more output goes out while the acknowledgement stays put.
    assert_eq!(window.blocked(2, held * 4, expired), None);
    // An advancing acknowledgement re-arms the bound and a fresh patience.
    window.on_ack(3, held * 4, expired);
    assert_eq!(
        window.blocked(3, held * 4, expired),
        Some(expired + PATIENCE)
    );
}

#[test]
fn an_advancing_acknowledgement_restarts_the_patience() {
    let start = Instant::now();
    let (mut window, sequence) = armed(start);
    let held = unacked(sequence, 2);
    assert!(window.blocked(2, held, start).is_some());
    let later = start + PATIENCE - Duration::from_millis(1);
    window.on_ack(3, held, later);
    assert_eq!(window.blocked(3, held, later), Some(later + PATIENCE));
    assert!(window.blocked(3, held, start + PATIENCE).is_some());
}

#[test]
fn a_new_transport_is_unbounded_until_its_first_acknowledgement() {
    let now = Instant::now();
    let (window, sequence) = armed(now);
    let mut recovered = window.for_new_transport();
    let held = unacked(sequence, 2);
    // The client reads the replay and acknowledges by volume; until then
    // the previous transport's backlog must not hold output.
    assert_eq!(recovered.blocked(2, held, now), None);
    recovered.on_ack(3, held, now);
    assert!(recovered.blocked(3, held, now).is_some());
}

#[test]
fn payload_excludes_framing() {
    let wire = 10 * (100 + PACKET_OVERHEAD);
    assert_eq!(unacknowledged_payload(5, wire, 15), 1000);
    assert_eq!(unacknowledged_payload(5, 0, 15), 0);
}

#[test]
fn the_window_always_exceeds_the_acknowledgement_interval() {
    // A client that read everything has at most one interval unacknowledged,
    // so it can always reopen the window.
    let window = OutputWindow::default();
    assert!(window.window() > ACK_INTERVAL + PACKET);
    let saturated = OutputWindow {
        pipe: [u64::MAX; PIPE_SAMPLES],
        ..OutputWindow::default()
    };
    assert_eq!(saturated.window(), MAX_WINDOW_BYTES);
}

/// One server writing 16 KiB packets to one client through a link of
/// `link_rate` and `one_way` delay. The server writes while the link has
/// under 32 KiB unsent (`TCP_NOTSENT_LOWAT`), the client has under
/// `receive_limit` unread, and the window allows; the client reads at
/// `console_rate` and acknowledges every [`ACK_INTERVAL_BYTES`] it reads.
struct Link {
    window: OutputWindow,
    start: Instant,
    now: Duration,
    one_way: Duration,
    link_rate: u64,
    console_rate: Option<u64>,
    receive_limit: u64,
    sequence: i64,
    link_free: Duration,
    in_flight: VecDeque<(Duration, i64)>,
    received: VecDeque<i64>,
    read: i64,
    console_budget: u64,
    since_ack: u64,
    acks: VecDeque<(Duration, i64)>,
    acknowledged: i64,
    read_bytes: u64,
    max_unread_bounded: u64,
}

impl Link {
    fn new(
        one_way: Duration,
        link_rate: u64,
        console_rate: Option<u64>,
        receive_limit: u64,
    ) -> Self {
        let mut window = OutputWindow::default();
        window.seed_round_trip(one_way * 2);
        Self {
            window,
            start: Instant::now(),
            now: Duration::ZERO,
            one_way,
            link_rate,
            console_rate,
            receive_limit,
            sequence: 0,
            link_free: Duration::ZERO,
            in_flight: VecDeque::new(),
            received: VecDeque::new(),
            read: 0,
            console_budget: 0,
            since_ack: 0,
            acks: VecDeque::new(),
            acknowledged: 0,
            read_bytes: 0,
            max_unread_bounded: 0,
        }
    }

    fn run(&mut self, step: Duration, until: Duration) {
        while self.now < until {
            self.now += step;
            let now = self.start + self.now;
            while self
                .in_flight
                .front()
                .is_some_and(|(at, _)| *at <= self.now)
            {
                let (_, sequence) = self.in_flight.pop_front().unwrap();
                self.received.push_back(sequence);
            }
            let budget = self.console_rate.map_or(u64::MAX, |rate| {
                (u128::from(rate) * step.as_nanos() / 1_000_000_000) as u64
            });
            self.console_budget = self
                .console_budget
                .saturating_add(budget)
                .min(budget.saturating_add(PACKET));
            while self.console_budget >= PACKET {
                let Some(sequence) = self.received.pop_front() else {
                    self.console_budget = self.console_budget.min(PACKET);
                    break;
                };
                self.console_budget -= PACKET;
                self.read = sequence;
                self.read_bytes += PACKET;
                self.since_ack += PACKET;
                if self.since_ack >= ACK_INTERVAL {
                    self.since_ack = 0;
                    self.acks.push_back((self.now + self.one_way, self.read));
                }
            }
            while self.acks.front().is_some_and(|(at, _)| *at <= self.now) {
                let (_, sequence) = self.acks.pop_front().unwrap();
                self.acknowledged = sequence;
                let behind = unacked(self.sequence, sequence);
                self.window.on_ack(sequence, behind, now);
            }
            let unsent_limit = Duration::from_nanos(32 * 1024 * 1_000_000_000 / self.link_rate);
            while self.link_free.saturating_sub(self.now) < unsent_limit
                && unacked(self.sequence, self.read) < self.receive_limit
                && self
                    .window
                    .blocked(
                        self.acknowledged,
                        unacked(self.sequence, self.acknowledged),
                        now,
                    )
                    .is_none()
            {
                self.sequence += 1;
                self.window.on_write(
                    self.sequence,
                    PACKET as usize,
                    true,
                    self.sequence == 1,
                    now,
                );
                let serialize = Duration::from_nanos(PACKET * 1_000_000_000 / self.link_rate);
                self.link_free = self.link_free.max(self.now) + serialize;
                self.in_flight
                    .push_back((self.link_free + self.one_way, self.sequence));
            }
            if self.window.armed {
                let unread =
                    unacked(self.sequence, self.read) - self.in_flight.len() as u64 * PACKET;
                self.max_unread_bounded = self.max_unread_bounded.max(unread);
            }
        }
    }
}

#[test]
fn a_queued_client_cannot_grow_the_window_past_a_seeded_round_trip() {
    // Given: acknowledgements that each arrive 50 ms after their write, as
    // when every packet waits in a console-bound client's queue, on a path
    // whose handshake measured 100 us.
    let start = Instant::now();
    let mut window = OutputWindow::default();
    window.seed_round_trip(Duration::from_micros(100));
    let mut sequence = 0;
    for round in 0..64u32 {
        let now = start + Duration::from_millis(5) * round;
        write(&mut window, &mut sequence, 32, now);
        let acked = sequence - 32;
        if acked > 0 {
            let later = now + Duration::from_millis(50);
            window.on_ack(acked, unacked(sequence, acked), later);
        }
    }
    // Then: 100 MB/s over a 100 us path is far below the floor.
    assert_eq!(window.window(), ACK_INTERVAL + MIN_PIPE_BYTES);
    // Without the seed, the same timing would have looked like 5 MB in flight.
    let mut unseeded = OutputWindow::default();
    let mut sequence = 0;
    write(&mut unseeded, &mut sequence, 64, start);
    unseeded.on_ack(32, unacked(sequence, 32), start + Duration::from_millis(50));
    assert_eq!(unseeded.window(), ACK_INTERVAL + MIN_PIPE_BYTES);
}

#[test]
fn a_console_bound_client_keeps_a_short_queue_at_full_console_speed() {
    // Given: a loopback-like link and a console that drains 100 MB/s,
    // under a receive buffer that would otherwise grow to 8 MiB.
    let console = 100_000_000;
    let mut link = Link::new(
        Duration::from_micros(25),
        10_000_000_000,
        Some(console),
        8 * 1024 * 1024,
    );
    link.run(Duration::from_micros(10), Duration::from_millis(100));
    assert!(link.window.armed);
    // The receive buffer filled before the client proved it acknowledges
    // by volume; measure once that backlog drained.
    link.max_unread_bounded = 0;
    let read_before = link.read_bytes;
    link.run(Duration::from_micros(10), Duration::from_millis(400));
    // Then: the bound stays at its floor, the client's unread backlog stays
    // within it (not the 8 MiB the receive buffer allows), and the console
    // never waits for data.
    assert_eq!(link.window.window(), ACK_INTERVAL + MIN_PIPE_BYTES);
    let backlog = link.max_unread_bounded;
    assert!(
        backlog <= link.window.window() + PACKET,
        "backlog {backlog}"
    );
    let rate = (link.read_bytes - read_before) * 1000 / 300;
    assert!(rate >= console * 95 / 100, "console read {rate} B/s");
}

#[test]
fn a_long_fat_path_is_not_throttled() {
    // Given: 1 Gbit/s at a 100 ms round trip (12.5 MB in flight) and a
    // client that reads as fast as data arrives.
    let rate = 125_000_000;
    let mut link = Link::new(Duration::from_millis(50), rate, None, 64 * 1024 * 1024);
    link.run(Duration::from_micros(100), Duration::from_secs(2));
    assert!(link.window.armed);
    let read_before = link.read_bytes;
    link.run(Duration::from_micros(100), Duration::from_secs(3));
    // Then: the window covers the bandwidth-delay product and the link
    // stays full.
    let window = link.window.window();
    assert!(window >= 12_500_000, "window {window}");
    let delivered = link.read_bytes - read_before;
    assert!(delivered >= rate * 95 / 100, "delivered {delivered} B/s");
}

#[test]
fn a_slow_console_on_a_long_path_keeps_its_queue_near_the_path() {
    // Given: a 50 ms round trip carrying 14 MB/s and a console draining
    // 2 MB/s behind a 16 MiB receive buffer.
    let console = 2_000_000;
    let mut link = Link::new(
        Duration::from_millis(25),
        14_000_000,
        Some(console),
        16 * 1024 * 1024,
    );
    link.run(Duration::from_micros(100), Duration::from_secs(6));
    assert!(link.window.armed);
    link.max_unread_bounded = 0;
    let read_before = link.read_bytes;
    link.run(Duration::from_micros(100), Duration::from_secs(10));
    // Then: the backlog the console waits behind stays near the window
    // floor, and the console keeps its pace.
    let backlog = link.max_unread_bounded;
    assert!(
        backlog <= ACK_INTERVAL + MIN_PIPE_BYTES + PACKET,
        "backlog {backlog}"
    );
    let rate = (link.read_bytes - read_before) / 4;
    assert!(rate >= console * 95 / 100, "console read {rate} B/s");
}
