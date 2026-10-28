use super::*;

const INTERVAL: Duration = Duration::from_secs(5);
/// Upstream's idle probe cadence for `INTERVAL`: one second tick later.
const PROBE: Duration = Duration::from_secs(6);

#[test]
fn an_unanswered_probe_declares_the_link_dead_two_intervals_after_the_last_read() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    assert!(!clock.probe_due(start + PROBE - Duration::from_millis(1)));
    assert_eq!(clock.wake_at(true, true), Some(start + PROBE));
    assert!(clock.probe_due(start + PROBE));
    assert!(!clock.dead(start + PROBE, true));
    clock.probe_sent(start + PROBE);
    // One probe at a time.
    assert!(!clock.probe_due(start + INTERVAL * 2));
    assert!(!clock.dead(start + INTERVAL * 2 - Duration::from_millis(1), true));
    assert_eq!(clock.wake_at(true, true), Some(start + INTERVAL * 2));
    // Two intervals after the last packet, not upstream's 12 s.
    assert!(clock.dead(start + INTERVAL * 2, true));
}

#[test]
fn an_idle_link_probes_on_upstreams_cadence() {
    // Upstream's `keepaliveTime < time(NULL)` sends an idle probe every
    // interval + 1 s; probing every interval cost 20% more keep-alive
    // exchanges on the wire.
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    let mut now = start;
    let mut probes = Vec::new();
    let end = start + Duration::from_secs(60);
    while now < end {
        if clock.probe_due(now) {
            probes.push(now - start);
            clock.probe_sent(now);
            // The echo arrives a millisecond later.
            now += Duration::from_millis(1);
            clock.alive(now);
        }
        now += Duration::from_millis(1);
    }
    assert_eq!(probes.len(), 9, "{probes:?}");
    for pair in probes.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= PROBE && gap < PROBE + Duration::from_millis(5),
            "{probes:?}"
        );
    }
}

#[test]
fn short_intervals_keep_a_second_for_the_reply() {
    let start = Instant::now();
    // `--keepalive 1`: probing later would leave the reply no time.
    let one = KeepaliveClock::new(Duration::from_secs(1), start);
    assert!(!one.probe_due(start + Duration::from_millis(999)));
    assert!(one.probe_due(start + Duration::from_secs(1)));
    one.probe_sent(start + Duration::from_secs(1));
    assert!(!one.dead(start + Duration::from_millis(1999), true));
    assert!(one.dead(start + Duration::from_secs(2), true));
    // `--keepalive 2`: the probe lags by the second, the reply keeps one.
    let two = KeepaliveClock::new(Duration::from_secs(2), start);
    assert!(!two.probe_due(start + Duration::from_millis(2999)));
    assert!(two.probe_due(start + Duration::from_secs(3)));
    two.probe_sent(start + Duration::from_secs(3));
    assert!(!two.dead(start + Duration::from_millis(3999), true));
    assert!(two.dead(start + Duration::from_secs(4), true));
}

#[test]
fn any_packet_read_answers_the_probe_and_restarts_the_interval() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + PROBE);
    let reply = start + PROBE + Duration::from_millis(1900);
    clock.alive(reply);
    assert!(!clock.dead(start + INTERVAL * 2, true));
    assert!(!clock.probe_due(reply + PROBE - Duration::from_millis(1)));
    assert!(clock.probe_due(reply + PROBE));
}

#[test]
fn no_verdict_while_the_transport_is_not_read() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + PROBE);
    let late = start + INTERVAL * 4;
    assert!(!clock.dead(late, false));
    // Nothing to wake for until reading resumes.
    assert_eq!(clock.wake_at(false, true), None);
    assert!(!clock.probe_due(late));
    // Probes still go out while output is held.
    let held = KeepaliveClock::new(INTERVAL, start);
    assert!(held.probe_due(start + PROBE));
    assert_eq!(held.wake_at(false, true), Some(start + PROBE));
    // Reading again: the verdict is due.
    assert!(clock.dead(late, true));
}

#[test]
fn a_pending_write_defers_the_probe_but_not_the_verdict() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    // No probe can start while a frame is pending: do not spin on it.
    assert_eq!(clock.wake_at(true, false), None);
    clock.probe_sent(start + PROBE);
    assert_eq!(clock.wake_at(true, false), Some(start + INTERVAL * 2));
}

#[test]
fn a_recovered_transport_starts_a_fresh_interval() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + PROBE);
    let recovered = start + INTERVAL * 2;
    clock.alive(recovered);
    assert!(!clock.dead(recovered, true));
    assert!(!clock.probe_due(recovered + PROBE - Duration::from_millis(1)));
    assert!(clock.probe_due(recovered + PROBE));
}
