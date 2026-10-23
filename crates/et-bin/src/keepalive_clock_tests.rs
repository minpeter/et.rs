use super::*;

const INTERVAL: Duration = Duration::from_secs(5);

#[test]
fn an_unanswered_probe_declares_the_link_dead_one_interval_later() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    assert!(!clock.probe_due(start + INTERVAL - Duration::from_millis(1)));
    assert_eq!(clock.wake_at(true, true), Some(start + INTERVAL));
    assert!(clock.probe_due(start + INTERVAL));
    assert!(!clock.dead(start + INTERVAL, true));
    clock.probe_sent(start + INTERVAL);
    // One probe at a time.
    assert!(!clock.probe_due(start + INTERVAL * 2));
    assert!(!clock.dead(start + INTERVAL * 2 - Duration::from_millis(1), true));
    assert_eq!(clock.wake_at(true, true), Some(start + INTERVAL * 2));
    // Two intervals after the last packet, not three.
    assert!(clock.dead(start + INTERVAL * 2, true));
}

#[test]
fn any_packet_read_answers_the_probe_and_restarts_the_interval() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + INTERVAL);
    let reply = start + INTERVAL + Duration::from_millis(1900);
    clock.alive(reply);
    assert!(!clock.dead(start + INTERVAL * 2, true));
    assert!(!clock.probe_due(reply + INTERVAL - Duration::from_millis(1)));
    assert!(clock.probe_due(reply + INTERVAL));
}

#[test]
fn no_verdict_while_the_transport_is_not_read() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + INTERVAL);
    let late = start + INTERVAL * 4;
    assert!(!clock.dead(late, false));
    // Nothing to wake for until reading resumes.
    assert_eq!(clock.wake_at(false, true), None);
    assert!(!clock.probe_due(late));
    // Probes still go out while output is held.
    let held = KeepaliveClock::new(INTERVAL, start);
    assert!(held.probe_due(start + INTERVAL));
    assert_eq!(held.wake_at(false, true), Some(start + INTERVAL));
    // Reading again: the verdict is due.
    assert!(clock.dead(late, true));
}

#[test]
fn a_pending_write_defers_the_probe_but_not_the_verdict() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    // No probe can start while a frame is pending: do not spin on it.
    assert_eq!(clock.wake_at(true, false), None);
    clock.probe_sent(start + INTERVAL);
    assert_eq!(clock.wake_at(true, false), Some(start + INTERVAL * 2));
}

#[test]
fn a_recovered_transport_starts_a_fresh_interval() {
    let start = Instant::now();
    let clock = KeepaliveClock::new(INTERVAL, start);
    clock.probe_sent(start + INTERVAL);
    let recovered = start + INTERVAL * 2;
    clock.alive(recovered);
    assert!(!clock.dead(recovered, true));
    assert!(!clock.probe_due(recovered));
    assert!(clock.probe_due(recovered + INTERVAL));
}
