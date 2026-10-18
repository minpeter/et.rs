use super::*;

const PATIENCE: Duration = Duration::from_secs(5);

#[test]
fn legacy_peer_without_acknowledgements_is_never_gated() {
    let mut gate = DeliveryGate::default();
    assert!(!gate.check(None, Instant::now(), PATIENCE));
}

#[test]
fn gates_only_while_the_backlog_reaches_the_bound() {
    let mut gate = DeliveryGate::default();
    let now = Instant::now();
    assert!(!gate.check(Some((10, MAX_UNACKNOWLEDGED_BYTES - 1)), now, PATIENCE));
    assert!(gate.check(Some((10, MAX_UNACKNOWLEDGED_BYTES)), now, PATIENCE));
    // An acknowledgement that drains the backlog releases producers.
    assert!(!gate.check(Some((90, 1024)), now, PATIENCE));
}

#[test]
fn advancing_acknowledgements_keep_the_gate_armed() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    // Slow but progressing delivery is not a stall.
    assert!(gate.check(Some((20, full)), start + PATIENCE, PATIENCE));
    assert!(gate.check(Some((30, full)), start + PATIENCE * 2, PATIENCE));
}

#[test]
fn a_stalled_acknowledgement_releases_the_gate_until_it_advances() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    assert!(gate.check(Some((10, full)), start + PATIENCE / 2, PATIENCE));
    assert!(!gate.check(Some((10, full)), start + PATIENCE, PATIENCE));
    // The same acknowledgement keeps producers released, however long.
    assert!(!gate.check(Some((10, full * 2)), start + PATIENCE * 3, PATIENCE));
}

#[test]
fn an_advancing_acknowledgement_re_arms_a_released_gate() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    assert!(!gate.check(Some((10, full)), start + PATIENCE, PATIENCE));
    // Delivery resumes: the bound applies again with a fresh patience window.
    let resumed = start + PATIENCE * 2;
    assert!(gate.check(Some((40, full)), resumed, PATIENCE));
    assert!(gate.check(Some((40, full)), resumed + PATIENCE / 2, PATIENCE));
    assert!(!gate.check(Some((40, full)), resumed + PATIENCE, PATIENCE));
}

#[test]
fn a_re_armed_gate_stays_open_while_the_backlog_is_below_the_bound() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    assert!(!gate.check(Some((10, full)), start + PATIENCE, PATIENCE));
    assert!(!gate.check(Some((40, 1024)), start + PATIENCE * 2, PATIENCE));
    // Re-armed by the advance above, so a later refill blocks again.
    assert!(gate.check(Some((40, full)), start + PATIENCE * 3, PATIENCE));
}

#[test]
fn draining_mid_stall_restarts_the_patience_window() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    // The backlog drains below the bound without a new acknowledgement.
    assert!(!gate.check(Some((10, full - 1)), start + PATIENCE / 2, PATIENCE));
    // Refilling with the same acknowledgement starts a new window instead of
    // counting from the first stall.
    let refilled = start + PATIENCE;
    assert!(gate.check(Some((10, full)), refilled, PATIENCE));
    assert!(gate.check(Some((10, full)), refilled + PATIENCE / 2, PATIENCE));
    assert!(!gate.check(Some((10, full)), refilled + PATIENCE, PATIENCE));
}

#[test]
fn disconnect_clears_a_pending_stall() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.observe(true, Some((10, full)), start, PATIENCE));
    assert!(!gate.observe(false, None, start + PATIENCE / 2, PATIENCE));
    // After reconnecting the stall window starts over.
    let reconnected = start + PATIENCE;
    assert!(gate.observe(true, Some((10, full)), reconnected, PATIENCE));
    assert!(gate.observe(true, Some((10, full)), reconnected + PATIENCE / 2, PATIENCE));
    assert!(!gate.observe(true, Some((10, full)), reconnected + PATIENCE, PATIENCE));
}

#[test]
fn disconnect_re_arms_a_released_gate() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.observe(true, Some((10, full)), start, PATIENCE));
    assert!(!gate.observe(true, Some((10, full)), start + PATIENCE, PATIENCE));
    assert!(!gate.observe(false, None, start + PATIENCE * 2, PATIENCE));
    // The new connection is gated even at the acknowledgement seen at release.
    assert!(gate.observe(true, Some((10, full)), start + PATIENCE * 3, PATIENCE));
}

#[test]
fn disconnected_connection_is_never_gated() {
    let mut gate = DeliveryGate::default();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(!gate.observe(false, Some((10, full)), Instant::now(), PATIENCE));
}
