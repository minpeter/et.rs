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
fn a_stalled_acknowledgement_disables_the_gate_for_good() {
    let mut gate = DeliveryGate::default();
    let start = Instant::now();
    let full = MAX_UNACKNOWLEDGED_BYTES;
    assert!(gate.check(Some((10, full)), start, PATIENCE));
    assert!(gate.check(Some((10, full)), start + PATIENCE / 2, PATIENCE));
    assert!(!gate.check(Some((10, full)), start + PATIENCE, PATIENCE));
    assert!(!gate.check(Some((40, full)), start + PATIENCE * 2, PATIENCE));
}
