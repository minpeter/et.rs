//! Real-role takeover while the previous UI is still attached.

use super::htm_support::{Daemon, Relay};
use et_htm::framing;

#[test]
fn kill_replaces_an_attached_session_without_stopping_an_unrelated_daemon() {
    // Given two initialized UIs, neither detached before the replacement.
    let selected = super::htm_support::Endpoint::new();
    let mut old_ui = Relay::start(&selected.path);
    let old_state = old_ui.state();
    let mut other = Daemon::start();
    let mut other_ui = Relay::start(&other.path);
    let other_state = other_ui.state();

    // When a new client requests -x against the occupied selected endpoint.
    let mut replacement = Relay::restart(&selected.path);
    let fresh_state = replacement.state();

    // Then the old UI exits cleanly, and the replacement owns fresh pane state.
    old_ui.finish();
    assert_ne!(fresh_state["panes"], old_state["panes"]);
    // The unrelated UI remains responsive and its daemon preserves pane state.
    framing::write_debug_keys(&mut other_ui.input, &[27]).unwrap();
    other_ui.finish();
    let mut other_ui = Relay::start(&other.path);
    assert_eq!(other_ui.state()["panes"], other_state["panes"]);
    framing::write_debug_keys(&mut replacement.input, b"x").unwrap();
    replacement.finish();
    framing::write_debug_keys(&mut other_ui.input, b"x").unwrap();
    other_ui.finish();
    other.finish();
    println!("HTM_ATTACHED_RESTART_PASS old-ui-closed fresh-daemon unrelated-daemon-survived");
}

#[test]
fn new_ui_takes_over_an_attached_daemon_and_preserves_its_panes() {
    // Given an initialized UI that remains open.
    let mut daemon = Daemon::start();
    let mut old_ui = Relay::start(&daemon.path);
    let original = old_ui.state();

    // When another UI attaches without requesting daemon shutdown.
    let mut new_ui = Relay::start(&daemon.path);
    let recovered = new_ui.state();

    // Then only the old UI closes; the daemon and pane identities survive.
    old_ui.finish();
    assert_eq!(recovered["panes"], original["panes"]);
    framing::write_debug_keys(&mut new_ui.input, b"x").unwrap();
    new_ui.finish();
    daemon.finish();
}
