//! Native Windows server/ConPTY coverage. No SSH daemon or installed service is used.
#![cfg(windows)]
#![forbid(unsafe_code)]

mod windows_runtime_support;

use std::net::Shutdown;

use et_core::proto::ConnectStatus;
use windows_runtime_support::{ProcessExitObserver, Shell, Stack};

#[test]
fn conpty_shell_state_survives_same_session_recovery_and_exit_reaps_descendants() {
    // Given: the shipped server and terminal host a real native shell and child.
    let mut stack = Stack::start();
    let mut client = stack.connect();
    let shell = Shell::start(&mut client);
    let mut exits = ProcessExitObserver::subscribe(&shell);

    // When: the transport disappears, then the same credentials return.
    client
        .try_clone_stream()
        .unwrap()
        .shutdown(Shutdown::Both)
        .unwrap();
    let returning = stack.handshake(ConnectStatus::ReturningClient);
    client.recover(returning).unwrap();

    // Then: a fresh command proves preserved shell state and both process IDs;
    // a successful handshake alone (or replay of the old marker) cannot pass.
    shell.assert_recovered(&mut client);
    Shell::send(&mut client, "exit\r\n");
    stack.wait_terminal(true);
    exits.wait();
    stack.finish();
}

#[test]
fn losing_the_router_reaps_the_native_shell_and_its_descendant() {
    // Given: exit observers hold process handles before the router is closed.
    let mut stack = Stack::start();
    let mut client = stack.connect();
    let shell = Shell::start(&mut client);
    let mut exits = ProcessExitObserver::subscribe(&shell);

    // When: only this test's foreground server is terminated.
    stack.stop_server();

    // Then: terminal failure cleanup, not the fixture's fallback, reaps the tree.
    stack.wait_terminal(false);
    exits.wait();
    stack.finish();
}
