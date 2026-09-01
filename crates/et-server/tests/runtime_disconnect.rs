#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::io::{self, Read};
use std::sync::mpsc;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectStatus, SequenceHeader};
use et_net::framing_io::read_proto_limited;
use et_server::SessionState;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};

fn assert_prompt_eof_or_reset(stream: &mut std::net::TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            panic!("terminal disconnect left initialization socket open: {error}")
        }
        Ok(read) => panic!("received {read} unexpected bytes after terminal disconnect"),
        Err(error) => panic!("unexpected read error after terminal disconnect: {error}"),
    }
}

#[test]
fn terminal_eof_removes_active_session_and_allows_fresh_registration() {
    let mut server = TestRuntime::start();
    let terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut active_client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    drop(terminal);
    server.handle.wait_disconnected(ID_A, TIMEOUT).unwrap();
    assert_eq!(server.handle.session_state(ID_A).unwrap(), None);
    assert!(active_client.read_packet().is_err());

    let (_stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::InvalidKey as i32));

    let _fresh_terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let (_fresh_client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server.runtime.shutdown().unwrap();
}

#[test]
fn terminal_eof_interrupts_blocked_returning_recovery() {
    let mut server = TestRuntime::start();
    let terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (_active_client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    let (mut returning, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    let _: SequenceHeader = read_proto_limited(&mut returning, 80 * 1024 * 1024).unwrap();
    drop(terminal);
    server.handle.wait_disconnected(ID_A, TIMEOUT).unwrap();
    assert_prompt_eof_or_reset(&mut returning);
    server.runtime.shutdown().unwrap();
}

#[test]
fn terminal_eof_interrupts_an_unauthenticated_initialization() {
    let server = TestRuntime::start();
    let terminal = server.register(ID_A, KEY_A);
    let (mut starting_client, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    assert_eq!(server.handle.session_state(ID_A).unwrap(), None);

    drop(terminal);
    server.handle.wait_disconnected(ID_A, TIMEOUT).unwrap();
    assert_prompt_eof_or_reset(&mut starting_client);

    let mut runtime = server.runtime;
    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = shutdown_tx.send(runtime.shutdown());
    });
    shutdown_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("pre-auth handler and permit were not released promptly")
        .unwrap();
}
