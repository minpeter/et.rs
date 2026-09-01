#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::thread;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectStatus, TerminalPacketType};
use et_net::local_packet::{read_local_packet, status_packet, write_local_packet, STARTUP_STATUS};
use et_server::SessionState;
use runtime_support::{
    default_payload, initialize, TestRuntime, ID_A, ID_B, KEY_A, KEY_B, TIMEOUT,
};

#[test]
fn real_new_client_completes_encrypted_initialization() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));

    let key = passkey_to_key(KEY_A).unwrap();
    let (_client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    server.runtime.shutdown().unwrap();
}

#[test]
fn passkeyless_known_id_staller_cannot_starve_legitimate_client() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (mut staller, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));

    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (_client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    let mut probe = [0u8; 1];
    assert_eq!(
        std::io::Read::read(&mut staller, &mut probe).unwrap_or(0),
        0
    );
    server.runtime.shutdown().unwrap();
}

#[test]
fn successful_initial_response_waits_for_terminal_startup_acknowledgement() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register_with_capability(ID_A, KEY_A, true);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = initialize(stream, &key, default_payload()).1;
        let _ = done_tx.send(result);
    });

    let init = read_local_packet(&mut terminal).unwrap();
    assert_eq!(init.header(), TerminalPacketType::TerminalInit as u8);
    assert!(matches!(
        done_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    write_local_packet(&mut terminal, &status_packet(STARTUP_STATUS, Ok(()))).unwrap();
    assert_eq!(done_rx.recv_timeout(TIMEOUT).unwrap().error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    server.runtime.shutdown().unwrap();
}

#[test]
fn stalled_startup_does_not_block_another_registration() {
    let mut server = TestRuntime::start();
    let mut terminal_a = server.register_with_capability(ID_A, KEY_A, true);
    let (stream, _) = server.handshake(ID_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = done_tx.send(initialize(stream, &key, default_payload()).1);
    });
    let init = read_local_packet(&mut terminal_a).unwrap();
    assert_eq!(init.header(), TerminalPacketType::TerminalInit as u8);

    let _terminal_b = server.register_with_capability(ID_B, KEY_B, true);
    assert!(server.handle.wait_registered(ID_B, TIMEOUT).is_ok());
    assert!(matches!(
        done_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    write_local_packet(&mut terminal_a, &status_packet(STARTUP_STATUS, Ok(()))).unwrap();
    assert_eq!(done_rx.recv_timeout(TIMEOUT).unwrap().error, None);
    server.runtime.shutdown().unwrap();
}

#[test]
fn server_startup_deadline_precedes_client_socket_timeout() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register_with_capability(ID_A, KEY_A, true);
    let (stream, _) = server.handshake(ID_A);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let key = passkey_to_key(KEY_A).unwrap();
    let started = std::time::Instant::now();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = done_tx.send(initialize(stream, &key, default_payload()).1);
    });
    let _init = read_local_packet(&mut terminal).unwrap();
    let response = done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(response.error.unwrap().contains("startup acknowledgement"));
    assert!(started.elapsed() < Duration::from_secs(10));
    server.runtime.shutdown().unwrap();
}

#[test]
fn terminal_startup_failure_is_returned_in_initial_response() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register_with_capability(ID_A, KEY_A, true);
    let (stream, _) = server.handshake(ID_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = done_tx.send(initialize(stream, &key, default_payload()).1);
    });
    let _init = read_local_packet(&mut terminal).unwrap();
    write_local_packet(
        &mut terminal,
        &status_packet(STARTUP_STATUS, Err("could not spawn terminal shell")),
    )
    .unwrap();
    let response = done_rx.recv_timeout(TIMEOUT).unwrap();
    assert!(response
        .error
        .unwrap()
        .contains("could not spawn terminal shell"));
    server.handle.wait_disconnected(ID_A, TIMEOUT).unwrap();
    assert_eq!(server.handle.session_state(ID_A).unwrap(), None);
    server.runtime.shutdown().unwrap();
}

#[test]
fn two_active_ids_are_isolated_through_the_server_handle() {
    let mut server = TestRuntime::start();
    let _terminal_a = server.register(ID_A, KEY_A);
    let _terminal_b = server.register(ID_B, KEY_B);
    let address = server.address;

    let clients: Vec<_> = [(ID_A, KEY_A), (ID_B, KEY_B)]
        .into_iter()
        .map(|(id, passkey)| {
            thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                runtime_support::bound(&stream);
                et_net::framing_io::write_proto(
                    &mut stream,
                    &et_net::handshake::client_request(id),
                )
                .unwrap();
                let response: et_core::proto::ConnectResponse =
                    et_net::framing_io::read_proto_limited(&mut stream, 64 * 1024).unwrap();
                assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
                let key = passkey_to_key(passkey).unwrap();
                initialize(stream, &key, default_payload()).0
            })
        })
        .collect();
    let mut clients: Vec<_> = clients
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    server
        .handle
        .wait_for_state(ID_B, SessionState::Active, TIMEOUT)
        .unwrap();

    server.handle.send_packet(ID_A, 11, b"only-a").unwrap();
    server.handle.send_packet(ID_B, 22, b"only-b").unwrap();
    let packet_a = clients[0].read_packet().unwrap();
    let packet_b = clients[1].read_packet().unwrap();
    assert_eq!(
        (packet_a.header(), packet_a.payload()),
        (11, b"only-a".as_slice())
    );
    assert_eq!(
        (packet_b.header(), packet_b.payload()),
        (22, b"only-b".as_slice())
    );
    server.runtime.shutdown().unwrap();
}
