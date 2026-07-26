#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectResponse, ConnectStatus, TerminalPacketType};
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::read_local_packet;
use et_server::SessionState;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};

#[test]
fn simultaneous_same_id_is_new_then_serialized_returning() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let barrier = Arc::new(Barrier::new(3));
    let (sender, receiver) = mpsc::channel();

    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = barrier.clone();
        let sender = sender.clone();
        let address = server.address;
        workers.push(thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            runtime_support::bound(&stream);
            barrier.wait();
            write_proto(&mut stream, &client_request(ID_A)).unwrap();
            let response: ConnectResponse = read_proto_limited(&mut stream, 64 * 1024).unwrap();
            sender.send((stream, response)).unwrap();
        }));
    }
    barrier.wait();
    let (first_stream, first_response) = receiver.recv_timeout(TIMEOUT).unwrap();
    assert_eq!(first_response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(first_stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    let (returning_stream, response) = receiver.recv_timeout(TIMEOUT).unwrap();
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    client.recover(returning_stream).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    for worker in workers {
        worker.join().unwrap();
    }
    server.runtime.shutdown().unwrap();
}

#[test]
fn returning_client_receives_exact_buffered_server_catchup() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let initial_terminal_packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        initial_terminal_packet.header(),
        TerminalPacketType::TerminalInit as u8
    );

    client.shutdown().unwrap();
    server.handle.send_packet(ID_A, 31, b"buffer-one").unwrap();
    server.handle.send_packet(ID_A, 32, b"buffer-two").unwrap();

    let (returning, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    client.recover(returning).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    let first = client.read_packet().unwrap();
    let second = client.read_packet().unwrap();
    assert_eq!(
        (first.header(), first.payload()),
        (31, b"buffer-one".as_slice())
    );
    assert_eq!(
        (second.header(), second.payload()),
        (32, b"buffer-two".as_slice())
    );
    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"post-recovery")
        .unwrap();
    let forwarded = read_local_packet(&mut terminal).unwrap();
    assert_eq!(forwarded.header(), TerminalPacketType::TerminalInfo as u8);
    assert_eq!(forwarded.payload(), b"post-recovery");
    server.runtime.shutdown().unwrap();
}

#[test]
fn keepalive_echo_acknowledges_everything_read_from_the_client() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    // An acknowledging keep-alive is echoed with the server's own ack: the
    // count of every packet the client has written (the server processes
    // packets in order, so by the time it echoes it has read them all).
    let ack = client.keepalive_ack();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
        .unwrap();
    let written = client.writer_sequence();
    let echo = client.read_packet().unwrap();
    assert_eq!(echo.header(), TerminalPacketType::KeepAlive as u8);
    assert_eq!(et_core::keepalive::decode_ack(echo.payload()), Some(written));

    // A legacy empty keep-alive still gets an echo.
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    let echo = client.read_packet().unwrap();
    assert_eq!(echo.header(), TerminalPacketType::KeepAlive as u8);
    server.runtime.shutdown().unwrap();
}

#[test]
fn library_shutdown_interrupts_partial_handshakes_and_joins_workers() {
    let mut server = TestRuntime::start();
    let path = server.dir.socket();
    let address = server.address;
    let _partial = std::net::TcpStream::connect(address).unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = server.runtime.shutdown();
        let _ = done_tx.send(result);
    });
    assert!(done_rx.recv_timeout(TIMEOUT).unwrap().is_ok());
    worker.join().unwrap();
    assert!(!path.exists());
    assert!(std::net::TcpStream::connect(address).is_err());
}
