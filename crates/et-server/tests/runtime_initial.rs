#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::thread;

use et_core::keys::passkey_to_key;
use et_core::proto::ConnectStatus;
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
