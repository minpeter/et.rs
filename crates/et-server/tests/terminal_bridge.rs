#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{ConnectStatus, TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::local_packet::{read_local_packet, write_local_packet};
use prost::Message;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};

#[test]
fn encrypted_client_and_registered_terminal_exchange_packets() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);

    let init = read_local_packet(&mut terminal).unwrap();
    assert_eq!(init.header(), TerminalPacketType::TerminalInit as u8);
    let environment = TermInit::decode(init.payload()).unwrap();
    assert!(environment.environmentnames.is_empty());

    let input = TerminalBuffer {
        buffer: Some(b"client-input".to_vec()),
    };
    client
        .write_packet(
            TerminalPacketType::TerminalBuffer as u8,
            &input.encode_to_vec(),
        )
        .unwrap();
    let local_input = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        TerminalBuffer::decode(local_input.payload())
            .unwrap()
            .buffer
            .as_deref(),
        Some(b"client-input".as_slice())
    );

    let output = TerminalBuffer {
        buffer: Some(b"terminal-output".to_vec()),
    };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            output.encode_to_vec(),
        ),
    )
    .unwrap();
    let client_output = client.read_packet().unwrap();
    assert_eq!(
        TerminalBuffer::decode(client_output.payload())
            .unwrap()
            .buffer
            .as_deref(),
        Some(b"terminal-output".as_slice())
    );

    let size = TerminalInfo {
        id: None,
        row: Some(40),
        column: Some(100),
        width: Some(800),
        height: Some(600),
    };
    client
        .write_packet(
            TerminalPacketType::TerminalInfo as u8,
            &size.encode_to_vec(),
        )
        .unwrap();
    let local_size = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        TerminalInfo::decode(local_size.payload()).unwrap().row,
        Some(40)
    );
    drop(terminal);
    server.runtime.shutdown().unwrap();
}

#[test]
fn terminal_environment_is_forwarded_without_interpolation() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let mut payload = default_payload();
    payload
        .environmentvariables
        .insert("LITERAL".to_owned(), "$(not-executed)".to_owned());
    let (_client, initial) = initialize(stream, &key, payload);
    assert_eq!(initial.error, None);
    let init = read_local_packet(&mut terminal).unwrap();
    let environment = TermInit::decode(init.payload()).unwrap();
    assert_eq!(environment.environmentnames, vec!["LITERAL"]);
    assert_eq!(environment.environmentvalues, vec!["$(not-executed)"]);
    drop(terminal);
    server.runtime.shutdown().unwrap();
}
