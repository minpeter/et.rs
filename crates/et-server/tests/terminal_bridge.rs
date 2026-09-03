#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{
    ConnectStatus, FlowControlMode, TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType,
};
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
    let second_input = TerminalBuffer {
        buffer: Some(b"second-input".to_vec()),
    };
    client
        .write_packet(
            TerminalPacketType::TerminalBuffer as u8,
            &second_input.encode_to_vec(),
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
    let local_second = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        TerminalBuffer::decode(local_second.payload())
            .unwrap()
            .buffer
            .as_deref(),
        Some(b"second-input".as_slice())
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
fn terminal_hup_still_delivers_buffered_final_packet() {
    use std::net::Shutdown;

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

    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"bridge-ready")
        .unwrap();
    let readiness = read_local_packet(&mut terminal).unwrap();
    assert_eq!(readiness.payload(), b"bridge-ready");

    let final_packets = [
        TerminalBuffer {
            buffer: Some(b"final-terminal-packet-one".to_vec()),
        },
        TerminalBuffer {
            buffer: Some(b"final-terminal-packet-two".to_vec()),
        },
    ];
    for packet in &final_packets {
        write_local_packet(
            &mut terminal,
            &Packet::new(
                TerminalPacketType::TerminalBuffer as u8,
                packet.encode_to_vec(),
            ),
        )
        .unwrap();
    }
    terminal.shutdown(Shutdown::Both).unwrap();

    for expected in &final_packets {
        let received = client.read_packet().unwrap();
        assert_eq!(received.header(), TerminalPacketType::TerminalBuffer as u8);
        assert_eq!(
            TerminalBuffer::decode(received.payload()).unwrap(),
            *expected
        );
    }

    server.runtime.shutdown().unwrap();
}

#[test]
fn flow_control_mode_reaches_terminal_and_relays_output() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let mut payload = default_payload();
    payload.flowcontrol = Some(FlowControlMode::Backpressure as i32);
    let (mut client, initial) = initialize(stream, &key, payload);
    assert_eq!(initial.error, None);

    let init = read_local_packet(&mut terminal).unwrap();
    let term_init = TermInit::decode(init.payload()).unwrap();
    assert_eq!(
        term_init.flowcontrol,
        Some(FlowControlMode::Backpressure as i32)
    );

    let output = TerminalBuffer {
        buffer: Some(b"flow-controlled-output".to_vec()),
    };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            output.encode_to_vec(),
        ),
    )
    .unwrap();

    let received = client.read_packet().unwrap();
    assert_eq!(received.header(), TerminalPacketType::TerminalBuffer as u8);
    assert_eq!(TerminalBuffer::decode(received.payload()).unwrap(), output);

    drop(terminal);
    server.runtime.shutdown().unwrap();
}

#[test]
fn saturated_terminal_hup_retains_final_packets_by_mode() {
    use std::sync::mpsc;
    use std::thread;

    for mode in [FlowControlMode::Backpressure, FlowControlMode::Discard] {
        // Given: terminal output fills the local/server path while the client is not reading.
        let mut server = TestRuntime::start();
        let mut terminal = server.register(ID_A, KEY_A);
        let (stream, response) = server.handshake(ID_A);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        let key = passkey_to_key(KEY_A).unwrap();
        let mut payload = default_payload();
        payload.flowcontrol = Some(mode as i32);
        let (mut client, initial) = initialize(stream, &key, payload);
        assert_eq!(initial.error, None);
        let _init = read_local_packet(&mut terminal).unwrap();
        let packets: Vec<TerminalBuffer> = (0u8..32)
            .map(|value| TerminalBuffer {
                buffer: Some(vec![value; 16 * 1024]),
            })
            .collect();
        let sent_packets = packets.clone();
        let (written_tx, written_rx) = mpsc::sync_channel(32);
        let producer = thread::spawn(move || {
            for (index, packet) in sent_packets.iter().enumerate() {
                write_local_packet(
                    &mut terminal,
                    &Packet::new(
                        TerminalPacketType::TerminalBuffer as u8,
                        packet.encode_to_vec(),
                    ),
                )
                .unwrap();
                written_tx.send(index).unwrap();
            }
            drop(terminal);
        });
        for expected in 0..8 {
            assert_eq!(written_rx.recv_timeout(TIMEOUT).unwrap(), expected);
        }

        // When: the client starts draining after saturation and local HUP follows.
        let reader = thread::spawn(move || {
            let mut values = Vec::new();
            while let Ok(packet) = client.read_packet() {
                if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
                    let decoded = TerminalBuffer::decode(packet.payload()).unwrap();
                    values.push(decoded.buffer.unwrap()[0]);
                }
            }
            values
        });
        producer.join().unwrap();
        let values = reader.join().unwrap();

        // Then: backpressure is lossless; discard is ordered and retains newest output.
        assert!(
            values.windows(2).all(|pair| pair[0] < pair[1]),
            "{values:?}"
        );
        assert_eq!(values.last(), Some(&31));
        if mode == FlowControlMode::Backpressure {
            assert_eq!(values, (0u8..32).collect::<Vec<_>>());
        }
        server.runtime.shutdown().unwrap();
    }
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
