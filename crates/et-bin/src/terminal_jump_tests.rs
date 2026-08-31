use super::*;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;

use socket2::SockRef;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const ID: &str = "abcdefghijklmnop";
const KEY_TEXT: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

#[test]
fn malformed_downstream_initial_response_fails_closed() {
    assert_eq!(
        downstream_requires_ack(&[0xff]),
        Err("destination sent a malformed INITIAL_RESPONSE".to_owned())
    );
    assert_eq!(
        downstream_requires_ack(
            &InitialResponse {
                error: Some("ordinary fatal".to_owned()),
            }
            .encode_to_vec()
        ),
        Ok(true)
    );
}

#[test]
fn jumphost_clamps_destination_before_typed_initial_payload() {
    // Given: a destination requiring proof of the clamp before it accepts
    // INITIAL_PAYLOAD and starts terminal output.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (clamped_tx, clamped_rx) = mpsc::sync_channel(1);
    let key = passkey_to_key(KEY_TEXT).unwrap();
    let destination = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let _: et_core::proto::ConnectRequest =
            read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN).unwrap();
        write_proto(
            &mut stream,
            &ConnectResponse {
                status: Some(ConnectStatus::NewClient as i32),
                error: None,
            },
        )
        .unwrap();
        let observed = clamped_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        assert!(
            observed <= et_net::connection::FLOW_CONTROL_SOCKET_BUFFER_BYTES * 2,
            "jumphost destination send buffer remained {observed} bytes"
        );
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        assert_eq!(packet.header(), EtPacketType::InitialPayload as u8);
        let payload = InitialPayload::decode(packet.payload()).unwrap();
        assert_eq!(
            payload.flowcontrol,
            Some(FlowControlMode::Backpressure as i32)
        );
        assert_eq!(payload.jumphost, Some(false));
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });
    let payload = InitialPayload {
        jumphost: Some(false),
        flowcontrol: Some(FlowControlMode::Backpressure as i32),
        ..Default::default()
    };

    // When: the jumphost establishes its destination side.
    let connection =
        try_connect_once_observed(ID, &key, "127.0.0.1", port, &payload, |connection| {
            let stream = connection
                .try_clone_stream()
                .map_err(|error| error.to_string())?;
            let size = SockRef::from(&stream)
                .send_buffer_size()
                .map_err(|error| error.to_string())?;
            clamped_tx.send(size).map_err(|error| error.to_string())
        })
        .unwrap();

    // Then: initialization completed after bounded pressure and mode retention.
    drop(connection);
    destination.join().unwrap();
}

#[test]
fn jumphost_run_bounds_router_sender_before_destination_output() {
    // Given: the real jump relay is paused after the destination receives its
    // typed initialization but before that destination may produce output.
    let (run_router, mut router_peer) = et_net::local::wake_pair().unwrap();
    let router_observer = run_router.try_clone().unwrap();
    let payload = InitialPayload {
        jumphost: Some(true),
        flowcontrol: Some(FlowControlMode::Discard as i32),
        ..Default::default()
    };
    write_local_packet(
        &mut router_peer,
        &Packet::new(
            TerminalPacketType::JumphostInit as u8,
            payload.encode_to_vec(),
        ),
    )
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (initialized_tx, initialized_rx) = mpsc::sync_channel(1);
    let (output_release_tx, output_release_rx) = mpsc::sync_channel(0);
    let key = passkey_to_key(KEY_TEXT).unwrap();
    let destination = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let _: et_core::proto::ConnectRequest =
            read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN).unwrap();
        write_proto(
            &mut stream,
            &ConnectResponse {
                status: Some(ConnectStatus::NewClient as i32),
                error: None,
            },
        )
        .unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        let received = InitialPayload::decode(packet.payload()).unwrap();
        assert_eq!(received.flowcontrol, Some(FlowControlMode::Discard as i32));
        assert_eq!(received.jumphost, Some(false));
        initialized_tx.send(()).unwrap();
        output_release_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });
    let input = crate::terminal_credentials::CredentialInput {
        id: ID.to_owned(),
        passkey: KEY_TEXT.to_owned(),
        term: "xterm-256color".to_owned(),
    };
    let relay = thread::spawn(move || run(run_router, &input, "127.0.0.1", port));

    // When: destination startup reaches the exact pre-output barrier.
    initialized_rx.recv_timeout(TEST_TIMEOUT).unwrap();

    // Then: the jumphost router sender is already bounded and mode survived both hops.
    let send_buffer = SockRef::from(&router_observer).send_buffer_size().unwrap();
    assert!(
        send_buffer <= et_net::local::FLOW_CONTROL_SEND_BUFFER_BYTES * 2,
        "jumphost router send buffer remained {send_buffer} bytes"
    );
    output_release_tx.send(()).unwrap();
    destination.join().unwrap();
    let response = et_net::local_packet::read_local_packet(&mut router_peer).unwrap();
    assert_eq!(response.header(), TerminalPacketType::JumphostInit as u8);
    assert_eq!(
        InitialResponse::decode(response.payload()).unwrap().error,
        None
    );
    drop(router_peer);
    assert_eq!(relay.join().unwrap().unwrap(), 0);
}
