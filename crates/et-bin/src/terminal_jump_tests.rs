use super::*;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;

use socket2::SockRef;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const PTY_CONTRACT: Duration = Duration::from_secs(5);
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
fn slow_jumphost_output_does_not_block_ctrl_c_toward_destination() {
    // Given: a real encrypted destination hop and a bounded local router link
    // whose client side deliberately does not consume destination output.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [29u8; 32];
    let mut destination_client = Connection::new_client(client_stream, &key);
    let mut destination_server = Connection::new_server(server_stream, &key);
    let (relay_router, mut router_peer) = et_net::local::wake_pair().unwrap();
    saturate_router_output(&relay_router, &router_peer);
    let (output_sent_tx, output_sent_rx) = mpsc::sync_channel(0);
    let (pending_tx, pending_rx) = mpsc::sync_channel(0);
    let (input_tx, input_rx) = mpsc::sync_channel(0);
    let destination = thread::spawn(move || {
        destination_server
            .write_packet(71, &vec![b'p'; 60 * 1024])
            .unwrap();
        output_sent_tx.send(()).unwrap();
        let input = destination_server.read_packet().unwrap();
        input_tx
            .send((input.header(), input.payload().to_vec()))
            .unwrap();
        destination_server.shutdown().unwrap();
    });
    let relay = thread::spawn(move || {
        relay_with_output_observer(relay_router, &mut destination_client, || {
            pending_tx.send(()).unwrap();
        })
    });
    output_sent_rx.recv_timeout(PTY_CONTRACT).unwrap();
    pending_rx.recv_timeout(PTY_CONTRACT).unwrap();

    // When: Ctrl-C arrives while ownership of the blocked prompt/output frame
    // remains in the destination-to-router direction.
    write_local_packet(
        &mut router_peer,
        &Packet::new(TerminalPacketType::TerminalBuffer as u8, vec![3]),
    )
    .unwrap();

    // Then: input reaches the destination within the unchanged five-second PTY contract.
    assert_eq!(
        input_rx.recv_timeout(PTY_CONTRACT).unwrap(),
        (TerminalPacketType::TerminalBuffer as u8, vec![3])
    );
    destination.join().unwrap();
    drop(router_peer);
    assert_eq!(relay.join().unwrap().unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn jumphost_drains_coalesced_destination_packets_without_new_socket_readiness() {
    // Given: several small encrypted frames are already queued before the
    // relay reads once, allowing one recv() to move all of them into the
    // connection's userspace BackedReader.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [31u8; 32];
    let mut destination_client = Connection::new_client(client_stream, &key);
    let mut destination_server = Connection::new_server(server_stream, &key);
    for header in 91..96 {
        destination_server.write_packet(header, &[header]).unwrap();
    }
    let (relay_router, mut router_peer) = et_net::local::wake_pair().unwrap();
    router_peer.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let relay = thread::spawn(move || relay(relay_router, &mut destination_client));

    // When: the router consumes every frame without sending input that could
    // create a fresh poll event.
    let mut relayed = Vec::new();
    for _ in 0..5 {
        match et_net::local_packet::read_local_packet(&mut router_peer) {
            Ok(packet) => relayed.push((packet.header(), packet.payload().to_vec())),
            Err(_) => break,
        }
    }
    drop(router_peer);
    assert_eq!(relay.join().unwrap().unwrap(), 0);

    // Then: userspace-buffered frames were drained even after kernel POLLIN
    // readiness disappeared.
    assert_eq!(
        relayed,
        (91..96)
            .map(|header| (header, vec![header]))
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn jumphost_resumes_coalesced_destination_packets_after_router_backpressure() {
    // Given: five destination packets coalesce in userspace while the router
    // output queue is already full.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [37u8; 32];
    let mut destination_client = Connection::new_client(client_stream, &key);
    let mut destination_server = Connection::new_server(server_stream, &key);
    for header in 101..106 {
        destination_server.write_packet(header, &[header]).unwrap();
    }
    let (relay_router, mut router_peer) = et_net::local::wake_pair().unwrap();
    let filler_bytes = saturate_router_output(&relay_router, &router_peer);
    router_peer.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let (pending_tx, pending_rx) = mpsc::sync_channel(0);
    let relay = thread::spawn(move || {
        relay_with_output_observer(relay_router, &mut destination_client, || {
            pending_tx.send(()).unwrap();
        })
    });
    pending_rx.recv_timeout(TEST_TIMEOUT).unwrap();

    // When: the router resumes reading after the first destination frame was
    // interrupted by real socket backpressure.
    router_peer
        .read_exact(&mut vec![0u8; filler_bytes])
        .unwrap();
    let mut relayed = Vec::new();
    for _ in 0..5 {
        match et_net::local_packet::read_local_packet(&mut router_peer) {
            Ok(packet) => relayed.push((packet.header(), packet.payload().to_vec())),
            Err(_) => break,
        }
    }
    drop(router_peer);
    assert_eq!(relay.join().unwrap().unwrap(), 0);

    // Then: clearing pending output resumes the userspace drain without a new
    // destination POLLIN event.
    assert_eq!(
        relayed,
        (101..106)
            .map(|header| (header, vec![header]))
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn closed_destination_poll_mask_ignores_readable_router_input() {
    // Given: destination closure is latched while output remains pending.
    // When: the router poll subscription is constructed.
    let flags = router_poll_flags(true, true);

    // Then: readable input cannot wake a loop that deliberately ignores it,
    // while output progress and local closure remain observable.
    assert!(!flags.contains(PollFlags::IN));
    assert!(flags.contains(PollFlags::OUT));
    assert!(flags.contains(PollFlags::HUP));
    assert!(flags.contains(PollFlags::ERR));
}

#[cfg(unix)]
#[test]
fn jumphost_drains_buffered_destination_packets_after_hup() {
    // Given: destination frames are coalesced before the peer closes, while
    // the first local frame is held by real router backpressure.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [41u8; 32];
    let mut destination_client = Connection::new_client(client_stream, &key);
    let mut destination_server = Connection::new_server(server_stream, &key);
    for header in 111..116 {
        destination_server.write_packet(header, &[header]).unwrap();
    }
    // FIN after the queued writes. A linger-0 RST can discard unread
    // destination bytes on macOS before the relay's BackedReader sees them,
    // so `read_local_packet` then fails with TruncatedPrefix.
    let closed = destination_server.try_clone_stream().unwrap();
    closed.shutdown(std::net::Shutdown::Write).unwrap();
    drop(closed);
    drop(destination_server);
    let (relay_router, mut router_peer) = et_net::local::wake_pair().unwrap();
    let filler_bytes = saturate_router_output(&relay_router, &router_peer);
    router_peer.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let (pending_tx, pending_rx) = mpsc::sync_channel(0);
    let relay = thread::spawn(move || {
        relay_with_output_observer(relay_router, &mut destination_client, || {
            pending_tx.send(()).unwrap();
        })
    });
    pending_rx.recv_timeout(TEST_TIMEOUT).unwrap();

    // When: the router resumes after destination HUP has already been observed.
    router_peer
        .read_exact(&mut vec![0u8; filler_bytes])
        .unwrap();
    let mut relayed = Vec::new();
    for _ in 0..5 {
        let packet = et_net::local_packet::read_local_packet(&mut router_peer).unwrap();
        relayed.push((packet.header(), packet.payload().to_vec()));
    }

    // Then: the pending frame and every packet already buffered in the
    // destination BackedReader leave in order before the relay exits.
    assert_eq!(relay.join().unwrap().unwrap(), 0);
    assert_eq!(
        relayed,
        (111..116)
            .map(|header| (header, vec![header]))
            .collect::<Vec<_>>()
    );
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

fn saturate_router_output(
    router: &et_net::local::LocalStream,
    peer: &et_net::local::LocalStream,
) -> usize {
    et_net::local::minimize_terminal_output_buffering(router).unwrap();
    SockRef::from(router)
        .set_send_buffer_size(2 * 1024)
        .unwrap();
    SockRef::from(peer).set_recv_buffer_size(2 * 1024).unwrap();
    let mut saturator = router.try_clone().unwrap();
    saturator.set_nonblocking(true).unwrap();
    let filler = [0u8; 16 * 1024];
    let mut saturated_bytes = 0usize;
    loop {
        match saturator.write(&filler) {
            Ok(0) => panic!("router output closed before reaching backpressure"),
            Ok(written) => saturated_bytes += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("could not saturate router output: {error}"),
        }
    }
    assert!(saturated_bytes > 0);
    saturated_bytes
}
