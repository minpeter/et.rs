#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;

use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectRequest, ConnectResponse, ConnectStatus, InitialPayload, InitialResponse,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_server::SessionState;
use prost::Message;
use runtime_support::{bound, default_payload, TestRuntime, ID_A, KEY_A, TIMEOUT};

#[test]
fn bad_encrypted_initial_messages_reset_the_slot() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let good_key = passkey_to_key(KEY_A).unwrap();

    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let mut wrong = Connection::new_client(stream, &[7; 32]);
    wrong
        .write_packet(253, &default_payload().encode_to_vec())
        .unwrap();
    assert!(wrong.read_packet().is_err());
    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();

    for (header, bytes) in [(1, default_payload().encode_to_vec()), (253, vec![0xff])] {
        let (stream, response) = server.handshake(ID_A);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        let mut client = Connection::new_client(stream, &good_key);
        client.write_packet(header, &bytes).unwrap();
        let packet = client.read_packet().unwrap();
        let response = InitialResponse::decode(packet.payload()).unwrap();
        assert!(response.error.is_some());
        server
            .handle
            .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
            .unwrap();
    }
    server.runtime.shutdown().unwrap();
}

#[test]
fn unbindable_reverse_tunnel_reports_an_error_and_resets_the_slot() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    // An empty reverse-tunnel request has no usable source endpoint, so the
    // server answers INITIAL_RESPONSE with an error like upstream does when
    // `createSource` fails.
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![Default::default()],
        environmentvariables: HashMap::new(),
    };
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let (_, initial) = runtime_support::initialize(stream, &key, payload);
    assert!(initial.error.is_some());
    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();
    server.runtime.shutdown().unwrap();
}

#[test]
fn occupied_reverse_row_is_fatal_and_rolls_back_sibling() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let occupied_path = server.dir.path().join("reported-occupied.sock");
    let usable_path = server.dir.path().join("reported-usable.sock");
    let _occupied = std::os::unix::net::UnixListener::bind(&occupied_path).unwrap();
    let request = |path: &std::path::Path| et_core::proto::PortForwardSourceRequest {
        source: Some(et_core::proto::SocketEndpoint {
            name: Some(path.to_string_lossy().into_owned()),
            port: None,
        }),
        destination: Some(et_core::proto::SocketEndpoint {
            name: Some("/tmp/destination.sock".to_owned()),
            port: None,
        }),
        environmentvariable: None,
    };
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![request(&occupied_path), request(&usable_path)],
        environmentvariables: HashMap::new(),
    };

    let (stream, _) = server.handshake(ID_A);
    let (client, initial) = runtime_support::initialize(stream, &key, payload);
    assert!(initial.error.is_some());
    drop(client);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();
    assert!(!usable_path.exists());
    server.runtime.shutdown().unwrap();
}

#[test]
fn reverse_bind_failure_never_activates_the_session() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let occupied_path = server.dir.path().join("unacked-occupied.sock");
    let sibling_path = server.dir.path().join("unacked-sibling.sock");
    let _occupied = std::os::unix::net::UnixListener::bind(&occupied_path).unwrap();
    let request = |path: &std::path::Path| et_core::proto::PortForwardSourceRequest {
        source: Some(et_core::proto::SocketEndpoint {
            name: Some(path.to_string_lossy().into_owned()),
            port: None,
        }),
        destination: Some(et_core::proto::SocketEndpoint {
            name: Some("/tmp/destination.sock".to_owned()),
            port: None,
        }),
        environmentvariable: None,
    };
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![request(&occupied_path), request(&sibling_path)],
        environmentvariables: HashMap::new(),
    };

    let (stream, _) = server.handshake(ID_A);
    let (client, initial) = runtime_support::initialize(stream, &key, payload);
    assert!(initial.error.is_some());
    drop(client);

    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();
    assert!(!sibling_path.exists());
    server.runtime.shutdown().unwrap();
}

#[test]
fn reverse_failures_are_plain_fatal_errors() {
    let cases = [
        vec![Default::default()],
        vec![et_core::proto::PortForwardSourceRequest {
            source: Some(et_core::proto::SocketEndpoint {
                name: Some("a".repeat(256)),
                port: Some(1),
            }),
            destination: Some(et_core::proto::SocketEndpoint {
                name: Some("127.0.0.1".to_owned()),
                port: Some(1),
            }),
            environmentvariable: None,
        }],
    ];
    for requests in cases {
        let mut server = TestRuntime::start();
        let _terminal = server.register(ID_A, KEY_A);
        let key = passkey_to_key(KEY_A).unwrap();
        let payload = InitialPayload {
            jumphost: Some(false),
            reversetunnels: requests,
            environmentvariables: HashMap::new(),
        };

        let (stream, _) = server.handshake(ID_A);
        let (_, initial) = runtime_support::initialize(stream, &key, payload);

        let error = initial.error.unwrap();
        assert!(!error.starts_with("ETRS-RF-SKIP"));
        server.runtime.shutdown().unwrap();
    }
}

#[test]
fn reverse_listener_cap_is_prebind_transactional_on_server() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let paths: Vec<_> = (0..33)
        .map(|index| server.dir.path().join(format!("cap-{index}.sock")))
        .collect();
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: paths
            .iter()
            .map(|path| et_core::proto::PortForwardSourceRequest {
                source: Some(et_core::proto::SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                destination: Some(et_core::proto::SocketEndpoint {
                    name: Some("/tmp/destination.sock".to_owned()),
                    port: None,
                }),
                environmentvariable: None,
            })
            .collect(),
        environmentvariables: HashMap::new(),
    };

    let (stream, _) = server.handshake(ID_A);
    let (_, initial) = runtime_support::initialize(stream, &key, payload);

    assert!(initial
        .error
        .is_some_and(|error| error.contains("listener limit")));
    assert!(paths.iter().all(|path| !path.exists()));
    server.runtime.shutdown().unwrap();
}

#[test]
fn obsolete_origin_marker_has_no_privileged_meaning() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![et_core::proto::PortForwardSourceRequest {
            source: Some(et_core::proto::SocketEndpoint {
                name: Some(
                    server
                        .dir
                        .path()
                        .join("hostile-origin.sock")
                        .to_string_lossy()
                        .into(),
                ),
                port: None,
            }),
            destination: Some(et_core::proto::SocketEndpoint {
                name: Some("/tmp/destination.sock".to_owned()),
                port: None,
            }),
            environmentvariable: Some("ET_RS_SSH_CONFIG_REMOTE_FORWARD".to_owned()),
        }],
        environmentvariables: HashMap::new(),
    };

    let (stream, _) = server.handshake(ID_A);
    let (_, initial) = runtime_support::initialize(stream, &key, payload);
    assert!(initial
        .error
        .is_some_and(|error| error.contains("Do not set a source")));
    server.runtime.shutdown().unwrap();
}

#[test]
fn jumphost_payload_is_relayed_to_the_registered_terminal() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let payload = InitialPayload {
        jumphost: Some(true),
        reversetunnels: Vec::new(),
        environmentvariables: HashMap::new(),
    };
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let (client_received_tx, client_received_rx) = std::sync::mpsc::sync_channel(0);
    let terminal_handshake = std::thread::spawn(move || {
        let packet = et_net::local_packet::read_local_packet(&mut terminal).unwrap();
        assert_eq!(
            packet.header(),
            et_core::proto::TerminalPacketType::JumphostInit as u8
        );
        let relayed = InitialPayload::decode(packet.payload()).unwrap();
        et_net::local_packet::write_local_packet(
            &mut terminal,
            &et_core::packet::Packet::new(
                et_core::proto::TerminalPacketType::JumphostInit as u8,
                InitialResponse { error: None }.encode_to_vec(),
            ),
        )
        .unwrap();
        client_received_rx.recv_timeout(TIMEOUT).unwrap();
        relayed
    });
    let (_client, initial) = runtime_support::initialize(stream, &key, payload);
    assert!(initial.error.is_none(), "{:?}", initial.error);
    client_received_tx.send(()).unwrap();
    let relayed = terminal_handshake.join().unwrap();
    assert_eq!(relayed.jumphost, Some(true));
    server.runtime.shutdown().unwrap();
}

#[test]
fn capped_malformed_unknown_and_mismatched_handshakes_are_typed() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);

    let cases = [
        (
            (et_net::handshake::MAX_HANDSHAKE_PROTO_LEN + 1)
                .to_le_bytes()
                .to_vec(),
            ConnectStatus::InvalidKey,
        ),
        (
            {
                let mut wire = (2i64).to_le_bytes().to_vec();
                wire.extend_from_slice(&[0xff, 0xff]);
                wire
            },
            ConnectStatus::InvalidKey,
        ),
    ];
    for (wire, status) in cases {
        let mut stream = TcpStream::connect(server.address).unwrap();
        bound(&stream);
        stream.write_all(&wire).unwrap();
        let response: ConnectResponse = read_proto_limited(&mut stream, 64 * 1024).unwrap();
        assert_eq!(response.status, Some(status as i32));
    }

    for id in ["short", "aaaaaaaaaaaaaaa!", "aaaaaaaaaaaaaaaaa"] {
        let mut malformed = TcpStream::connect(server.address).unwrap();
        bound(&malformed);
        write_proto(&mut malformed, &client_request(id)).unwrap();
        let response: ConnectResponse = read_proto_limited(&mut malformed, 64 * 1024).unwrap();
        assert_eq!(response.status, Some(ConnectStatus::InvalidKey as i32));
    }

    let mut unknown = TcpStream::connect(server.address).unwrap();
    bound(&unknown);
    write_proto(&mut unknown, &client_request("unknownunknown00")).unwrap();
    let response: ConnectResponse = read_proto_limited(&mut unknown, 64 * 1024).unwrap();
    assert_eq!(response.status, Some(ConnectStatus::InvalidKey as i32));

    let mut mismatch = TcpStream::connect(server.address).unwrap();
    bound(&mismatch);
    write_proto(
        &mut mismatch,
        &ConnectRequest {
            client_id: Some(ID_A.to_owned()),
            version: Some(5),
        },
    )
    .unwrap();
    let response: ConnectResponse = read_proto_limited(&mut mismatch, 64 * 1024).unwrap();
    assert_eq!(
        response.status,
        Some(ConnectStatus::MismatchedProtocol as i32)
    );
    server.runtime.shutdown().unwrap();
}
