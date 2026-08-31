#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectRequest, ConnectResponse, ConnectStatus, InitialPayload, InitialResponse,
    PortForwardSourceRequest, SocketEndpoint,
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
    assert_eq!(server.handle.session_state(ID_A).unwrap(), None);

    for (header, bytes) in [(1, default_payload().encode_to_vec()), (253, vec![0xff])] {
        let (stream, response) = server.handshake(ID_A);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        let mut client = Connection::new_client(stream, &good_key);
        client.write_packet(header, &bytes).unwrap();
        let packet = client.read_packet().unwrap();
        let response = InitialResponse::decode(packet.payload()).unwrap();
        assert!(response.error.is_some());
        assert_eq!(server.handle.session_state(ID_A).unwrap(), None);
    }
    server.runtime.shutdown().unwrap();
}

struct DelayedResolver {
    address: SocketAddr,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    finished: mpsc::SyncSender<()>,
}

impl et_net::forward::ForwardResolver for DelayedResolver {
    fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
        let _ = self.finished.send(());
        Ok(vec![self.address])
    }
}

#[test]
fn delayed_valid_reverse_forward_times_out_rolls_back_and_resets_slot() {
    let probe = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let mut server = TestRuntime::start_with_forward_resolver(Arc::new(DelayedResolver {
        address,
        entered: entered_tx,
        release: Mutex::new(release_rx),
        finished: finished_tx,
    }));
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some("delayed.valid.test".to_owned()),
                port: Some(i32::from(address.port())),
            }),
            destination: Some(SocketEndpoint {
                name: Some("localhost".to_owned()),
                port: Some(1),
            }),
            environmentvariable: None,
        }],
        environmentvariables: HashMap::new(),
    };
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let started = Instant::now();
    let (initial_tx, initial_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let (_, initial) = runtime_support::initialize(stream, &key, payload);
        let _ = initial_tx.send(initial);
    });
    entered_rx.recv_timeout(TIMEOUT).unwrap();
    let initial = initial_rx.recv_timeout(Duration::from_secs(8)).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "forwarding timeout missed the server initialization deadline"
    );
    let encoded = initial.error.as_deref().expect("typed forwarding timeout");
    assert!(et_net::forward::decode_forward_timeout(encoded).is_some());
    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();
    // Runtime shutdown must not own or join a resolver currently blocked in
    // the process-wide bounded executor.
    server.runtime.shutdown().unwrap();
    release_tx.send(()).unwrap();
    finished_rx.recv_timeout(TIMEOUT).unwrap();
    TcpListener::bind(address).expect("cancelled forwarding setup left a listener behind");
}

struct StalledTcpHelperResolver {
    address: SocketAddr,
    helper: PathBuf,
}

impl et_net::forward::ForwardResolver for StalledTcpHelperResolver {
    fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![self.address])
    }

    fn listen_tcp_as_user(
        &self,
        address: SocketAddr,
        uid: u32,
        gid: u32,
        deadline: Instant,
    ) -> std::io::Result<TcpListener> {
        et_net::user_socket_ops::listen_tcp_as_user_deadline_with_helper(
            address,
            uid,
            gid,
            deadline,
            &self.helper,
        )
    }
}

#[test]
fn stalled_privileged_tcp_helper_honors_initialization_deadline_and_resets_slot() {
    let probe = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let helper_dir = support::TestDir::new();
    let event = helper_dir.path().join("tcp-helper.event");
    assert!(std::process::Command::new("mkfifo")
        .arg(&event)
        .status()
        .unwrap()
        .success());
    let event_control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&event)
        .unwrap();
    let pid_path = helper_dir.path().join("tcp-helper.pid");
    let helper = helper_dir.path().join("tcp-helper.py");
    fs::write(
        &helper,
        format!(
            "#!/usr/bin/python3\nimport os, socket\nhost, port = os.environ['ET_RS_USER_SOCKET_PATH'].rsplit(':', 1)\ns = socket.socket(socket.AF_INET)\ns.bind((host, int(port)))\ns.listen(1)\nopen(r'{}', 'w').write(str(os.getpid()))\nopen(r'{}', 'wb').write(b'x')\nos.read(0, 1)\n",
            pid_path.display(),
            event.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let mut server = TestRuntime::start_with_forward_resolver(Arc::new(StalledTcpHelperResolver {
        address,
        helper: helper.clone(),
    }));
    let _terminal = server.register(ID_A, KEY_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: vec![PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some("stalled.helper.test".to_owned()),
                port: Some(i32::from(address.port())),
            }),
            destination: Some(SocketEndpoint {
                name: Some("localhost".to_owned()),
                port: Some(1),
            }),
            environmentvariable: None,
        }],
        environmentvariables: HashMap::new(),
    };
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let started = Instant::now();
    let (initial_tx, initial_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let (_, initial) = runtime_support::initialize(stream, &key, payload);
        let _ = initial_tx.send(initial);
    });
    let (event_tx, event_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut event_control = event_control;
        let mut byte = [0];
        let result = event_control.read_exact(&mut byte);
        let _ = event_tx.send(result);
    });
    event_rx
        .recv_timeout(TIMEOUT)
        .expect("privileged TCP helper did not bind and enter no-reply")
        .unwrap();
    let initial = initial_rx
        .recv_timeout(Duration::from_secs(8))
        .expect("privileged TCP helper exceeded initialization deadline");
    assert!(started.elapsed() < Duration::from_secs(8));
    assert!(initial
        .error
        .as_deref()
        .and_then(et_net::forward::decode_forward_timeout)
        .is_some());
    server
        .handle
        .wait_for_state(ID_A, SessionState::Registered, TIMEOUT)
        .unwrap();
    let pid = fs::read_to_string(pid_path)
        .unwrap()
        .trim()
        .parse()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .unwrap();
    assert_eq!(
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
        rustix::io::Errno::CHILD,
        "timed-out privileged helper was not killed and reaped"
    );
    TcpListener::bind(address).expect("timed-out privileged helper left a listener behind");
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
fn occupied_reverse_row_is_reported_while_usable_row_stays_live() {
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
    let (mut client, initial) = runtime_support::initialize(stream, &key, payload);
    let report = et_net::reverse_report::decode_skipped_rows(initial.error.as_deref().unwrap(), 2)
        .unwrap()
        .unwrap();

    assert_eq!(
        report,
        [et_net::reverse_report::SkippedRow {
            index: 0,
            reason: et_net::reverse_report::SkipReason::Bind,
        }]
    );
    runtime_support::acknowledge_skip_report(&mut client);
    let usable = std::os::unix::net::UnixStream::connect(&usable_path).unwrap();
    drop(usable);
    drop(client);
    server.runtime.shutdown().unwrap();
}

#[test]
fn unacknowledged_report_releases_sibling_before_activation() {
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
fn reverse_row_and_report_bounds_are_global_fatal() {
    let cases = [
        vec![Default::default(); et_net::reverse_report::MAX_REVERSE_ROWS + 1],
        vec![
            et_core::proto::PortForwardSourceRequest {
                source: Some(et_core::proto::SocketEndpoint {
                    name: Some("a".repeat(256)),
                    port: Some(1),
                }),
                destination: Some(et_core::proto::SocketEndpoint {
                    name: Some("127.0.0.1".to_owned()),
                    port: Some(1),
                }),
                environmentvariable: None,
            };
            et_net::reverse_report::MAX_REVERSE_ROWS
        ],
    ];
    for requests in cases {
        let count = requests.len();
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
        assert_eq!(
            et_net::reverse_report::decode_skipped_rows(&error, count).unwrap(),
            None
        );
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
fn hostile_origin_marker_does_not_change_origin_independent_report() {
    fn run(marker: Option<&str>) -> String {
        let mut server = TestRuntime::start();
        let _terminal = server.register(ID_A, KEY_A);
        let key = passkey_to_key(KEY_A).unwrap();
        let occupied_path = server.dir.path().join("hostile-origin.sock");
        let usable_path = server.dir.path().join("hostile-usable.sock");
        let _occupied = std::os::unix::net::UnixListener::bind(&occupied_path).unwrap();
        let request = |path: &std::path::Path, environmentvariable: Option<String>| {
            et_core::proto::PortForwardSourceRequest {
                source: Some(et_core::proto::SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                destination: Some(et_core::proto::SocketEndpoint {
                    name: Some("/tmp/destination.sock".to_owned()),
                    port: None,
                }),
                environmentvariable,
            }
        };
        let payload = InitialPayload {
            jumphost: Some(false),
            reversetunnels: vec![
                request(&occupied_path, marker.map(str::to_owned)),
                request(&usable_path, None),
            ],
            environmentvariables: HashMap::new(),
        };

        let (stream, _) = server.handshake(ID_A);
        let (mut client, initial) = runtime_support::initialize(stream, &key, payload);
        let report = initial.error.unwrap();
        runtime_support::acknowledge_skip_report(&mut client);
        let usable = std::os::unix::net::UnixStream::connect(&usable_path).unwrap();
        drop(usable);
        drop(client);
        server.runtime.shutdown().unwrap();
        report
    }

    let ordinary = run(None);
    let hostile = run(Some("ET_RS_SSH_CONFIG_REMOTE_FORWARD"));

    assert_eq!(hostile, ordinary);
    assert_eq!(
        et_net::reverse_report::decode_skipped_rows(&hostile, 2)
            .unwrap()
            .unwrap(),
        [et_net::reverse_report::SkippedRow {
            index: 0,
            reason: et_net::reverse_report::SkipReason::Bind,
        }]
    );
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
