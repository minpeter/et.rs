use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{
    ConnectResponse, ConnectStatus, FlowControlMode, InitialPayload, InitialResponse,
    TerminalBuffer, TerminalPacketType, TerminalUserInfo,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::{
    read_local_packet, write_local_packet, RouterFraming, RouterStreamDecoder,
};
use prost::Message;

use super::Runtime;
use crate::path::select_router_path_for;

const ID: &str = "flowpause0000001";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "et-rs-recovery-pause-test-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("router.sock")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn terminal_hup_after_returning_status_delivers_final_output_only_to_recovered_connection() {
    // Given: an active flow-controlled session and a recovery handler blocked
    // immediately after exposing ReturningClient but before permit completion.
    let directory = TestDirectory::new();
    let router_path = select_router_path_for(
        rustix::process::getuid().as_raw(),
        Some(&directory.socket()),
        None,
        None,
    )
    .unwrap();
    let mut runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path).unwrap();
    let handle = runtime.handle();
    let address = runtime.tcp_addresses()[0];
    let mut terminal = register(&directory.socket(), &handle);
    let (stream, response) = handshake(address);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let mut client = Connection::new_client(stream, &passkey_to_key(KEY).unwrap());
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: Vec::new(),
        environmentvariables: HashMap::new(),
        flowcontrol: Some(FlowControlMode::Backpressure as i32),

        no_pty: None,
        command: None,

        supports_exit_status: None,
        no_shell: None,
        disconnect_timeout_seconds: None,
    };
    client.write_packet(253, &payload.encode_to_vec()).unwrap();
    let initial = client.read_packet().unwrap();
    assert_eq!(
        InitialResponse::decode(initial.payload()).unwrap().error,
        None
    );
    assert_eq!(
        read_local_packet(&mut terminal).unwrap().header(),
        TerminalPacketType::TerminalInit as u8
    );
    let mut old_stream = client.try_clone_stream().unwrap();
    old_stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (status_tx, status_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    crate::runtime_handler::install_returning_status_hook(ID, status_tx, release_rx);
    let (returning, response) = handshake(address);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    status_rx
        .recv_timeout(TIMEOUT)
        .expect("recovery handler did not reach the post-status barrier");
    let (client_tx, client_rx) = mpsc::sync_channel(1);
    let recovering = std::thread::spawn(move || {
        client.recover(returning).unwrap();
        client
            .write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .unwrap();
        client_tx.send(client).unwrap();
    });

    // When: the terminal queues its final output while permit completion
    // remains blocked at that exact barrier, then the real terminal socket
    // reaches HUP and lifecycle scans the returning raw socket.
    let (queued_tx, queued_rx) = mpsc::sync_channel(1);
    runtime
        .core
        .sessions
        .active(ID)
        .unwrap()
        .unwrap()
        .install_flow_enqueue_hook(queued_tx);
    let final_output = TerminalBuffer {
        buffer: Some(b"final-after-returning-status".to_vec()),

        is_stderr: None,
    };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            final_output.encode_to_vec(),
        ),
    )
    .unwrap();
    queued_rx
        .recv_timeout(TIMEOUT)
        .expect("terminal output was not admitted to the flow queue");
    let (scan_tx, scan_rx) = mpsc::sync_channel(1);
    crate::runtime_lifecycle::install_raw_scan_hook(ID, scan_tx);
    drop(terminal);
    scan_rx
        .recv_timeout(TIMEOUT)
        .expect("terminal lifecycle did not complete its raw-socket scan");

    // Then: releasing recovery installs the protected candidate, delivers the
    // packet exactly once there, and retires the old stream without bytes.
    release_tx.send(()).unwrap();
    let mut client = client_rx
        .recv_timeout(TIMEOUT)
        .expect("client recovery did not complete after terminal HUP");
    recovering.join().unwrap();
    let mut byte = [0u8; 1];
    let old_read = old_stream.read(&mut byte);
    assert!(
        match &old_read {
            Ok(0) => true,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                true
            }
            Ok(_) | Err(_) => false,
        },
        "final output reached the old connection after terminal HUP: {old_read:?}"
    );
    assert_eq!(
        client.read_packet().unwrap().header(),
        TerminalPacketType::KeepAlive as u8
    );
    let delivered = client.read_packet().unwrap();
    assert_eq!(delivered.header(), TerminalPacketType::TerminalBuffer as u8);
    assert_eq!(
        TerminalBuffer::decode(delivered.payload()).unwrap(),
        final_output
    );
    if let Ok(packet) = client.read_packet() {
        assert_eq!(
            packet.header(),
            TerminalPacketType::KeepAlive as u8,
            "final terminal output was duplicated before EOF"
        );
        assert!(
            client.read_packet().is_err(),
            "terminal EOF must follow the recovery keepalive"
        );
    }
    runtime.shutdown().unwrap();
}

fn register(
    path: &Path,
    handle: &crate::runtime_handle::RuntimeHandle,
) -> et_net::local::LocalStream {
    register_resume(path, handle, false, None)
}

fn register_resume(
    path: &Path,
    handle: &crate::runtime_handle::RuntimeHandle,
    resumed: bool,
    timeout: Option<i32>,
) -> et_net::local::LocalStream {
    let mut stream = et_net::local::connect(path).unwrap();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        TerminalUserInfo {
            id: Some(ID.to_owned()),
            passkey: Some(KEY.to_owned()),
            uid: Some(i64::from(rustix::process::getuid().as_raw())),
            gid: Some(i64::from(rustix::process::getgid().as_raw())),
            fd: None,
            ptyactive: resumed.then_some(true),
            hadreversetunnels: None,
            disconnect_timeout_seconds: timeout,
            upstream_router_stream: None,
        }
        .encode_to_vec(),
    );
    write_local_packet(&mut stream, &packet).unwrap();
    handle.wait_registered(ID, TIMEOUT).unwrap();
    stream
}

/// One message of the upstream raw stream a terminal registered without the
/// startup sentinel reads once its pty runs.
fn read_upstream(terminal: &mut et_net::local::LocalStream) -> Packet {
    RouterStreamDecoder::new(RouterFraming::Upstream)
        .read_from(terminal)
        .unwrap()
        .expect("router message before the read timeout")
}

fn handshake(address: SocketAddr) -> (TcpStream, ConnectResponse) {
    handshake_on(TcpStream::connect(address).unwrap())
}

fn handshake_on(mut stream: TcpStream) -> (TcpStream, ConnectResponse) {
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    write_proto(&mut stream, &client_request(ID)).unwrap();
    let response = read_proto_limited(&mut stream, 64 * 1024).unwrap();
    (stream, response)
}

/// A client socket whose receive window is fixed at `bytes` from the SYN, so
/// output beyond it stays in the server's send queue until the client reads.
fn connect_with_receive_buffer(address: SocketAddr, bytes: usize) -> TcpStream {
    use rustix::net::{connect, socket, sockopt, AddressFamily, SocketType};
    let socket = socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    sockopt::set_socket_recv_buffer_size(&socket, bytes).unwrap();
    connect(&socket, &address).unwrap();
    TcpStream::from(socket)
}

#[test]
fn unclaimed_resumes_obey_grace_override_and_exact_expiry_boundary() {
    for (global, session, expires_after) in [
        (1, None, Some(60)),
        (90, None, Some(90)),
        (90, Some(1), Some(60)),
        (1, Some(120), Some(120)),
        (1, Some(0), None),
        (0, None, None),
        (0, Some(1), Some(60)),
    ] {
        let directory = TestDirectory::new();
        let router_path = select_router_path_for(
            rustix::process::getuid().as_raw(),
            Some(&directory.socket()),
            None,
            None,
        )
        .unwrap();
        let mut runtime = Runtime::start_with_settings(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            router_path,
            128,
            global,
        )
        .unwrap();
        let mut terminal = register_resume(&directory.socket(), &runtime.handle(), true, session);
        terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
        let (registration, registered_at) = runtime.core.registry.resumed().unwrap().pop().unwrap();
        let before = registered_at + Duration::from_secs(expires_after.unwrap_or(1000))
            - Duration::from_nanos(1);
        crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, before).unwrap();
        assert!(runtime
            .core
            .registry
            .contains(&registration.identity())
            .unwrap());
        crate::runtime_lifecycle::expire_unclaimed_resumes(
            &runtime.core,
            before + Duration::from_nanos(1),
        )
        .unwrap();
        assert_eq!(
            runtime
                .core
                .registry
                .contains(&registration.identity())
                .unwrap(),
            expires_after.is_none()
        );
        if expires_after.is_some() {
            assert!(runtime.core.registry.was_removed(ID).unwrap());
            assert_eq!(
                read_upstream(&mut terminal).header(),
                TerminalPacketType::TerminalClose as u8
            );
        }
        runtime.shutdown().unwrap();
    }
}

#[test]
fn authenticated_reconnect_blocks_expiry_only_while_claim_is_pending() {
    let directory = TestDirectory::new();
    let router_path = select_router_path_for(
        rustix::process::getuid().as_raw(),
        Some(&directory.socket()),
        None,
        None,
    )
    .unwrap();
    let mut runtime =
        Runtime::start_with_settings(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path, 128, 1)
            .unwrap();
    let mut terminal = register_resume(&directory.socket(), &runtime.handle(), true, None);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = runtime.core.registry.get(ID).unwrap().unwrap();

    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut reconnect = runtime.core.raw_sockets.track(&stream).unwrap();
    reconnect.assign(registration.identity()).unwrap();
    reconnect.authenticate().unwrap();

    let expired = Instant::now() + et_core::RECOVERY_GRACE + Duration::from_secs(1);
    crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, expired).unwrap();
    assert!(runtime
        .core
        .registry
        .contains(&registration.identity())
        .unwrap());

    drop(reconnect);
    crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, expired).unwrap();
    assert!(!runtime
        .core
        .registry
        .contains(&registration.identity())
        .unwrap());
    assert_eq!(
        read_upstream(&mut terminal).header(),
        TerminalPacketType::TerminalClose as u8
    );
    drop(peer);
    runtime.shutdown().unwrap();
}

#[test]
fn unclaimed_sweep_does_not_close_starting_active_or_fresh_terminals() {
    for activate in [false, true] {
        let directory = TestDirectory::new();
        let router_path = select_router_path_for(
            rustix::process::getuid().as_raw(),
            Some(&directory.socket()),
            None,
            None,
        )
        .unwrap();
        let mut runtime =
            Runtime::start_with_settings(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path, 128, 1)
                .unwrap();
        let mut terminal = register_resume(&directory.socket(), &runtime.handle(), true, None);
        terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
        let registration = runtime.core.registry.get(ID).unwrap().unwrap();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let crate::session_table::SessionClaim::New { start, .. } = runtime
            .core
            .sessions
            .claim(registration.clone(), &stream, &runtime.core.registry)
            .unwrap()
        else {
            panic!("new claim expected")
        };
        let later = std::time::Instant::now() + Duration::from_secs(1000);
        crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, later).unwrap();
        assert!(runtime
            .core
            .registry
            .contains(&registration.identity())
            .unwrap());
        if activate {
            let router = runtime.core.registry.clone_stream(&registration).unwrap();
            let active = crate::session::ActiveSession::new(
                Connection::new_server(stream, &registration.key),
                &router,
                None,
            )
            .unwrap();
            start.activate(std::sync::Arc::new(active)).unwrap();
            crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, later).unwrap();
            assert!(runtime
                .core
                .registry
                .contains(&registration.identity())
                .unwrap());
        } else {
            drop(start); // Failed initialization rolls back to Registered.
            crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, later).unwrap();
            assert!(!runtime
                .core
                .registry
                .contains(&registration.identity())
                .unwrap());
            assert_eq!(
                read_upstream(&mut terminal).header(),
                TerminalPacketType::TerminalClose as u8
            );
            assert!(matches!(
                runtime
                    .core
                    .sessions
                    .claim(registration, &stream, &runtime.core.registry),
                Err(crate::session_table::SessionTableError::ObsoleteRegistration)
            ));
            drop(terminal);
            let _fresh_terminal = register(&directory.socket(), &runtime.handle());
            crate::runtime_lifecycle::expire_unclaimed_resumes(&runtime.core, later).unwrap();
            assert!(runtime.core.registry.get(ID).unwrap().is_some());
        }
        drop(peer);
        runtime.shutdown().unwrap();
    }
}

#[test]
fn terminal_hup_releases_session_whose_held_output_no_client_can_recover() {
    // A full output queue, and an exit status held behind queued output, are
    // both retained only for a client that recovers. Once the terminal hangs
    // up the router drops the slot, so no client can.
    for exit_status in [false, true] {
        // Given: an active session whose client transport is gone.
        let directory = TestDirectory::new();
        let router_path = select_router_path_for(
            rustix::process::getuid().as_raw(),
            Some(&directory.socket()),
            None,
            None,
        )
        .unwrap();
        let mut runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path).unwrap();
        let address = runtime.tcp_addresses()[0];
        let mut terminal = register(&directory.socket(), &runtime.handle());
        let (stream, response) = handshake(address);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        let mut client = Connection::new_client(stream, &passkey_to_key(KEY).unwrap());
        let payload = InitialPayload {
            jumphost: Some(false),
            reversetunnels: Vec::new(),
            environmentvariables: HashMap::new(),
            flowcontrol: None,
            no_pty: None,
            command: None,
            supports_exit_status: Some(true),
            no_shell: None,
            disconnect_timeout_seconds: None,
        };
        client.write_packet(253, &payload.encode_to_vec()).unwrap();
        client.read_packet().unwrap();
        read_local_packet(&mut terminal).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let session = loop {
            if let Some(session) = runtime.core.sessions.active(ID).unwrap() {
                break session;
            }
            assert!(Instant::now() < deadline, "session never became active");
            std::thread::sleep(Duration::from_millis(5));
        };
        drop(client);
        while session.connection_state().unwrap().0 {
            assert!(Instant::now() < deadline, "client drop was not noticed");
            std::thread::sleep(Duration::from_millis(5));
        }

        // When: the terminal produces output nobody drains, then hangs up.
        let hangup = terminal.try_clone().unwrap();
        let output = Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            TerminalBuffer {
                buffer: Some(vec![b'x'; 4096]),
                is_stderr: None,
            }
            .encode_to_vec(),
        );
        let writer = std::thread::spawn(move || {
            if exit_status {
                write_local_packet(&mut terminal, &output).unwrap();
                let status = et_core::proto::TerminalExitStatus { exitcode: Some(0) };
                let status = Packet::new(
                    TerminalPacketType::TerminalExitStatus as u8,
                    status.encode_to_vec(),
                );
                write_local_packet(&mut terminal, &status).unwrap();
            } else {
                // Blocks once the bridge stops reading; HUP ends it.
                while write_local_packet(&mut terminal, &output).is_ok() {}
            }
        });
        if exit_status {
            writer.join().unwrap();
            hangup.shutdown(std::net::Shutdown::Both).unwrap();
        } else {
            while session.can_buffer_write(64 * 1024).unwrap() {
                assert!(Instant::now() < deadline, "terminal output never filled");
                std::thread::sleep(Duration::from_millis(5));
            }
            hangup.shutdown(std::net::Shutdown::Both).unwrap();
            writer.join().unwrap();
        }

        // Then: the bridge ends and releases the session.
        let released = std::sync::Arc::downgrade(&session);
        drop(session);
        let deadline = Instant::now() + TIMEOUT;
        while released.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "bridge kept an unrecoverable session (exit_status={exit_status})"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        runtime.shutdown().unwrap();
    }
}

#[test]
fn ended_terminal_keeps_the_transport_open_until_the_client_reads_its_last_output() {
    // Given: an `et -T` session whose client window is smaller than the
    // command's last output, so most of it waits in etserver's send queue.
    const OUTPUT: usize = 48 * 1024;
    let directory = TestDirectory::new();
    let router_path = select_router_path_for(
        rustix::process::getuid().as_raw(),
        Some(&directory.socket()),
        None,
        None,
    )
    .unwrap();
    let mut runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path).unwrap();
    let address = runtime.tcp_addresses()[0];
    let mut terminal = register(&directory.socket(), &runtime.handle());
    let (stream, response) = handshake_on(connect_with_receive_buffer(address, 4 * 1024));
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let mut client = Connection::new_client(stream, &passkey_to_key(KEY).unwrap());
    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: Vec::new(),
        environmentvariables: HashMap::new(),
        flowcontrol: None,
        no_pty: Some(true),
        command: Some(format!("head -c {OUTPUT} /dev/zero")),
        supports_exit_status: Some(true),
        no_shell: None,
        disconnect_timeout_seconds: None,
    };
    client.write_packet(253, &payload.encode_to_vec()).unwrap();
    let initial = client.read_packet().unwrap();
    assert_eq!(
        InitialResponse::decode(initial.payload()).unwrap().error,
        None
    );
    assert_eq!(
        read_local_packet(&mut terminal).unwrap().header(),
        TerminalPacketType::TerminalInit as u8
    );
    let deadline = Instant::now() + TIMEOUT;
    let session = loop {
        if let Some(session) = runtime.core.sessions.active(ID).unwrap() {
            break std::sync::Arc::downgrade(&session);
        }
        assert!(Instant::now() < deadline, "session never became active");
        std::thread::sleep(Duration::from_millis(5));
    };

    // When: the command writes that output and exits, and after the bridge
    // has ended the client sends the keep-alive `et` sends per 512 KiB read.
    let output = TerminalBuffer {
        buffer: Some(vec![b'x'; OUTPUT]),
        is_stderr: None,
    };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            output.encode_to_vec(),
        ),
    )
    .unwrap();
    let status = et_core::proto::TerminalExitStatus { exitcode: Some(3) };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalExitStatus as u8,
            status.encode_to_vec(),
        ),
    )
    .unwrap();
    drop(terminal);
    while session
        .upgrade()
        .is_some_and(|session| !session.is_shutting_down())
    {
        assert!(Instant::now() < deadline, "the terminal bridge never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();

    // Then: the client still reads all of the output, the exit status, and
    // EOF, instead of a connection reset that discarded the queued tail.
    let mut received = 0;
    let exitcode = loop {
        let packet = client.read_packet().unwrap_or_else(|error| {
            panic!("lost the session tail after {received} bytes: {error:?}")
        });
        match packet.header() {
            header if header == TerminalPacketType::TerminalBuffer as u8 => {
                received += et_core::packet::decode_terminal_buffer(packet.payload())
                    .map(|(bytes, _)| bytes.len())
                    .unwrap_or_else(|| {
                        TerminalBuffer::decode(packet.payload())
                            .unwrap()
                            .buffer
                            .unwrap_or_default()
                            .len()
                    });
            }
            header if header == TerminalPacketType::TerminalExitStatus as u8 => {
                break et_core::proto::TerminalExitStatus::decode(packet.payload())
                    .unwrap()
                    .exitcode;
            }
            header => assert_eq!(header, TerminalPacketType::KeepAlive as u8),
        }
    };
    assert_eq!(received, OUTPUT);
    assert_eq!(exitcode, Some(3));
    assert!(
        client.read_packet().is_err(),
        "EOF must follow the exit status"
    );
    drop(client);
    runtime.shutdown().unwrap();
}
