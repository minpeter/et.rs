use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{
    ConnectResponse, ConnectStatus, FlowControlMode, InitialPayload, InitialResponse,
    TerminalBuffer, TerminalPacketType, TerminalUserInfo,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::{read_local_packet, write_local_packet};
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
    let mut stream = et_net::local::connect(path).unwrap();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        TerminalUserInfo {
            id: Some(ID.to_owned()),
            passkey: Some(KEY.to_owned()),
            uid: Some(i64::from(rustix::process::getuid().as_raw())),
            gid: Some(i64::from(rustix::process::getgid().as_raw())),
            fd: None,
        }
        .encode_to_vec(),
    );
    write_local_packet(&mut stream, &packet).unwrap();
    handle.wait_registered(ID, TIMEOUT).unwrap();
    stream
}

fn handshake(address: SocketAddr) -> (TcpStream, ConnectResponse) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    write_proto(&mut stream, &client_request(ID)).unwrap();
    let response = read_proto_limited(&mut stream, 64 * 1024).unwrap();
    (stream, response)
}
