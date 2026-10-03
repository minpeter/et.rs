#![forbid(unsafe_code)]
#![cfg(unix)]

mod runtime_support;
mod support;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{ConnectStatus, TermInit, TerminalPacketType, TerminalUserInfo};
use et_net::connection::{Connection, RecoveryExchange};
use et_net::handshake::client_handshake;
use et_net::local_packet::{read_local_packet, write_local_packet, LocalPacketError};
use et_server::{Runtime, SessionState};
use prost::Message;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};
use support::TestDir;

fn start(dir: TestDir, seconds: i32) -> TestRuntime {
    let path = et_server::path::select_router_path_for(
        rustix::process::getuid().as_raw(),
        Some(&dir.socket()),
        None,
        None,
    )
    .unwrap();
    let runtime =
        Runtime::start_with_settings(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, path, 128, seconds)
            .unwrap();
    let handle = runtime.handle();
    let address = runtime.tcp_addresses()[0];
    TestRuntime {
        dir,
        runtime,
        handle,
        address,
    }
}

fn initial(server: &TestRuntime, timeout: Option<i32>) -> (Connection, UnixStream, TermInit) {
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let mut payload = default_payload();
    payload.disconnect_timeout_seconds = timeout;
    let (client, response) = initialize(stream, &passkey_to_key(KEY_A).unwrap(), payload);
    assert_eq!(response.error, None);
    let packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(packet.header(), TerminalPacketType::TerminalInit as u8);
    let init = TermInit::decode(packet.payload()).unwrap();
    // Store the override, not the effective value. An inherited default must
    // be re-resolved against the replacement server's configuration.
    assert_eq!(init.disconnect_timeout_seconds, timeout);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    (client, terminal, init)
}

fn assert_disconnect(client: Connection, terminal: &mut UnixStream, expires: bool) {
    client
        .try_clone_stream()
        .unwrap()
        .shutdown(Shutdown::Both)
        .unwrap();
    drop(client);
    terminal
        .set_read_timeout(Some(if expires {
            TIMEOUT
        } else {
            Duration::from_millis(1400)
        }))
        .unwrap();
    if expires {
        assert_eq!(
            read_local_packet(terminal).unwrap().header(),
            TerminalPacketType::TerminalClose as u8
        );
    } else {
        assert!(
            matches!(read_local_packet(terminal), Err(LocalPacketError::Io(error)) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
        );
    }
}

fn register_resumed(server: &TestRuntime, id: &str, timeout: Option<i32>) -> UnixStream {
    let mut terminal = UnixStream::connect(server.dir.socket()).unwrap();
    let registration = TerminalUserInfo {
        id: Some(id.to_owned()),
        passkey: Some(KEY_A.to_owned()),
        uid: Some(i64::from(rustix::process::getuid().as_raw())),
        gid: Some(i64::from(rustix::process::getgid().as_raw())),
        ptyactive: Some(true),
        disconnect_timeout_seconds: timeout,
        ..TerminalUserInfo::default()
    };
    write_local_packet(
        &mut terminal,
        &Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            registration.encode_to_vec(),
        ),
    )
    .unwrap();
    server.handle.wait_registered(id, TIMEOUT).unwrap();
    terminal
}

#[test]
fn server_default_and_session_overrides_control_real_disconnected_sessions() {
    for (global, session, expires) in [
        (1, None, true),
        (1, Some(0), false),
        (0, Some(1), true),
        (1, Some(10), false),
        (0, None, false),
    ] {
        let mut server = start(TestDir::new(), global);
        let (client, mut terminal, _) = initial(&server, session);
        assert_disconnect(client, &mut terminal, expires);
        server.runtime.shutdown().unwrap();
    }
}

#[test]
fn restart_re_resolves_inherited_default_but_preserves_explicit_override() {
    for (old_default, new_default, session, expires) in [
        (0, 1, None, true),
        (1, 0, None, false),
        (0, 1, Some(0), false),
        (10, 0, Some(1), true),
    ] {
        let mut server = start(TestDir::new(), old_default);
        let (client, terminal, init) = initial(&server, session);
        server.runtime.shutdown().unwrap();
        drop(client);
        drop(terminal);
        let mut server = start(server.dir, new_default);
        let mut terminal = register_resumed(&server, ID_A, init.disconnect_timeout_seconds);
        let key = passkey_to_key(KEY_A).unwrap();
        let mut stream = TcpStream::connect(server.address).unwrap();
        let response =
            client_handshake(&mut stream, ID_A, &key, false, Instant::now() + TIMEOUT).unwrap();
        assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
        assert_eq!(response.reset_required, Some(true));
        let salt = response.reset_salt.unwrap().try_into().unwrap();
        let mut client = Connection::new_client(stream, &key);
        client
            .establish_reset(TIMEOUT, RecoveryExchange::client(Some(salt)))
            .unwrap();
        server
            .handle
            .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
            .unwrap();
        assert_disconnect(client, &mut terminal, expires);
        server.runtime.shutdown().unwrap();
    }
}

#[test]
fn lifecycle_expires_unclaimed_resume_after_real_recovery_grace_but_not_explicit_zero() {
    let mut server = start(TestDir::new(), 1);
    let began = Instant::now();
    let mut expires = register_resumed(&server, ID_A, None);
    let mut unlimited = register_resumed(&server, runtime_support::ID_B, Some(0));
    expires
        .set_read_timeout(Some(et_core::RECOVERY_GRACE + TIMEOUT))
        .unwrap();
    assert_eq!(
        read_local_packet(&mut expires).unwrap().header(),
        TerminalPacketType::TerminalClose as u8
    );
    assert!(began.elapsed() >= et_core::RECOVERY_GRACE);
    server.handle.wait_disconnected(ID_A, TIMEOUT).unwrap();
    unlimited
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(
        matches!(read_local_packet(&mut unlimited), Err(LocalPacketError::Io(error)) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
    );
    server
        .handle
        .wait_registered(runtime_support::ID_B, TIMEOUT)
        .unwrap();
    server.runtime.shutdown().unwrap();
}
