#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{
    ConnectResponse, InitialPayload, InitialResponse, TerminalPacketType, TerminalUserInfo,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::{
    parse_registration_status, read_local_packet, write_local_packet, LocalPacketError,
    RouterFraming, RouterStreamDecoder,
};
use et_server::path::select_router_path_for;
use et_server::{Runtime, RuntimeHandle};
use prost::Message;

use super::support::TestDir;

pub const ID_A: &str = "aaaaaaaaaaaaaaaa";
pub const ID_B: &str = "bbbbbbbbbbbbbbbb";
pub const KEY_A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
pub const KEY_B: &str = "0123456789abcdefghijklmnopqrstuv";
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// How a fake `etterminal` registers, which decides how the router answers
/// and frames what it writes once a session runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalKind {
    /// ET C++: no fd sentinel, no `REGISTRATION_STATUS`, upstream raw stream.
    Upstream,
    /// et.rs 0.0.43 and older: fd sentinel only, `[0]` status, packets.
    LegacyEtrs,
    /// et.rs from 0.0.44: fd sentinel and `upstream_router_stream`, `[0, 1]`
    /// status, upstream raw stream.
    Etrs,
}

impl TerminalKind {
    pub fn framing(self) -> RouterFraming {
        match self {
            Self::LegacyEtrs => RouterFraming::Packets,
            Self::Upstream | Self::Etrs => RouterFraming::Upstream,
        }
    }

    pub fn startup_ack(self) -> bool {
        self != Self::Upstream
    }
}

/// Read one message the router wrote after `TERMINAL_INIT`. A timeout
/// reports `WouldBlock`.
pub fn read_router(
    terminal: &mut UnixStream,
    framing: RouterFraming,
) -> Result<Packet, LocalPacketError> {
    RouterStreamDecoder::new(framing)
        .read_from(terminal)?
        .ok_or_else(|| LocalPacketError::Io(std::io::ErrorKind::WouldBlock.into()))
}

/// [`read_router`] for a terminal registered with [`TestRuntime::register`].
pub fn read_upstream(terminal: &mut UnixStream) -> Result<Packet, LocalPacketError> {
    read_router(terminal, RouterFraming::Upstream)
}

pub struct TestRuntime {
    pub dir: TestDir,
    pub runtime: Runtime,
    pub handle: RuntimeHandle,
    pub address: SocketAddr,
}

impl TestRuntime {
    pub fn start() -> Self {
        Self::start_with_forward_resolver(std::sync::Arc::new(
            et_net::forward::SystemForwardResolver,
        ))
    }

    pub fn start_with_forward_resolver(
        resolver: std::sync::Arc<dyn et_net::forward::ForwardResolver>,
    ) -> Self {
        let dir = TestDir::new();
        let path = dir.socket();
        let uid = rustix::process::getuid().as_raw();
        let selected = select_router_path_for(uid, Some(&path), None, None).unwrap();
        let runtime = Runtime::start_with_forward_resolver(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            selected,
            resolver,
        )
        .unwrap();
        let handle = runtime.handle();
        let address = runtime.tcp_addresses()[0];
        Self {
            dir,
            runtime,
            handle,
            address,
        }
    }

    /// Register like an ET C++ `etterminal`.
    pub fn register(&self, id: &str, passkey: &str) -> UnixStream {
        self.register_as(id, passkey, TerminalKind::Upstream)
    }

    /// Register like an et.rs `etterminal`, with the startup sentinel when
    /// `startup_ack` is set.
    pub fn register_with_capability(
        &self,
        id: &str,
        passkey: &str,
        startup_ack: bool,
    ) -> UnixStream {
        let kind = if startup_ack {
            TerminalKind::Etrs
        } else {
            TerminalKind::Upstream
        };
        self.register_as(id, passkey, kind)
    }

    pub fn register_as(&self, id: &str, passkey: &str, kind: TerminalKind) -> UnixStream {
        let mut stream = UnixStream::connect(self.dir.socket()).unwrap();
        let uid = i64::from(rustix::process::getuid().as_raw());
        let gid = i64::from(rustix::process::getgid().as_raw());
        let user = TerminalUserInfo {
            id: Some(id.to_owned()),
            passkey: Some(passkey.to_owned()),
            uid: Some(uid),
            gid: Some(gid),
            fd: kind.startup_ack().then_some(-6),
            ptyactive: None,
            hadreversetunnels: None,
            disconnect_timeout_seconds: None,
            upstream_router_stream: (kind == TerminalKind::Etrs).then_some(true),
        };
        let packet = Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            user.encode_to_vec(),
        );
        write_local_packet(&mut stream, &packet).unwrap();
        if kind.startup_ack() {
            let acknowledgement = read_local_packet(&mut stream).unwrap();
            assert_eq!(
                parse_registration_status(&acknowledgement).unwrap(),
                kind.framing()
            );
        }
        self.handle.wait_registered(id, TIMEOUT).unwrap();
        stream
    }

    pub fn handshake(&self, id: &str) -> (TcpStream, ConnectResponse) {
        let mut stream = TcpStream::connect(self.address).unwrap();
        bound(&stream);
        write_proto(&mut stream, &client_request(id)).unwrap();
        let response = read_proto_limited(&mut stream, 64 * 1024).unwrap();
        (stream, response)
    }
}

pub fn bound(stream: &TcpStream) {
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
}

pub fn default_payload() -> InitialPayload {
    InitialPayload {
        jumphost: Some(false),
        reversetunnels: Vec::new(),
        environmentvariables: HashMap::new(),
        flowcontrol: None,

        no_pty: None,
        command: None,
        supports_exit_status: None,
        no_shell: None,
        disconnect_timeout_seconds: None,
    }
}

pub fn initialize(
    stream: TcpStream,
    key: &[u8; 32],
    payload: InitialPayload,
) -> (Connection, InitialResponse) {
    let mut connection = Connection::new_client(stream, key);
    connection
        .write_packet(253, &payload.encode_to_vec())
        .unwrap();
    let packet = connection.read_packet().unwrap();
    assert_eq!(packet.header(), 252);
    let response = InitialResponse::decode(packet.payload()).unwrap();
    (connection, response)
}
