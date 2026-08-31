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
    parse_status, read_local_packet, write_local_packet, REGISTRATION_STATUS,
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

pub struct TestRuntime {
    pub dir: TestDir,
    pub runtime: Runtime,
    pub handle: RuntimeHandle,
    pub address: SocketAddr,
}

impl TestRuntime {
    pub fn start() -> Self {
        let dir = TestDir::new();
        let path = dir.socket();
        let uid = rustix::process::getuid().as_raw();
        let selected = select_router_path_for(uid, Some(&path), None, None).unwrap();
        let runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, selected).unwrap();
        let handle = runtime.handle();
        let address = runtime.tcp_addresses()[0];
        Self {
            dir,
            runtime,
            handle,
            address,
        }
    }

    pub fn register(&self, id: &str, passkey: &str) -> UnixStream {
        self.register_with_capability(id, passkey, false)
    }

    pub fn register_with_capability(
        &self,
        id: &str,
        passkey: &str,
        startup_ack: bool,
    ) -> UnixStream {
        let mut stream = UnixStream::connect(self.dir.socket()).unwrap();
        let uid = i64::from(rustix::process::getuid().as_raw());
        let gid = i64::from(rustix::process::getgid().as_raw());
        let user = TerminalUserInfo {
            id: Some(id.to_owned()),
            passkey: Some(passkey.to_owned()),
            uid: Some(uid),
            gid: Some(gid),
            fd: startup_ack.then_some(-6),
        };
        let packet = Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            user.encode_to_vec(),
        );
        write_local_packet(&mut stream, &packet).unwrap();
        if startup_ack {
            let acknowledgement = read_local_packet(&mut stream).unwrap();
            parse_status(&acknowledgement, REGISTRATION_STATUS).unwrap();
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
