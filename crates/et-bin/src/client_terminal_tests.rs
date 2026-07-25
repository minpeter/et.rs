use std::net::{Ipv4Addr, TcpListener, TcpStream};

use et_core::crypto::KEY_LEN;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::connection::{ConnError, Connection};
use prost::Message;

use super::send_command;
use crate::client_terminal_loop::connection_ended;

#[test]
fn command_exit_suffix_matches_no_exit_flag() {
    for (no_exit, expected) in [
        (false, b"printf ok; exit\n".as_slice()),
        (true, b"printf ok\n".as_slice()),
    ] {
        let (client_stream, server_stream) = tcp_pair();
        let key = [7u8; KEY_LEN];
        let worker = std::thread::spawn(move || {
            let mut server = Connection::new_server(server_stream, &key);
            server.read_packet().unwrap()
        });
        let mut client = Connection::new_client(client_stream, &key);
        send_command(&mut client, "printf ok", no_exit).unwrap();
        let packet = worker.join().unwrap();
        assert_eq!(packet.header(), TerminalPacketType::TerminalBuffer as u8);
        assert_eq!(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn only_terminal_connection_end_errors_are_clean() {
    assert!(connection_ended(&ConnError::Io(
        std::io::ErrorKind::UnexpectedEof.into()
    )));
    assert!(!connection_ended(&ConnError::Backpressure));
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}
