#![forbid(unsafe_code)]

use std::net::{TcpListener, TcpStream};
use std::thread;

use et_core::crypto::KEY_LEN;
use et_core::keys::passkey_to_key;
use et_core::proto::ConnectStatus;
use et_net::connection::Connection;
use et_net::handshake::{
    client_request, protocol_matches, read_request, response_status, write_response,
};

fn loopback() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || listener.accept().unwrap().0);
    let client = TcpStream::connect(addr).unwrap();
    (client, server.join().unwrap())
}

#[test]
fn handshake_and_encrypted_roundtrip() {
    let (mut client_stream, mut server_stream) = loopback();
    let key = passkey_to_key("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef").unwrap();

    let client_thread = thread::spawn(move || {
        let req = client_request("session-1");
        et_net::framing_io::write_proto(&mut client_stream, &req).unwrap();
        let resp: et_core::proto::ConnectResponse =
            et_net::framing_io::read_proto(&mut client_stream).unwrap();
        assert_eq!(resp.status, Some(ConnectStatus::NewClient as i32));
        let mut conn = Connection::new_client(client_stream, &key);
        conn.write_terminal(b"hello server").unwrap();
        conn.read_terminal().unwrap()
    });

    let server_thread = thread::spawn(move || {
        let req = read_request(&mut server_stream).unwrap();
        assert!(protocol_matches(&req));
        let resp = response_status(ConnectStatus::NewClient);
        write_response(&mut server_stream, &resp).unwrap();
        let mut conn = Connection::new_server(server_stream, &key);
        let got = conn.read_terminal().unwrap();
        conn.write_terminal(b"hello client").unwrap();
        got
    });

    let client_got = client_thread.join().unwrap();
    let server_got = server_thread.join().unwrap();
    assert_eq!(client_got, b"hello client");
    assert_eq!(server_got, b"hello server");
}

#[test]
fn multiple_packets_in_order() {
    let (mut client_stream, mut server_stream) = loopback();
    let key: [u8; KEY_LEN] = [0xAB; KEY_LEN];

    let client = thread::spawn(move || {
        let req = client_request("s2");
        et_net::framing_io::write_proto(&mut client_stream, &req).unwrap();
        let _: et_core::proto::ConnectResponse =
            et_net::framing_io::read_proto(&mut client_stream).unwrap();
        let mut conn = Connection::new_client(client_stream, &key);
        for i in 0u8..5 {
            conn.write_terminal(&[i]).unwrap();
        }
    });

    let server = thread::spawn(move || {
        let _req = read_request(&mut server_stream).unwrap();
        write_response(
            &mut server_stream,
            &response_status(ConnectStatus::NewClient),
        )
        .unwrap();
        let mut conn = Connection::new_server(server_stream, &key);
        let mut got = Vec::new();
        while got.len() < 5 {
            let data = conn.read_terminal().unwrap();
            got.push(data[0]);
        }
        got
    });

    client.join().unwrap();
    let got = server.join().unwrap();
    assert_eq!(got, vec![0, 1, 2, 3, 4]);
}

#[test]
fn version_mismatch_rejected_by_server() {
    let (mut client_stream, mut server_stream) = loopback();

    let client = thread::spawn(move || {
        let bad = et_core::proto::ConnectRequest {
            client_id: Some("x".into()),
            version: Some(5),
        };
        et_net::framing_io::write_proto(&mut client_stream, &bad).unwrap();
        let resp: et_core::proto::ConnectResponse =
            et_net::framing_io::read_proto(&mut client_stream).unwrap();
        resp.status
    });

    let server = thread::spawn(move || {
        let req = read_request(&mut server_stream).unwrap();
        let status = if protocol_matches(&req) {
            ConnectStatus::NewClient
        } else {
            ConnectStatus::MismatchedProtocol
        };
        write_response(&mut server_stream, &response_status(status)).unwrap();
    });

    server.join().unwrap();
    let status = client.join().unwrap();
    assert_eq!(status, Some(ConnectStatus::MismatchedProtocol as i32));
}
