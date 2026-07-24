#![forbid(unsafe_code)]

use std::net::{TcpListener, TcpStream};
use std::thread;

use et_net::connection::{Connection, MAX_RECOVERY_PROTO_LEN};

#[test]
fn eof_invalidates_connection_so_future_output_is_buffered() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    drop(client);

    let mut connection = Connection::new_server(server, &[3; 32]);
    assert!(connection.read_packet().is_err());
    assert!(connection.write_packet(7, b"buffered").is_ok());
    assert_eq!(connection.writer_sequence(), 1);
}

#[test]
fn recovery_protobuf_limit_is_explicit_and_enforced() {
    let old_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let old_client = TcpStream::connect(old_listener.local_addr().unwrap()).unwrap();
    let (old_server, _) = old_listener.accept().unwrap();
    let mut connection = Connection::new_server(old_server, &[4; 32]);
    drop(old_client);
    connection.disconnect();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _: et_core::proto::SequenceHeader =
            et_net::framing_io::read_proto_limited(&mut stream, MAX_RECOVERY_PROTO_LEN).unwrap();
        use std::io::Write;
        stream
            .write_all(&(MAX_RECOVERY_PROTO_LEN + 1).to_le_bytes())
            .unwrap();
    });
    let stream = TcpStream::connect(address).unwrap();
    assert!(connection.recover(stream).is_err());
    peer.join().unwrap();
}
