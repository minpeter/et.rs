#![forbid(unsafe_code)]

use std::io::Read;
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

#[test]
fn detected_disconnect_buffers_write_exactly_once() {
    let old_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_stream = TcpStream::connect(old_listener.local_addr().unwrap()).unwrap();
    let (server_stream, _) = old_listener.accept().unwrap();
    let mut observer = server_stream.try_clone().unwrap();
    let mut client = Connection::new_client(client_stream, &[5; 32]);
    let mut server = Connection::new_server(server_stream, &[5; 32]);
    client.shutdown().unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(observer.read(&mut byte).unwrap(), 0);

    server.write_packet(9, b"once").unwrap();
    assert_eq!(server.writer_sequence(), 1);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let recovered_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (recovered_server, _) = listener.accept().unwrap();
    let peer = thread::spawn(move || {
        client.recover(recovered_client).unwrap();
        client.read_packet().unwrap()
    });
    server.recover(recovered_server).unwrap();
    let packet = peer.join().unwrap();
    assert_eq!(packet.header(), 9);
    assert_eq!(packet.payload(), b"once");
    assert_eq!(server.writer_sequence(), 1);
}
