#![forbid(unsafe_code)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use et_net::connection::{Connection, DEFAULT_LIVE_WRITE_TIMEOUT, MAX_RECOVERY_PROTO_LEN};

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

/// Regression: a blackholed peer (no FIN/RST, peer stops reading) used to make
/// `write_all` block for minutes while the server session lock was held,
/// which prevented `ActiveSession::recover` from starting. Live writes must
/// soft-disconnect within roughly [`DEFAULT_LIVE_WRITE_TIMEOUT`].
#[test]
fn blackholed_peer_write_soft_disconnects_within_live_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    // Peer that accepts but never reads — fills the sender's TCP buffer.
    let sink = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::park();
    });
    let stream = TcpStream::connect(address).unwrap();
    shrink_send_buffer(&stream);
    let mut connection = Connection::new_server(stream, &[9; 32]);
    let payload = vec![0u8; 32 * 1024];
    let started = Instant::now();
    let mut disconnected = false;
    // Fill the socket send buffer until the bounded write times out.
    for _ in 0..4_096 {
        connection.write_packet(7, &payload).unwrap();
        if !connection.connected() {
            disconnected = true;
            break;
        }
        assert!(
            started.elapsed() < DEFAULT_LIVE_WRITE_TIMEOUT + Duration::from_secs(3),
            "write_packet blocked for {:?} without soft-disconnect",
            started.elapsed()
        );
    }
    assert!(
        disconnected,
        "expected soft-disconnect after blackhole write timeout"
    );
    assert!(
        started.elapsed() < DEFAULT_LIVE_WRITE_TIMEOUT + Duration::from_secs(3),
        "soft-disconnect took {:?}, longer than live write bound",
        started.elapsed()
    );
    // Further output buffers for reconnect instead of hanging.
    connection.write_packet(8, b"buffered").unwrap();
    assert!(!connection.connected());
    assert!(connection.writer_sequence() >= 1);
    sink.thread().unpark();
    let _ = sink.join();
}

fn shrink_send_buffer(stream: &TcpStream) {
    // 4 KiB send buffer so the blackhole fills quickly under CI load.
    socket2::SockRef::from(stream)
        .set_send_buffer_size(4 * 1024)
        .unwrap();
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
