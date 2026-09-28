use std::io::Read;
use std::net::TcpListener;
use std::time::Duration;

use et_core::backed_writer::{MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS};
use et_core::proto::{CatchupBuffer, SequenceHeader};

use super::{validate_catchup_encoding, Connection, RecoveryExchange};
use crate::framing_io::{read_proto_limited, write_proto};
use crate::handshake::MAX_HANDSHAKE_PROTO_LEN;

#[test]
fn catchup_wire_rejects_empty_and_excessive_entries() {
    assert!(validate_catchup_encoding(&[0x0a, 0]).is_err());
    let limit = MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS;
    let mut excessive = Vec::with_capacity((limit + 1) * 3);
    for _ in 0..=limit {
        excessive.extend_from_slice(&[0x0a, 1, 0]);
    }
    assert!(validate_catchup_encoding(&excessive).is_err());
}

#[test]
fn catchup_wire_rejects_overflowing_varints() {
    let mut encoded = vec![0x0a];
    encoded.extend_from_slice(&[0xff; 10]);
    assert!(validate_catchup_encoding(&encoded).is_err());
}

#[test]
fn client_reads_the_peer_catchup_before_writing_its_own() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _header: SequenceHeader =
            read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN).unwrap();
        write_proto(
            &mut stream,
            &SequenceHeader {
                sequence_number: Some(0),
                reset: None,
                reset_salt: None,
            },
        )
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut probe = [0u8; 1];
        assert!(
            stream.read(&mut probe).is_err(),
            "client wrote its catchup before reading the peer catchup"
        );
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_proto(&mut stream, &CatchupBuffer { buffer: Vec::new() }).unwrap();
        let _peer: CatchupBuffer =
            read_proto_limited(&mut stream, super::MAX_RECOVERY_PROTO_LEN).unwrap();
    });
    let stream = std::net::TcpStream::connect(address).unwrap();
    let mut client = Connection::new_client(stream, &[9u8; 32]);
    client
        .run_recovery_handshake_with(Duration::from_secs(2), RecoveryExchange::client(None))
        .unwrap();
    server.join().unwrap();
}
