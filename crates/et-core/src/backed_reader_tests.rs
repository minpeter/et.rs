use super::*;
use crate::backed_writer::{BackedWriter, WriterOutcome};
use crate::crypto::{CryptoHandler, DecryptError, DIR_CLIENT_TO_SERVER, KEY_LEN};

fn pair() -> (BackedWriter, BackedReader) {
    let key = [9u8; KEY_LEN];
    let writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    let reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    (writer, reader)
}

#[test]
fn reader_parses_writer_frame() {
    let (mut writer, mut reader) = pair();
    let WriterOutcome::Send(frame) = writer.write_packet(7, b"payload").unwrap() else {
        panic!();
    };
    reader.feed(&frame);
    let ReadItem::Packet(packet) = reader.pop().unwrap() else {
        panic!("expected packet");
    };
    assert_eq!(packet.header(), 7);
    assert_eq!(packet.payload(), b"payload");
}

#[test]
fn partial_frame_needs_more() {
    let (mut writer, mut reader) = pair();
    let WriterOutcome::Send(frame) = writer.write_packet(0, b"ab").unwrap() else {
        panic!();
    };
    reader.feed(&frame[..3]);
    assert_eq!(reader.pop().unwrap(), ReadItem::NeedMore);
    reader.feed(&frame[3..]);
    assert!(matches!(reader.pop().unwrap(), ReadItem::Packet(_)));
}

#[test]
fn multiple_packets_in_one_feed() {
    let (mut writer, mut reader) = pair();
    let mut combined = Vec::new();
    for value in 0..5u8 {
        let WriterOutcome::Send(frame) = writer.write_packet(value, &[value]).unwrap() else {
            panic!();
        };
        combined.extend_from_slice(&frame);
    }
    reader.feed(&combined);
    for value in 0..5u8 {
        let ReadItem::Packet(packet) = reader.pop().unwrap() else {
            panic!("expected packet {value}");
        };
        assert_eq!(packet.header(), value);
        assert_eq!(packet.payload(), &[value]);
    }
    assert_eq!(reader.pop().unwrap(), ReadItem::NeedMore);
}

#[test]
fn invalidate_discards_partial_transport_bytes() {
    let (mut writer, mut reader) = pair();
    let WriterOutcome::Send(frame) = writer.write_packet(4, b"clean").unwrap() else {
        panic!();
    };
    reader.feed(&frame[..3]);
    reader.invalidate();
    reader.revive(Vec::new()).unwrap();
    reader.feed(&frame);
    assert!(matches!(reader.pop().unwrap(), ReadItem::Packet(_)));
}

#[test]
fn unencrypted_live_packet_is_rejected() {
    let (_, mut reader) = pair();
    let packet = Packet::raw(false, 0, b"plaintext");
    reader.feed(&crate::framing::frame_be_u32(&packet.serialize()));
    assert_eq!(reader.pop(), Err(ReadError::Unencrypted));
}

#[test]
fn replay_catchup_before_live_reads() {
    let key = [5u8; KEY_LEN];
    let mut writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), false);
    let mut reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    for value in 0..3u8 {
        let WriterOutcome::BufferedOnly = writer.write_packet(value, &[value]).unwrap() else {
            panic!();
        };
    }
    reader.revive(writer.recover(0).unwrap()).unwrap();
    for value in 0..3u8 {
        let ReadItem::Packet(packet) = reader.pop().unwrap() else {
            panic!("expected catchup packet {value}");
        };
        assert_eq!(packet.header(), value);
        assert_eq!(packet.payload(), &[value]);
    }
    assert_eq!(reader.sequence(), 3);
}

#[test]
fn forged_catchup_is_rejected_without_poisoning_sequence() {
    let good_key = [6u8; KEY_LEN];
    let bad_key = [7u8; KEY_LEN];
    let mut bad_writer =
        BackedWriter::new(CryptoHandler::new(&bad_key, DIR_CLIENT_TO_SERVER), false);
    bad_writer.write_packet(1, b"forged").unwrap();
    let mut reader = BackedReader::new(CryptoHandler::new(&good_key, DIR_CLIENT_TO_SERVER), false);
    assert!(matches!(
        reader.revive(bad_writer.recover(0).unwrap()),
        Err(ReadError::Crypto(DecryptError::BadMac))
    ));
    assert_eq!(reader.sequence(), 0);
    assert!(!reader.connected());

    let mut good_writer =
        BackedWriter::new(CryptoHandler::new(&good_key, DIR_CLIENT_TO_SERVER), false);
    good_writer.write_packet(2, b"valid").unwrap();
    reader.revive(good_writer.recover(0).unwrap()).unwrap();
    let ReadItem::Packet(packet) = reader.pop().unwrap() else {
        panic!("expected authenticated catchup");
    };
    assert_eq!(packet.payload(), b"valid");
    assert_eq!(reader.sequence(), 1);
}

#[test]
fn authenticated_replay_survives_another_disconnect() {
    let key = [8u8; KEY_LEN];
    let mut writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), false);
    writer.write_packet(1, b"first").unwrap();
    writer.write_packet(2, b"second").unwrap();
    let mut reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), false);
    reader.revive(writer.recover(0).unwrap()).unwrap();
    let ReadItem::Packet(first) = reader.pop().unwrap() else {
        panic!("expected first catchup packet");
    };
    assert_eq!(first.payload(), b"first");
    reader.invalidate();
    assert_eq!(reader.pop().unwrap(), ReadItem::NeedMore);
    reader.revive(Vec::new()).unwrap();
    let ReadItem::Packet(second) = reader.pop().unwrap() else {
        panic!("expected preserved catchup packet");
    };
    assert_eq!(second.payload(), b"second");
    assert_eq!(reader.sequence(), 2);
}

#[test]
fn tiny_frame_is_rejected_before_it_is_a_packet() {
    let key = [3u8; KEY_LEN];
    let mut reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    reader.feed(&1u32.to_be_bytes());
    reader.feed(&[0]);
    assert!(matches!(
        reader.pop(),
        Err(ReadError::Frame(crate::framing::FrameError::TooSmall))
    ));
    assert_eq!(reader.sequence(), 0);
}

#[test]
fn tampered_live_frame_keeps_the_nonce_for_the_genuine_packet() {
    let key = [9u8; KEY_LEN];
    let mut writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    let WriterOutcome::Send(frame) = writer.write_packet(1, b"real").unwrap() else {
        panic!("connected write should send");
    };
    let mut tampered = frame.to_vec();
    tampered[6] ^= 0xff;
    let mut reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    reader.feed(&tampered);
    assert!(matches!(
        reader.pop(),
        Err(ReadError::Crypto(DecryptError::BadMac))
    ));
    assert_eq!(reader.sequence(), 0);
    reader.feed(&frame);
    let ReadItem::Packet(packet) = reader.pop().unwrap() else {
        panic!("genuine retransmission should decrypt");
    };
    assert_eq!(packet.payload(), b"real");
    assert_eq!(reader.sequence(), 1);
}

/// Copies as much of `stream` as the next socket read asks for, like `recv`.
fn socket_read(reader: &mut BackedReader, stream: &mut &[u8]) -> usize {
    let slice = reader.prepare_socket_read();
    let count = slice.len().min(stream.len());
    slice[..count].copy_from_slice(&stream[..count]);
    *stream = &stream[count..];
    reader.commit_socket_read(count);
    count
}

fn drain_packets(reader: &mut BackedReader) {
    while let ReadItem::Packet(_) = reader.pop().unwrap() {}
}

#[test]
fn socket_reads_grow_for_bulk_and_release_the_buffer_once_traffic_is_small() {
    let (mut writer, mut reader) = pair();
    let mut bulk = Vec::new();
    while bulk.len() < 2 * 1024 * 1024 {
        let WriterOutcome::Send(frame) = writer.write_packet(1, &[7; 60 * 1024]).unwrap() else {
            panic!();
        };
        bulk.extend_from_slice(&frame);
    }

    // A fresh connection asks for little and grows while reads fill up.
    let mut stream = bulk.as_slice();
    assert_eq!(socket_read(&mut reader, &mut stream), MIN_SOCKET_READ);
    drain_packets(&mut reader);
    assert_eq!(socket_read(&mut reader, &mut stream), 4 * MIN_SOCKET_READ);
    drain_packets(&mut reader);
    // Once a frame has been decoded, bulk reads end on frame boundaries: no
    // partial frame is left to move before the next read.
    for _ in 0..4 {
        let size = socket_read(&mut reader, &mut stream);
        drain_packets(&mut reader);
        assert!(
            size > MAX_SOCKET_READ / 2 && size <= MAX_SOCKET_READ,
            "{size}"
        );
        assert_eq!(reader.offset, reader.filled, "a bulk read split a frame");
    }
    while !stream.is_empty() {
        socket_read(&mut reader, &mut stream);
        drain_packets(&mut reader);
    }
    assert!(reader.partial.capacity() > 4 * MIN_SOCKET_READ);

    // Keep-alive-sized reads shrink the request back and release the bulk
    // buffer, so an idle connection does not keep it resident.
    for _ in 0..5 {
        let WriterOutcome::Send(frame) = writer.write_packet(0, b"ka").unwrap() else {
            panic!();
        };
        socket_read(&mut reader, &mut frame.as_slice());
        drain_packets(&mut reader);
    }
    assert_eq!(reader.prepare_socket_read().len(), MIN_SOCKET_READ);
    assert!(reader.partial.capacity() <= 2 * MIN_SOCKET_READ);
}

#[test]
fn data_sequence_follows_the_latest_packet_that_is_not_a_keepalive() {
    let keepalive = crate::proto::TerminalPacketType::KeepAlive as u8;
    let output = crate::proto::TerminalPacketType::TerminalBuffer as u8;
    let (mut writer, mut reader) = pair();
    let mut read = |header: u8, reader: &mut BackedReader| {
        let WriterOutcome::Send(frame) = writer.write_packet(header, b"x").unwrap() else {
            panic!();
        };
        reader.feed(&frame);
        assert!(matches!(reader.pop().unwrap(), ReadItem::Packet(_)));
    };
    read(keepalive, &mut reader);
    assert_eq!((reader.sequence(), reader.data_sequence()), (1, 0));
    read(output, &mut reader);
    read(keepalive, &mut reader);
    assert_eq!((reader.sequence(), reader.data_sequence()), (3, 2));

    // Catchup counts like live reads.
    let key = [5u8; KEY_LEN];
    let mut writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), false);
    writer.write_packet(keepalive, &[]).unwrap();
    let mut reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
    reader.revive(writer.recover(0).unwrap()).unwrap();
    assert_eq!((reader.sequence(), reader.data_sequence()), (1, 0));
    writer.write_packet(output, b"output").unwrap();
    reader.revive(writer.recover(1).unwrap()).unwrap();
    assert_eq!((reader.sequence(), reader.data_sequence()), (2, 2));
}
