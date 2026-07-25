use super::*;
use crate::backed_writer::{BackedWriter, WriterOutcome};
use crate::crypto::{CryptoHandler, DIR_CLIENT_TO_SERVER, KEY_LEN};

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
