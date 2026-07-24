#![forbid(unsafe_code)]

use std::io::{Cursor, ErrorKind};

use et_core::packet::Packet;
use et_net::local_packet::{
    read_local_packet, write_local_packet, LocalPacketDecoder, LocalPacketError,
    MAX_LOCAL_PACKET_LEN,
};

#[test]
fn local_packet_roundtrip_uses_native_i64_framing() {
    let packet = Packet::new(8, b"registration".to_vec());
    let mut wire = Vec::new();
    write_local_packet(&mut wire, &packet).unwrap();
    assert_eq!(&wire[..8], &(packet.wire_len() as i64).to_ne_bytes());
    assert_eq!(read_local_packet(&mut Cursor::new(wire)).unwrap(), packet);
}

#[test]
fn negative_and_oversized_lengths_are_rejected_before_payload_reads() {
    let negative = read_local_packet(&mut Cursor::new((-1i64).to_ne_bytes())).unwrap_err();
    assert!(matches!(negative, LocalPacketError::NegativeLength));
    let oversized = (MAX_LOCAL_PACKET_LEN as i64 + 1).to_ne_bytes();
    let error = read_local_packet(&mut Cursor::new(oversized)).unwrap_err();
    assert!(matches!(error, LocalPacketError::FrameTooLarge { .. }));
}

#[test]
fn short_prefix_and_payload_have_distinct_errors() {
    let prefix = read_local_packet(&mut Cursor::new([0u8; 7])).unwrap_err();
    assert!(matches!(prefix, LocalPacketError::TruncatedPrefix));

    let mut payload = Vec::from((4i64).to_ne_bytes());
    payload.extend_from_slice(&[0, 8, 1]);
    let error = read_local_packet(&mut Cursor::new(payload)).unwrap_err();
    assert!(matches!(error, LocalPacketError::TruncatedPayload));
}

#[test]
fn malformed_packet_and_zero_frame_are_rejected() {
    for body in [&[][..], &[0][..]] {
        let mut wire = Vec::from((body.len() as i64).to_ne_bytes());
        wire.extend_from_slice(body);
        let error = read_local_packet(&mut Cursor::new(wire)).unwrap_err();
        assert!(matches!(error, LocalPacketError::MalformedPacket(_)));
    }
}

#[test]
fn decoder_is_capped_and_reports_eof_without_polling() {
    let mut decoder = LocalPacketDecoder::new();
    assert!(decoder.feed(&(3i64).to_ne_bytes()).unwrap().is_none());
    assert!(decoder.feed(&[0, 8]).unwrap().is_none());
    assert!(matches!(
        decoder.finish(),
        Err(LocalPacketError::TruncatedPayload)
    ));
}

#[test]
fn writer_rejects_packets_above_the_local_cap() {
    let packet = Packet::new(8, vec![0; MAX_LOCAL_PACKET_LEN]);
    let error = write_local_packet(&mut Vec::new(), &packet).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
