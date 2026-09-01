#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{Cursor, ErrorKind, Read};

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

/// Regression test: `set_nonblocking(true)` on a local stream applies to
/// every clone of the socket, so packet writers can see `WouldBlock` when the
/// kernel buffer fills. `write_local_packet` must wait for the peer to drain
/// instead of failing (which previously killed the terminal session) or
/// leaving a truncated frame behind.
#[test]
fn writer_survives_wouldblock_backpressure_on_a_nonblocking_stream() {
    let (mut reader, mut writer) = et_net::local::wake_pair().unwrap();
    // Mirror the session loops: the reader side flips the stream to
    // non-blocking, which also affects the writer clone of the same socket.
    writer.set_nonblocking(true).unwrap();

    const PACKETS: usize = 64;
    const PAYLOAD: usize = 32 * 1024;
    let drain = std::thread::spawn(move || {
        // Let the writer hit a full socket buffer before draining slowly.
        std::thread::sleep(std::time::Duration::from_millis(50));
        reader.set_nonblocking(false).unwrap();
        let mut decoder = LocalPacketDecoder::new();
        let mut received = Vec::new();
        let mut buffer = [0u8; 4096];
        while received.len() < PACKETS {
            let count = reader.read(&mut buffer).unwrap();
            assert_ne!(count, 0, "writer hung up before all packets arrived");
            let mut chunk = &buffer[..count];
            while !chunk.is_empty() {
                let take = decoder.required_bytes().min(chunk.len());
                if let Some(packet) = decoder.feed(&chunk[..take]).unwrap() {
                    received.push(packet);
                    decoder = LocalPacketDecoder::new();
                }
                chunk = &chunk[take..];
            }
        }
        received
    });

    for index in 0..PACKETS {
        let packet = Packet::new(index as u8, vec![index as u8; PAYLOAD]);
        write_local_packet(&mut writer, &packet)
            .expect("backpressure on a non-blocking local stream must not fail the write");
    }

    let received = drain.join().unwrap();
    assert_eq!(received.len(), PACKETS);
    for (index, packet) in received.iter().enumerate() {
        assert_eq!(packet.header(), index as u8);
        assert_eq!(packet.payload(), vec![index as u8; PAYLOAD]);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn opted_in_terminal_sender_hits_backpressure_near_the_configured_bound() {
    let (_server, mut terminal) = et_net::local::wake_pair().unwrap();
    et_net::local::minimize_terminal_output_buffering(&terminal).unwrap();
    terminal.set_nonblocking(true).unwrap();

    let chunk = [0u8; 16 * 1024];
    let mut queued = 0usize;
    loop {
        match terminal.write(&chunk) {
            Ok(0) => panic!("local stream stopped accepting output before backpressure"),
            Ok(count) => queued += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("unexpected terminal output error: {error}"),
        }
    }

    // Linux reports SO_SNDBUF at twice the requested value for bookkeeping.
    // One write may straddle the threshold, so allow one chunk of headroom.
    let configured = et_net::local::FLOW_CONTROL_SEND_BUFFER_BYTES;
    assert!(
        queued >= configured,
        "backpressure arrived too early: {queued}"
    );
    assert!(
        queued <= configured * 2 + chunk.len(),
        "sender queued {queued} bytes past the configured {configured}-byte bound"
    );
}
