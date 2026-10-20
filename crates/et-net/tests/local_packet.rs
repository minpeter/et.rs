#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{Cursor, ErrorKind, Read};

use et_core::packet::Packet;
use et_core::proto::TerminalPacketType;
use et_net::local_packet::{
    read_local_packet, write_local_packet, write_router_message, LocalPacketDecoder,
    LocalPacketError, RouterFraming, RouterStreamDecoder, MAX_LOCAL_PACKET_LEN,
    MAX_REGISTRATION_LEN,
};

/// Upstream `SocketHandler` reads a packet, header included, or a router
/// stream protobuf of up to 128 MiB.
const UPSTREAM_MAX_LEN: usize = 128 * 1024 * 1024;
const TERMINAL_BUFFER: u8 = TerminalPacketType::TerminalBuffer as u8;
const TERMINAL_CLOSE: u8 = TerminalPacketType::TerminalClose as u8;

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

#[test]
fn lengths_up_to_128_mib_are_accepted_and_longer_ones_rejected() {
    let too_large = |result: Result<_, LocalPacketError>| {
        matches!(
            result,
            Err(LocalPacketError::FrameTooLarge { limit, .. }) if limit == UPSTREAM_MAX_LEN
        )
    };
    for (length, accepted) in [(UPSTREAM_MAX_LEN, true), (UPSTREAM_MAX_LEN + 1, false)] {
        let prefix = (length as i64).to_ne_bytes();
        let mut upstream = vec![TERMINAL_BUFFER];
        upstream.extend_from_slice(&prefix);

        let blocking = read_local_packet(&mut Cursor::new(prefix));
        let fed = LocalPacketDecoder::new().feed(&prefix).map(|_| ());
        let read = LocalPacketDecoder::new().read_from(&mut Cursor::new(prefix));
        let packets =
            RouterStreamDecoder::new(RouterFraming::Packets).read_from(&mut Cursor::new(prefix));
        let raw =
            RouterStreamDecoder::new(RouterFraming::Upstream).read_from(&mut Cursor::new(upstream));
        if accepted {
            assert!(matches!(blocking, Err(LocalPacketError::TruncatedPayload)));
            assert!(fed.is_ok());
            for result in [read, packets, raw] {
                assert!(
                    matches!(&result, Err(LocalPacketError::Io(error)) if error.kind() == ErrorKind::UnexpectedEof),
                    "{result:?}"
                );
            }
        } else {
            assert!(too_large(blocking.map(|_| ())));
            assert!(too_large(fed));
            for result in [read, packets, raw] {
                assert!(too_large(result.map(|_| ())));
            }
        }
    }
}

#[test]
fn decoder_limit_bounds_the_whole_packet() {
    for (length, accepted) in [
        (MAX_REGISTRATION_LEN, true),
        (MAX_REGISTRATION_LEN + 1, false),
    ] {
        let prefix = (length as i64).to_ne_bytes();
        let fed = LocalPacketDecoder::with_limit(MAX_REGISTRATION_LEN).feed(&prefix);
        let read = LocalPacketDecoder::with_limit(MAX_REGISTRATION_LEN)
            .read_from(&mut Cursor::new(prefix));
        if accepted {
            assert!(matches!(fed, Ok(None)));
            assert!(matches!(read, Err(LocalPacketError::Io(_))));
        } else {
            for result in [fed, read] {
                assert!(matches!(
                    result,
                    Err(LocalPacketError::FrameTooLarge { limit, .. }) if limit == MAX_REGISTRATION_LEN
                ));
            }
        }
    }
}

/// `Read` that would block before every `step`-byte piece of `bytes`.
struct Stutter {
    bytes: Vec<u8>,
    offset: usize,
    step: usize,
    ready: bool,
}

impl Read for Stutter {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.ready = !self.ready;
        if !self.ready {
            return Err(ErrorKind::WouldBlock.into());
        }
        let count = self
            .step
            .min(buffer.len())
            .min(self.bytes.len() - self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn messages_over_64_kib_round_trip_in_both_framings() {
    let output: Vec<u8> = (0..1024 * 1024 + 3)
        .map(|index| (index % 251) as u8)
        .collect();
    let messages = [
        Packet::new(
            TERMINAL_BUFFER,
            et_core::packet::encode_terminal_buffer(&output, false),
        ),
        Packet::new(TERMINAL_BUFFER, vec![7; 200 * 1024]),
        Packet::new(TERMINAL_CLOSE, Vec::new()),
    ];

    // Length-prefixed packets, read blocking and fed in pieces.
    let mut wire = Vec::new();
    write_local_packet(&mut wire, &messages[0]).unwrap();
    assert_eq!(
        read_local_packet(&mut Cursor::new(&wire)).unwrap(),
        messages[0]
    );
    let mut decoder = LocalPacketDecoder::new();
    let mut fed = None;
    for piece in wire.chunks(8192) {
        assert!(fed.is_none());
        fed = decoder.feed(piece).unwrap();
    }
    assert_eq!(fed.as_ref(), Some(&messages[0]));

    // The router stream in either framing, through partial nonblocking reads.
    for framing in [RouterFraming::Upstream, RouterFraming::Packets] {
        let mut wire = Vec::new();
        for message in &messages {
            write_router_message(&mut wire, message, framing).unwrap();
        }
        let mut reader = Stutter {
            bytes: wire,
            offset: 0,
            step: 5000,
            ready: false,
        };
        let mut decoder = RouterStreamDecoder::new(framing);
        let mut decoded = Vec::new();
        while decoded.len() < messages.len() {
            if let Some(message) = decoder.read_from(&mut reader).unwrap() {
                decoded.push(message);
            }
        }
        assert_eq!(decoded, messages, "{framing:?}");
    }
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
