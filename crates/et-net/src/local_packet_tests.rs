use super::*;
use std::collections::VecDeque;
use std::sync::{mpsc, Arc};

use et_core::packet::encode_terminal_buffer;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use prost::Message;

const TERMINAL_BUFFER: u8 = TerminalPacketType::TerminalBuffer as u8;

struct StalledWriter(Option<mpsc::Sender<()>>);

impl Write for StalledWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        if let Some(started) = self.0.take() {
            let _ = started.send(());
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn cancelled_local_write_finishes_while_peer_remains_stalled() {
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        let result = write_local_packet_cancelled(
            &mut StalledWriter(Some(started_tx)),
            &Packet::new(1, vec![0; 1024]),
            &worker_cancelled,
            Instant::now() + Duration::from_secs(30),
        );
        let _ = done_tx.send(result);
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    cancelled.store(true, Ordering::Release);
    let error = done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("cancelled writer did not terminate")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

/// `Write` that accepts a bounded number of bytes per call.
///
/// `limits` holds per-call budgets consumed in order (a budget of 0 makes the
/// call return `Ok(0)`); once it is empty every call accepts up to `limit`.
/// With `vectored`, one call spans as many slices as its budget covers;
/// without it, `write_vectored` mirrors std's default and writes only the
/// first non-empty slice. With `block_between`, every odd-numbered call fails
/// with `WouldBlock` before accepting anything.
struct ShortWriter {
    bytes: Vec<u8>,
    limits: VecDeque<usize>,
    limit: usize,
    vectored: bool,
    block_between: bool,
    calls: usize,
}

impl ShortWriter {
    fn new(limit: usize, vectored: bool) -> Self {
        Self {
            bytes: Vec::new(),
            limits: VecDeque::new(),
            limit,
            vectored,
            block_between: false,
            calls: 0,
        }
    }

    fn budget(&mut self) -> io::Result<usize> {
        self.calls += 1;
        if self.block_between && self.calls % 2 == 1 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(self.limits.pop_front().unwrap_or(self.limit))
    }
}

impl Write for ShortWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = self.budget()?.min(buffer.len());
        self.bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if !self.vectored {
            let first = buffers
                .iter()
                .find(|buffer| !buffer.is_empty())
                .map_or(&[][..], |buffer| &**buffer);
            return self.write(first);
        }
        let mut budget = self.budget()?;
        let mut count = 0;
        for buffer in buffers {
            let take = budget.min(buffer.len());
            self.bytes.extend_from_slice(&buffer[..take]);
            budget -= take;
            count += take;
            if budget == 0 {
                break;
            }
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// The local frame the generic packet writer produces for this output.
///
/// Empty output omits the unset `buffer` field (the `0a 00` pair the
/// reference encoder emits for it), exactly as the Unix frame writer always
/// has; any other output carries `encode_terminal_buffer`'s payload verbatim.
fn reference(output: &[u8], is_stderr: bool) -> Vec<u8> {
    let mut payload = encode_terminal_buffer(output, is_stderr);
    if output.is_empty() {
        assert_eq!(payload[..2], [0x0a, 0x00]);
        payload.drain(..2);
    }
    encode_local_packet(&Packet::new(TERMINAL_BUFFER, payload)).unwrap()
}

fn new_frame(output: &[u8], is_stderr: bool) -> TerminalBufferFrame {
    TerminalBufferFrame::new(output.len(), is_stderr).unwrap()
}

/// Drive `frame` to completion the way the poll loops do: retry
/// `WouldBlock`/`Interrupted` with the same slice, stop on any other error.
fn drive(
    frame: &mut TerminalBufferFrame,
    writer: &mut ShortWriter,
    output: &[u8],
) -> io::Result<()> {
    while !frame.is_complete() {
        assert!(
            writer.calls <= 2 * frame.total_len() + 2,
            "frame stopped making progress"
        );
        match frame.write_some(writer, output) {
            Ok(count) => assert_ne!(count, 0),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[test]
fn terminal_frame_matches_reference_for_every_per_call_limit() {
    for len in [0, 1, 2, 127, 128, 300] {
        let output = sample(len);
        for is_stderr in [false, true] {
            let expected = reference(&output, is_stderr);
            for vectored in [false, true] {
                for limit in 1..=expected.len() + 1 {
                    let mut frame = new_frame(&output, is_stderr);
                    let mut writer = ShortWriter::new(limit, vectored);
                    drive(&mut frame, &mut writer, &output).unwrap();
                    assert_eq!(
                        writer.bytes, expected,
                        "len {len} stderr {is_stderr} vectored {vectored} limit {limit}"
                    );
                }
            }
        }
    }
}

#[test]
fn terminal_frame_resumes_at_every_pair_of_cut_points() {
    // 128 bytes needs a two-byte varint, so the head itself varies in length.
    for len in [0, 3, 128] {
        let output = sample(len);
        for is_stderr in [false, true] {
            let expected = reference(&output, is_stderr);
            let total = expected.len();
            for vectored in [false, true] {
                for first in 1..total {
                    for second in 1..=total - first {
                        let mut frame = new_frame(&output, is_stderr);
                        let mut writer = ShortWriter::new(total, vectored);
                        writer.limits = VecDeque::from([first, second]);
                        drive(&mut frame, &mut writer, &output).unwrap();
                        assert_eq!(
                            writer.bytes, expected,
                            "len {len} stderr {is_stderr} vectored {vectored} cuts {first}+{second}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn terminal_frame_resumes_after_would_block() {
    let output = sample(300);
    for is_stderr in [false, true] {
        let expected = reference(&output, is_stderr);
        for vectored in [false, true] {
            for limit in 1..=expected.len() {
                let mut frame = new_frame(&output, is_stderr);
                let mut writer = ShortWriter::new(limit, vectored);
                writer.block_between = true;
                let error = frame.write_some(&mut writer, &output).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                assert!(!frame.is_started());
                assert!(writer.bytes.is_empty());
                drive(&mut frame, &mut writer, &output).unwrap();
                assert_eq!(
                    writer.bytes, expected,
                    "stderr {is_stderr} vectored {vectored} limit {limit}"
                );
            }
        }
    }
}

#[test]
fn terminal_frame_reports_write_zero_at_every_boundary() {
    let output = sample(5);
    for is_stderr in [false, true] {
        let expected = reference(&output, is_stderr);
        let total = expected.len();
        let head_len = new_frame(&output, is_stderr).head_len;
        let mut cuts = vec![0, 1, head_len - 1, head_len, head_len + 1];
        cuts.push(head_len + output.len());
        cuts.push(total - 1);
        // Without the stderr suffix the output ends the frame, and a cut at
        // the very end would complete it before the zero-length write.
        cuts.retain(|&cut| cut < total);
        for cut in cuts {
            let mut frame = new_frame(&output, is_stderr);
            // Vectored, so the first call takes exactly `cut` bytes across
            // slice boundaries before the stream reports a zero-length write.
            let mut writer = ShortWriter::new(total, true);
            writer.limits = if cut == 0 {
                VecDeque::from([0])
            } else {
                VecDeque::from([cut, 0])
            };
            let error = drive(&mut frame, &mut writer, &output).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
            assert!(!frame.is_complete());
            assert_eq!(
                writer.bytes,
                expected[..cut],
                "stderr {is_stderr} cut {cut}"
            );
        }
    }
}

#[test]
fn empty_terminal_frame_decodes_to_empty_output() {
    for is_stderr in [false, true] {
        let mut frame = new_frame(&[], is_stderr);
        let mut writer = ShortWriter::new(usize::MAX, true);
        drive(&mut frame, &mut writer, &[]).unwrap();
        assert_eq!(writer.bytes, reference(&[], is_stderr));
        let packet = read_local_packet(&mut &writer.bytes[..]).unwrap();
        assert_eq!(packet.header(), TERMINAL_BUFFER);
        let body = TerminalBuffer::decode(packet.payload()).unwrap();
        assert!(body.buffer.unwrap_or_default().is_empty());
        assert_eq!(body.is_stderr, is_stderr.then_some(true));
    }
}

#[test]
fn mismatched_output_length_is_rejected_before_writing() {
    let output = sample(4);
    let mut frame = new_frame(&output, false);
    let mut writer = ShortWriter::new(usize::MAX, true);
    let error = frame.write_some(&mut writer, &output[..3]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(writer.calls, 0);
    assert!(!frame.is_started());

    writer.limits = VecDeque::from([6]);
    assert_eq!(frame.write_some(&mut writer, &output).unwrap(), 6);
    let longer = sample(5);
    let error = frame.write_some(&mut writer, &longer).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(writer.calls, 1);
    assert_eq!(writer.bytes.len(), 6);

    drive(&mut frame, &mut writer, &output).unwrap();
    assert_eq!(writer.bytes, reference(&output, false));
}

#[test]
fn oversized_terminal_frame_is_rejected_without_overflow() {
    for is_stderr in [false, true] {
        for len in [
            usize::MAX,
            usize::MAX - 1,
            MAX_LOCAL_PACKET_LEN + 1,
            MAX_LOCAL_PACKET_LEN,
        ] {
            let error = TerminalBufferFrame::new(len, is_stderr)
                .err()
                .expect("oversized frame was accepted");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
}

#[test]
fn largest_terminal_frame_matches_reference_limit() {
    // Packet header (2) + tag (1) + four-byte varint (4) + output + suffix.
    for (largest, is_stderr) in [
        (MAX_LOCAL_PACKET_LEN - 7, false),
        (MAX_LOCAL_PACKET_LEN - 9, true),
    ] {
        let frame = TerminalBufferFrame::new(largest, is_stderr).unwrap();
        assert_eq!(frame.total_len(), PREFIX_LEN + MAX_LOCAL_PACKET_LEN);
        let mut head = Vec::from((MAX_LOCAL_PACKET_LEN as i64).to_ne_bytes());
        head.extend_from_slice(&[0, TERMINAL_BUFFER, 0x0a]);
        prost::encoding::encode_varint(largest as u64, &mut head);
        assert_eq!(frame.head[..frame.head_len], head[..]);
        assert_eq!(frame.suffix.len(), if is_stderr { 2 } else { 0 });

        let error = TerminalBufferFrame::new(largest + 1, is_stderr)
            .err()
            .expect("frame over the local cap was accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    // The generic writer draws the same line.
    let oversized = Packet::new(
        TERMINAL_BUFFER,
        vec![0; MAX_LOCAL_PACKET_LEN - et_core::packet::HEADER_LEN + 1],
    );
    assert!(encode_local_packet(&oversized).is_err());
}

#[test]
fn terminal_frame_over_64_kib_matches_reference() {
    let output = sample(1024 * 1024 + 3);
    for is_stderr in [false, true] {
        let mut frame = new_frame(&output, is_stderr);
        let mut writer = ShortWriter::new(48 * 1024 + 7, true);
        drive(&mut frame, &mut writer, &output).unwrap();
        assert_eq!(writer.bytes, reference(&output, is_stderr));
        let packet = read_local_packet(&mut &writer.bytes[..]).unwrap();
        let body = TerminalBuffer::decode(packet.payload()).unwrap();
        assert_eq!(body.buffer.as_deref(), Some(&output[..]));
    }
}

const TERMINAL_INFO: u8 = TerminalPacketType::TerminalInfo as u8;
const TERMINAL_CLOSE: u8 = TerminalPacketType::TerminalClose as u8;

/// `Read` that hands out one byte per call and would block before each one.
struct TrickleReader {
    bytes: VecDeque<u8>,
    ready: bool,
}

impl Read for TrickleReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.ready = !self.ready;
        if !self.ready {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match self.bytes.pop_front() {
            Some(byte) => {
                buffer[0] = byte;
                Ok(1)
            }
            None => Ok(0),
        }
    }
}

fn router_messages() -> Vec<Packet> {
    vec![
        Packet::new(TERMINAL_BUFFER, encode_terminal_buffer(b"ls -l\r", false)),
        Packet::new(TERMINAL_INFO, vec![0x10, 0x18, 0x18, 0x50]),
        Packet::new(TERMINAL_BUFFER, Vec::new()),
        Packet::new(TERMINAL_CLOSE, Vec::new()),
    ]
}

#[test]
fn router_stream_round_trips_through_partial_reads_in_both_framings() {
    for framing in [RouterFraming::Upstream, RouterFraming::Packets] {
        let mut wire = Vec::new();
        for packet in router_messages() {
            write_router_message(&mut wire, &packet, framing).unwrap();
        }
        let mut reader = TrickleReader {
            bytes: wire.into(),
            ready: false,
        };
        let mut decoder = RouterStreamDecoder::new(framing);
        let mut decoded = Vec::new();
        loop {
            match decoder.read_from(&mut reader) {
                Ok(Some(packet)) => decoded.push(packet),
                Ok(None) => {}
                Err(LocalPacketError::Io(error))
                    if error.kind() == io::ErrorKind::UnexpectedEof =>
                {
                    break
                }
                Err(error) => panic!("{framing:?}: {error}"),
            }
        }
        assert_eq!(decoded, router_messages(), "{framing:?}");
    }
}

#[test]
fn upstream_router_stream_matches_terminal_server_bytes() {
    // Given: upstream `TerminalServer` writes `[type]` + `writeProto` for
    // input and resizes, and the bare `TERMINAL_CLOSE` byte.
    let input = encode_terminal_buffer(b"x", false);
    let mut expected = vec![TERMINAL_BUFFER];
    expected.extend_from_slice(&(input.len() as i64).to_ne_bytes());
    expected.extend_from_slice(&input);
    expected.push(TERMINAL_CLOSE);

    // When: et.rs writes the same two messages upstream-framed.
    let mut wire = Vec::new();
    write_router_message(
        &mut wire,
        &Packet::new(TERMINAL_BUFFER, input),
        RouterFraming::Upstream,
    )
    .unwrap();
    write_router_message(
        &mut wire,
        &Packet::new(TERMINAL_CLOSE, Vec::new()),
        RouterFraming::Upstream,
    )
    .unwrap();

    // Then: the bytes are identical.
    assert_eq!(wire, expected);
}

#[test]
fn upstream_router_stream_refuses_what_upstream_cannot_frame() {
    let keep_alive = TerminalPacketType::KeepAlive as u8;
    for (header, payload_len) in [(keep_alive, 0), (TERMINAL_CLOSE, 1)] {
        let error = RouterHead::new(header, payload_len, RouterFraming::Upstream).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(RouterHead::new(header, payload_len, RouterFraming::Packets).is_ok());
    }
    for (framing, largest) in [
        (RouterFraming::Upstream, MAX_LOCAL_PACKET_LEN),
        (
            RouterFraming::Packets,
            MAX_LOCAL_PACKET_LEN - et_core::packet::HEADER_LEN,
        ),
    ] {
        assert!(RouterHead::new(TERMINAL_BUFFER, largest, framing).is_ok());
        let error = RouterHead::new(TERMINAL_BUFFER, largest + 1, framing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    let decode = |bytes: Vec<u8>| {
        RouterStreamDecoder::new(RouterFraming::Upstream).read_from(&mut io::Cursor::new(bytes))
    };
    assert!(matches!(
        decode(vec![keep_alive]),
        Err(LocalPacketError::UnknownRouterMessage(0))
    ));
    let mut negative = vec![TERMINAL_INFO];
    negative.extend_from_slice(&(-1i64).to_ne_bytes());
    assert!(matches!(
        decode(negative),
        Err(LocalPacketError::NegativeLength)
    ));
    let mut oversized = vec![TERMINAL_BUFFER];
    oversized.extend_from_slice(&((MAX_LOCAL_PACKET_LEN + 1) as i64).to_ne_bytes());
    assert!(matches!(
        decode(oversized),
        Err(LocalPacketError::FrameTooLarge { .. })
    ));
}

#[test]
fn registration_status_names_the_router_framing() {
    // A bare success byte is all et.rs 0.0.43 and older send or accept.
    let legacy = registration_status_packet(Ok(RouterFraming::Packets));
    assert_eq!(legacy, status_packet(REGISTRATION_STATUS, Ok(())));
    assert_eq!(
        parse_registration_status(&legacy).unwrap(),
        RouterFraming::Packets
    );
    assert!(parse_status(&legacy, REGISTRATION_STATUS).is_ok());

    let upstream = registration_status_packet(Ok(RouterFraming::Upstream));
    assert_eq!(
        parse_registration_status(&upstream).unwrap(),
        RouterFraming::Upstream
    );

    let rejected = registration_status_packet(Err("duplicate"));
    assert_eq!(
        parse_registration_status(&rejected)
            .unwrap_err()
            .to_string(),
        "duplicate"
    );
    let unknown = Packet::new(REGISTRATION_STATUS, vec![0, 2]);
    assert_eq!(
        parse_registration_status(&unknown).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

/// `Read` that hands out queued chunks and then would block, or reports end
/// of stream with `eof`. It records the largest buffer it was asked to fill.
struct ChunkReader {
    chunks: VecDeque<Vec<u8>>,
    eof: bool,
    largest_buffer: usize,
}

impl ChunkReader {
    fn new<const N: usize>(chunks: [Vec<u8>; N], eof: bool) -> Self {
        Self {
            chunks: chunks.into(),
            eof,
            largest_buffer: 0,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest_buffer = self.largest_buffer.max(buffer.len());
        let Some(chunk) = self.chunks.front_mut() else {
            return if self.eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        };
        let count = chunk.len().min(buffer.len());
        buffer[..count].copy_from_slice(&chunk[..count]);
        chunk.drain(..count);
        if chunk.is_empty() {
            self.chunks.pop_front();
        }
        Ok(count)
    }
}

#[test]
fn a_declared_length_is_not_allocated_before_its_bytes_arrive() {
    // Given: a peer that declares the largest packet but sends 100 bytes.
    let mut head = Vec::from((MAX_LOCAL_PACKET_LEN as i64).to_ne_bytes());
    head.extend_from_slice(&[0, TERMINAL_BUFFER]);
    let mut upstream_head = vec![TERMINAL_BUFFER];
    upstream_head.extend_from_slice(&(MAX_LOCAL_PACKET_LEN as i64).to_ne_bytes());
    let sent = sample(100);

    // Then: no decoder holds more than one read step for it.
    let mut decoder = LocalPacketDecoder::new();
    let mut reader = ChunkReader::new([head.clone(), sent.clone()], false);
    assert!(decoder.read_from(&mut reader).unwrap().is_none());
    assert_eq!(decoder.filled, sent.len());
    let capacity = decoder.payload.capacity();
    assert!(capacity <= PAYLOAD_READ_STEP, "read_from holds {capacity}");

    let mut decoder = LocalPacketDecoder::new();
    assert!(decoder.feed(&head).unwrap().is_none());
    assert!(decoder.feed(&sent).unwrap().is_none());
    let capacity = decoder.payload.capacity();
    assert!(capacity <= PAYLOAD_READ_STEP, "feed holds {capacity}");

    let mut decoder = RouterStreamDecoder::new(RouterFraming::Upstream);
    let mut reader = ChunkReader::new([upstream_head, sent.clone()], false);
    assert!(decoder.read_from(&mut reader).unwrap().is_none());
    let RouterStream::Upstream(upstream) = &decoder.0 else {
        unreachable!()
    };
    assert_eq!(upstream.filled, sent.len());
    let capacity = upstream.payload.capacity();
    assert!(capacity <= PAYLOAD_READ_STEP, "upstream holds {capacity}");

    // And: the blocking reader never asks for more than one step at a time.
    let mut reader = ChunkReader::new([head, sent], true);
    assert!(matches!(
        read_local_packet(&mut reader),
        Err(LocalPacketError::TruncatedPayload)
    ));
    assert!(
        reader.largest_buffer <= PAYLOAD_READ_STEP,
        "read_local_packet read into {} bytes",
        reader.largest_buffer
    );
}

#[derive(Clone, Copy, Debug)]
enum Via {
    ReadFrom,
    Feed,
    Upstream,
}

/// The payload a decoder holds between reads.
#[derive(Debug)]
struct Held {
    len: usize,
    capacity: usize,
    filled: usize,
    ptr: *const u8,
}

/// Decode `packet` arriving `chunk` bytes at a time, calling `check` with
/// what the decoder holds while it waits for the next chunk.
fn decode_in_chunks(
    via: Via,
    packet: &Packet,
    chunk: usize,
    mut check: impl FnMut(Held),
) -> Packet {
    let framing = match via {
        Via::Upstream => RouterFraming::Upstream,
        Via::ReadFrom | Via::Feed => RouterFraming::Packets,
    };
    let mut wire = Vec::new();
    write_router_message(&mut wire, packet, framing).unwrap();
    let mut reader = ChunkReader::new([], false);
    let mut local = LocalPacketDecoder::new();
    let mut router = RouterStreamDecoder::new(RouterFraming::Upstream);
    for bytes in wire.chunks(chunk) {
        if !matches!(via, Via::Feed) {
            reader.chunks.push_back(bytes.to_vec());
        }
        let decoded = match via {
            Via::ReadFrom => local.read_from(&mut reader).unwrap(),
            Via::Feed => local.feed(bytes).unwrap(),
            Via::Upstream => router.read_from(&mut reader).unwrap(),
        };
        if let Some(decoded) = decoded {
            return decoded;
        }
        let (payload, filled) = match (&router.0, via) {
            (RouterStream::Upstream(upstream), Via::Upstream) => {
                (&upstream.payload, upstream.filled)
            }
            _ => (&local.payload, local.filled),
        };
        check(Held {
            len: payload.len(),
            capacity: payload.capacity(),
            filled,
            ptr: payload.as_ptr(),
        });
    }
    panic!("{via:?}: packet incomplete");
}

#[test]
fn payload_grows_with_the_bytes_received() {
    for via in [Via::ReadFrom, Via::Feed, Via::Upstream] {
        // Over one step: what the decoder holds follows what arrived.
        let large = Packet::new(TERMINAL_BUFFER, sample(1024 * 1024 + 5));
        let decoded = decode_in_chunks(via, &large, 7919, |held| {
            assert!(
                held.len <= held.filled + PAYLOAD_READ_STEP,
                "{via:?}: {held:?}"
            );
            assert!(
                held.capacity <= 2 * (held.filled + PAYLOAD_READ_STEP),
                "{via:?}: {held:?}"
            );
        });
        assert_eq!(decoded, large, "{via:?}");

        // Up to one step: one allocation of the exact size, handed over
        // without a copy.
        let small = Packet::new(TERMINAL_BUFFER, sample(60_000));
        let mut buffer = None;
        let decoded = decode_in_chunks(via, &small, 7919, |held| {
            assert_eq!(held.capacity, 60_000, "{via:?}: {held:?}");
            assert_eq!(*buffer.get_or_insert(held.ptr), held.ptr, "{via:?}");
        });
        assert_eq!(decoded, small, "{via:?}");
        assert_eq!(buffer, Some(decoded.payload().as_ptr()), "{via:?}");
    }
}
