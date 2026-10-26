//! Native-`i64` framing for packets exchanged with local terminal processes,
//! and the upstream router stream `etserver` writes to `etterminal` once a
//! session runs (see [`RouterFraming`]).

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use et_core::packet::{Packet, PacketError};

/// Largest serialized local packet, its two header bytes included, and the
/// largest protobuf the upstream router stream carries: upstream
/// `SocketHandler::readPacket` and `readProto` accept up to 128 MiB.
pub const MAX_LOCAL_PACKET_LEN: usize = 128 * 1024 * 1024;
/// Largest registration packet the router reads, header included: upstream
/// `UserTerminalRouter::MAX_REGISTRATION_LENGTH`.
pub const MAX_REGISTRATION_LEN: usize = 4096;
/// Local-only control packets. These values are deliberately outside the
/// protocol-v6 terminal enum and never cross the encrypted network transport.
pub const REGISTRATION_STATUS: u8 = 254;
pub const STARTUP_STATUS: u8 = 255;
pub const MAX_STATUS_MESSAGE: usize = 8 * 1024;
const PREFIX_LEN: usize = std::mem::size_of::<i64>();
/// How long a blocking local packet writer naps before retrying a `WouldBlock`
/// write on non-Unix or generic `Write` streams.
const BACKPRESSURE_RETRY: Duration = Duration::from_micros(100);
/// Payload bytes a reader makes room for ahead of what has arrived. Like
/// upstream `BackedReader`, a declared length is never allocated up front, so
/// a peer that announces a large message but sends little costs little.
const PAYLOAD_READ_STEP: usize = 64 * 1024;

#[derive(Debug)]
pub enum LocalPacketError {
    Io(io::Error),
    TruncatedPrefix,
    TruncatedPayload,
    NegativeLength,
    FrameTooLarge {
        length: i64,
        limit: usize,
    },
    MalformedPacket(PacketError),
    TrailingData,
    AlreadyComplete,
    /// The upstream router stream named a message type it cannot carry.
    UnknownRouterMessage(u8),
}

impl std::fmt::Display for LocalPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "local packet I/O: {error}"),
            Self::TruncatedPrefix => write!(f, "local packet length prefix is truncated"),
            Self::TruncatedPayload => write!(f, "local packet payload is truncated"),
            Self::NegativeLength => write!(f, "local packet length is negative"),
            Self::FrameTooLarge { length, limit } => {
                write!(f, "local packet length {length} exceeds {limit} bytes")
            }
            Self::MalformedPacket(error) => write!(f, "malformed local packet: {error}"),
            Self::TrailingData => write!(f, "local registration contains trailing data"),
            Self::AlreadyComplete => write!(f, "local packet decoder is already complete"),
            Self::UnknownRouterMessage(header) => {
                write!(f, "unknown router message type {header}")
            }
        }
    }
}

impl std::error::Error for LocalPacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::MalformedPacket(error) => Some(error),
            _ => None,
        }
    }
}

pub fn read_local_packet<R: Read>(reader: &mut R) -> Result<Packet, LocalPacketError> {
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact_classified(reader, &mut prefix, LocalPacketError::TruncatedPrefix)?;
    let length = parse_length(prefix, MAX_LOCAL_PACKET_LEN)?;
    let mut header = [0u8; et_core::packet::HEADER_LEN];
    let header_len = length.min(et_core::packet::HEADER_LEN);
    read_exact_classified(
        reader,
        &mut header[..header_len],
        LocalPacketError::TruncatedPayload,
    )?;
    if length < et_core::packet::HEADER_LEN {
        return Err(LocalPacketError::MalformedPacket(PacketError::Short));
    }
    let body_len = length - et_core::packet::HEADER_LEN;
    let mut payload = Vec::new();
    while payload.len() < body_len {
        let filled = payload.len();
        grow_payload(&mut payload, filled, body_len);
        read_exact_classified(
            reader,
            &mut payload[filled..],
            LocalPacketError::TruncatedPayload,
        )?;
    }
    Ok(Packet::raw(header[0] != 0, header[1], payload))
}

/// The error every local writer returns for a packet over
/// [`MAX_LOCAL_PACKET_LEN`].
fn packet_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("local packet exceeds {MAX_LOCAL_PACKET_LEN} bytes"),
    )
}

pub fn encode_local_packet(packet: &Packet) -> io::Result<Vec<u8>> {
    let wire_len = packet.wire_len();
    if wire_len > MAX_LOCAL_PACKET_LEN {
        return Err(packet_too_large());
    }
    let length = i64::try_from(wire_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local packet too large"))?;
    let mut frame = Vec::with_capacity(PREFIX_LEN + wire_len);
    frame.extend_from_slice(&length.to_ne_bytes());
    frame.push(packet.is_encrypted() as u8);
    frame.push(packet.header());
    frame.extend_from_slice(packet.payload());
    Ok(frame)
}

pub fn status_packet(header: u8, result: Result<(), &str>) -> Packet {
    let mut payload = Vec::new();
    match result {
        Ok(()) => payload.push(0),
        Err(message) => {
            payload.push(1);
            payload.extend_from_slice(&message.as_bytes()[..message.len().min(MAX_STATUS_MESSAGE)]);
        }
    }
    Packet::new(header, payload)
}

pub fn parse_status(packet: &Packet, expected_header: u8) -> io::Result<()> {
    if packet.is_encrypted() || packet.header() != expected_header {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected local status packet",
        ));
    }
    match packet.payload().split_first() {
        Some((&0, [])) => Ok(()),
        Some((&1, message)) if message.len() <= MAX_STATUS_MESSAGE => Err(io::Error::other(
            String::from_utf8_lossy(message).into_owned(),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed local status packet",
        )),
    }
}

/// How `etserver` frames what it writes to `etterminal` once a session runs:
/// after `TERMINAL_INIT`, or straight after registration when a live pty
/// re-registers.
///
/// Registration, `TERMINAL_INIT`, `JUMPHOST_INIT`, the jumphost relay and
/// everything `etterminal` writes stay length-prefixed packets either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterFraming {
    /// Upstream `TerminalServer`: `TERMINAL_BUFFER` and `TERMINAL_INFO` are
    /// the type byte, a native `i64` length and the protobuf, and
    /// `TERMINAL_CLOSE` is the type byte alone. ET C++ and et.rs from 0.0.44
    /// write and read this.
    Upstream,
    /// et.rs 0.0.43 and older: every message is a length-prefixed packet.
    Packets,
}

/// Trailing success byte of a `REGISTRATION_STATUS`: this `etserver` writes
/// [`RouterFraming::Upstream`]. A bare success byte comes from et.rs 0.0.43
/// and older, which write [`RouterFraming::Packets`].
const UPSTREAM_ROUTER_STREAM: u8 = 1;

/// `REGISTRATION_STATUS` for a terminal that registered with the `fd = -6`
/// sentinel. Success names the framing that terminal will read; only a
/// terminal that asked for [`RouterFraming::Upstream`] may receive it, because
/// et.rs 0.0.43 and older reject any success payload but the bare byte.
pub fn registration_status_packet(result: Result<RouterFraming, &str>) -> Packet {
    match result {
        Ok(RouterFraming::Packets) => status_packet(REGISTRATION_STATUS, Ok(())),
        Ok(RouterFraming::Upstream) => {
            Packet::new(REGISTRATION_STATUS, vec![0, UPSTREAM_ROUTER_STREAM])
        }
        Err(message) => status_packet(REGISTRATION_STATUS, Err(message)),
    }
}

/// Parse a `REGISTRATION_STATUS` into the framing `etserver` will write.
pub fn parse_registration_status(packet: &Packet) -> io::Result<RouterFraming> {
    if !packet.is_encrypted()
        && packet.header() == REGISTRATION_STATUS
        && packet.payload() == [0, UPSTREAM_ROUTER_STREAM]
    {
        return Ok(RouterFraming::Upstream);
    }
    parse_status(packet, REGISTRATION_STATUS).map(|()| RouterFraming::Packets)
}

/// Longest [`RouterHead`]: a packet's length prefix and two header bytes.
const ROUTER_HEAD_MAX: usize = PREFIX_LEN + et_core::packet::HEADER_LEN;

/// The bytes that precede one router message's payload.
#[derive(Debug, Clone, Copy)]
pub struct RouterHead {
    bytes: [u8; ROUTER_HEAD_MAX],
    len: usize,
}

impl RouterHead {
    /// Head for a plaintext message of `payload_len` bytes.
    ///
    /// [`RouterFraming::Upstream`] carries a protobuf of up to
    /// [`MAX_LOCAL_PACKET_LEN`] (upstream `writeProto`) and rejects types
    /// upstream never writes to a terminal and a payload on `TERMINAL_CLOSE`;
    /// [`RouterFraming::Packets`] carries a packet of up to
    /// [`MAX_LOCAL_PACKET_LEN`], header included.
    pub fn new(header: u8, payload_len: usize, framing: RouterFraming) -> io::Result<Self> {
        let max_payload_len = match framing {
            RouterFraming::Packets => MAX_LOCAL_PACKET_LEN - et_core::packet::HEADER_LEN,
            RouterFraming::Upstream => MAX_LOCAL_PACKET_LEN,
        };
        if payload_len > max_payload_len {
            return Err(packet_too_large());
        }
        let mut bytes = [0u8; ROUTER_HEAD_MAX];
        let len = match framing {
            RouterFraming::Packets => {
                let length = i64::try_from(et_core::packet::HEADER_LEN + payload_len)
                    .map_err(|_| packet_too_large())?;
                bytes[..PREFIX_LEN].copy_from_slice(&length.to_ne_bytes());
                bytes[PREFIX_LEN + 1] = header;
                ROUTER_HEAD_MAX
            }
            RouterFraming::Upstream => match upstream_router_message(header) {
                Some(UpstreamMessage::Close) if payload_len == 0 => {
                    bytes[0] = header;
                    1
                }
                Some(UpstreamMessage::Proto) => {
                    let length = i64::try_from(payload_len).map_err(|_| packet_too_large())?;
                    bytes[0] = header;
                    bytes[1..=PREFIX_LEN].copy_from_slice(&length.to_ne_bytes());
                    1 + PREFIX_LEN
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("the upstream router stream cannot carry packet type {header}"),
                    ))
                }
            },
        };
        Ok(Self { bytes, len })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UpstreamMessage {
    /// `[type][i64 length][protobuf]`.
    Proto,
    /// `[type]`.
    Close,
}

/// Upstream `TerminalServer` writes exactly these three types to a terminal.
fn upstream_router_message(header: u8) -> Option<UpstreamMessage> {
    use et_core::proto::TerminalPacketType;
    if header == TerminalPacketType::TerminalBuffer as u8
        || header == TerminalPacketType::TerminalInfo as u8
    {
        Some(UpstreamMessage::Proto)
    } else if header == TerminalPacketType::TerminalClose as u8 {
        Some(UpstreamMessage::Close)
    } else {
        None
    }
}

/// Write one router message; `WouldBlock` waits like [`write_local_packet`].
pub fn write_router_message<W: Write>(
    writer: &mut W,
    packet: &Packet,
    framing: RouterFraming,
) -> io::Result<()> {
    write_router_message_with(writer, packet, framing, || false)
}

/// [`write_router_message`] that gives up once `cancelled` is set or
/// `deadline` passes, like [`write_local_packet_cancelled`].
pub fn write_router_message_cancelled<W: Write>(
    writer: &mut W,
    packet: &Packet,
    framing: RouterFraming,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    write_router_message_with(writer, packet, framing, || {
        cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
    })
}

fn write_router_message_with<W: Write>(
    writer: &mut W,
    packet: &Packet,
    framing: RouterFraming,
    cancelled: impl Fn() -> bool,
) -> io::Result<()> {
    let head = RouterHead::new(packet.header(), packet.payload().len(), framing)?;
    let mut frame = Vec::with_capacity(head.as_bytes().len() + packet.payload().len());
    frame.extend_from_slice(head.as_bytes());
    frame.extend_from_slice(packet.payload());
    write_all_blocking(writer, &frame, &cancelled)?;
    flush_blocking(writer, &cancelled)
}

pub fn write_local_packet<W: Write>(writer: &mut W, packet: &Packet) -> io::Result<()> {
    write_local_packet_with(writer, packet, || false)
}

pub fn write_local_packet_cancelled<W: Write>(
    writer: &mut W,
    packet: &Packet,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    write_local_packet_with(writer, packet, || {
        cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
    })
}

pub fn write_local_packet_until_cancelled<W: Write>(
    writer: &mut W,
    packet: &Packet,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    write_local_packet_with(writer, packet, || cancelled.load(Ordering::Acquire))
}

/// One framed local `TERMINAL_BUFFER` packet, written without copying the
/// output bytes.
///
/// The frame head (length prefix, packet header and protobuf tag/length) is
/// built once; [`Self::write_some`] sends head, output and the optional
/// `is_stderr` suffix with vectored writes. A readiness-driven loop keeps the
/// frame across `WouldBlock` and resumes it with the same `output` slice, so a
/// frame is never abandoned half-written and bytes never move through an
/// intermediate buffer.
pub struct TerminalBufferFrame {
    head: [u8; TERMINAL_FRAME_HEAD_MAX],
    head_len: usize,
    output_len: usize,
    suffix: &'static [u8],
    written: usize,
}

const TERMINAL_FRAME_HEAD_MAX: usize = PREFIX_LEN + et_core::packet::HEADER_LEN + 1 + 10;
const STDERR_SUFFIX: [u8; 2] = [0x10, 0x01];

impl TerminalBufferFrame {
    /// Frame `output_len` bytes of terminal output; rejects frames over
    /// [`MAX_LOCAL_PACKET_LEN`].
    pub fn new(output_len: usize, is_stderr: bool) -> io::Result<Self> {
        // Reject oversized output before sizing the payload, so the length
        // arithmetic below stays far from `usize::MAX`.
        if output_len > MAX_LOCAL_PACKET_LEN {
            return Err(packet_too_large());
        }
        let mut varint = [0u8; 10];
        let mut varint_len = 0usize;
        let mut value = output_len;
        while value >= 0x80 {
            varint[varint_len] = (value as u8) | 0x80;
            value >>= 7;
            varint_len += 1;
        }
        varint[varint_len] = value as u8;
        varint_len += 1;
        let suffix: &'static [u8] = if is_stderr { &STDERR_SUFFIX } else { &[] };
        let payload_len = if output_len == 0 {
            suffix.len()
        } else {
            1 + varint_len + output_len + suffix.len()
        };
        let wire_len = et_core::packet::HEADER_LEN + payload_len;
        if wire_len > MAX_LOCAL_PACKET_LEN {
            return Err(packet_too_large());
        }
        let length = i64::try_from(wire_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local packet too large"))?;
        let mut head = [0u8; TERMINAL_FRAME_HEAD_MAX];
        head[..PREFIX_LEN].copy_from_slice(&length.to_ne_bytes());
        head[PREFIX_LEN] = 0;
        head[PREFIX_LEN + 1] = et_core::proto::TerminalPacketType::TerminalBuffer as u8;
        let head_len = if output_len == 0 {
            PREFIX_LEN + 2
        } else {
            head[PREFIX_LEN + 2] = 0x0a;
            head[PREFIX_LEN + 3..PREFIX_LEN + 3 + varint_len]
                .copy_from_slice(&varint[..varint_len]);
            PREFIX_LEN + 3 + varint_len
        };
        Ok(Self {
            head,
            head_len,
            output_len,
            suffix,
            written: 0,
        })
    }

    fn total_len(&self) -> usize {
        self.head_len + self.output_len + self.suffix.len()
    }

    pub fn is_complete(&self) -> bool {
        self.written == self.total_len()
    }

    /// True once any byte reached the stream: the frame must then finish.
    pub fn is_started(&self) -> bool {
        self.written != 0
    }

    /// Issue one write for the unsent remainder and return how many bytes the
    /// stream accepted. `output` must be the slice the frame was created for;
    /// a slice of any other length fails with `InvalidInput` before a byte is
    /// written. `WouldBlock`/`Interrupted` are returned unchanged for the
    /// caller's loop.
    pub fn write_some<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        output: &[u8],
    ) -> io::Result<usize> {
        if output.len() != self.output_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal output length does not match its frame",
            ));
        }
        let head_len = self.head_len;
        let written = self.written;
        let count = if written < head_len {
            writer.write_vectored(&[
                io::IoSlice::new(&self.head[written..head_len]),
                io::IoSlice::new(output),
                io::IoSlice::new(self.suffix),
            ])?
        } else if written < head_len + output.len() {
            writer.write_vectored(&[
                io::IoSlice::new(&output[written - head_len..]),
                io::IoSlice::new(self.suffix),
            ])?
        } else {
            writer.write(&self.suffix[written - head_len - output.len()..])?
        };
        if count == 0 && !self.is_complete() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.written += count;
        Ok(count)
    }
}

pub fn write_local_terminal_buffer_until_cancelled(
    writer: &mut crate::local::LocalStream,
    output: &[u8],
    is_stderr: bool,
    cancelled: &AtomicBool,
    progress: Option<&std::sync::atomic::AtomicUsize>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut frame = TerminalBufferFrame::new(output.len(), is_stderr)?;
        while !frame.is_complete() {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local packet write cancelled",
                ));
            }
            match frame.write_some(writer, output) {
                Ok(_) => {
                    if let Some(progress) = progress {
                        progress.fetch_add(1, Ordering::Release);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut fds = [PollFd::new(&*writer, PollFlags::OUT)];
                    let _ = poll(
                        &mut fds,
                        Some(&Timespec {
                            tv_sec: 0,
                            tv_nsec: 5_000_000,
                        }),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let packet = Packet::new(
            et_core::proto::TerminalPacketType::TerminalBuffer as u8,
            et_core::packet::encode_terminal_buffer(output, is_stderr),
        );
        let res = write_local_packet_until_cancelled(writer, &packet, cancelled);
        if res.is_ok() {
            if let Some(progress) = progress {
                progress.fetch_add(1, Ordering::Release);
            }
        }
        res
    }
}

fn write_local_packet_with<W: Write>(
    writer: &mut W,
    packet: &Packet,
    cancelled: impl Fn() -> bool,
) -> io::Result<()> {
    let frame = encode_local_packet(packet)?;
    write_all_blocking(writer, &frame, &cancelled)?;
    flush_blocking(writer, &cancelled)
}

/// `write_all` that treats `WouldBlock` as backpressure instead of an error.
///
/// `set_nonblocking(true)` applies to the underlying socket, not the handle:
/// every `try_clone()` of a [`crate::local::LocalStream`] shares the flag
/// (`O_NONBLOCK` lives on the open file description; `FIONBIO` is per-socket
/// on Windows). The readiness-driven session loops flip their local streams
/// to non-blocking for reads, which silently makes the packet *writers* on
/// cloned handles non-blocking too. A full socket buffer (e.g. a shell that
/// stops reading input during a large paste, or a bridge that pauses reading
/// terminal output while a client reconnects) must wait for the peer to
/// drain, exactly like upstream's blocking writes, rather than tearing the
/// session down — and a bare `write_all` would also abandon a partially
/// written frame, corrupting the stream for good.
fn write_all_blocking<W: Write>(
    writer: &mut W,
    mut buffer: &[u8],
    cancelled: &impl Fn() -> bool,
) -> io::Result<()> {
    while !buffer.is_empty() {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local packet write cancelled",
            ));
        }
        match writer.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(BACKPRESSURE_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn flush_blocking<W: Write>(writer: &mut W, cancelled: &impl Fn() -> bool) -> io::Result<()> {
    loop {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local packet flush cancelled",
            ));
        }
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(BACKPRESSURE_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Reads one length-prefixed packet, from a stream that may block or from
/// bytes fed to it. The payload grows as bytes arrive (see
/// [`PAYLOAD_READ_STEP`]), however large the declared length.
pub struct LocalPacketDecoder {
    max_packet_len: usize,
    prefix: [u8; PREFIX_LEN],
    prefix_len: usize,
    expected: Option<usize>,
    header: [u8; et_core::packet::HEADER_LEN],
    header_len: usize,
    payload: Vec<u8>,
    filled: usize,
    complete: bool,
}

impl Default for LocalPacketDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPacketDecoder {
    /// A decoder for packets of up to [`MAX_LOCAL_PACKET_LEN`].
    pub fn new() -> Self {
        Self::with_limit(MAX_LOCAL_PACKET_LEN)
    }

    /// A decoder that rejects a declared length over `max_packet_len` bytes,
    /// header included, as [`LocalPacketError::FrameTooLarge`]. Limits above
    /// [`MAX_LOCAL_PACKET_LEN`] are clamped to it.
    pub fn with_limit(max_packet_len: usize) -> Self {
        Self {
            max_packet_len: max_packet_len.min(MAX_LOCAL_PACKET_LEN),
            prefix: [0; PREFIX_LEN],
            prefix_len: 0,
            expected: None,
            header: [0; et_core::packet::HEADER_LEN],
            header_len: 0,
            payload: Vec::new(),
            filled: 0,
            complete: bool::default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.prefix_len == 0 && self.expected.is_none()
    }

    pub fn required_bytes(&self) -> usize {
        match self.expected {
            None => PREFIX_LEN - self.prefix_len,
            Some(expected) => expected.saturating_sub(self.header_len + self.filled),
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<Option<Packet>, LocalPacketError> {
        if self.complete {
            return Err(LocalPacketError::AlreadyComplete);
        }
        let mut offset = 0;
        if self.expected.is_none() {
            let count = (PREFIX_LEN - self.prefix_len).min(input.len());
            self.prefix[self.prefix_len..self.prefix_len + count].copy_from_slice(&input[..count]);
            self.prefix_len += count;
            offset += count;
            if self.prefix_len == PREFIX_LEN {
                self.expected = Some(parse_length(self.prefix, self.max_packet_len)?);
            }
        }
        if let Some(expected) = self.expected {
            let hdr_target = expected.min(et_core::packet::HEADER_LEN);
            if self.header_len < hdr_target {
                let count = (hdr_target - self.header_len).min(input.len().saturating_sub(offset));
                self.header[self.header_len..self.header_len + count]
                    .copy_from_slice(&input[offset..offset + count]);
                self.header_len += count;
                offset += count;
            }
            if self.header_len == hdr_target {
                let body_len = expected.saturating_sub(et_core::packet::HEADER_LEN);
                let remaining = body_len - self.filled;
                let count = remaining.min(input.len() - offset);
                let chunk = &input[offset..offset + count];
                // `read_from` may already have made room past `filled`.
                let room = (self.payload.len() - self.filled).min(count);
                self.payload[self.filled..self.filled + room].copy_from_slice(&chunk[..room]);
                if room < count {
                    reserve_payload(&mut self.payload, self.filled + count, body_len);
                    self.payload.extend_from_slice(&chunk[room..]);
                }
                self.filled += count;
                offset += count;
                if self.header_len + self.filled == expected {
                    if offset != input.len() {
                        return Err(LocalPacketError::TrailingData);
                    }
                    self.complete = true;
                    if expected < et_core::packet::HEADER_LEN {
                        return Err(LocalPacketError::MalformedPacket(PacketError::Short));
                    }
                    return Ok(Some(Packet::raw(
                        self.header[0] != 0,
                        self.header[1],
                        std::mem::take(&mut self.payload),
                    )));
                }
            }
        }
        if offset != input.len() {
            return Err(LocalPacketError::TrailingData);
        }
        Ok(None)
    }

    pub fn read_from<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Packet>, LocalPacketError> {
        if self.complete {
            return Err(LocalPacketError::AlreadyComplete);
        }
        while self.expected.is_none() {
            match reader.read(&mut self.prefix[self.prefix_len..PREFIX_LEN]) {
                Ok(0) => {
                    return Err(LocalPacketError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => {
                    self.prefix_len += count;
                    if self.prefix_len == PREFIX_LEN {
                        self.expected = Some(parse_length(self.prefix, self.max_packet_len)?);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(LocalPacketError::Io(error)),
            }
        }
        if let Some(expected) = self.expected {
            let hdr_target = expected.min(et_core::packet::HEADER_LEN);
            while self.header_len < hdr_target {
                match reader.read(&mut self.header[self.header_len..hdr_target]) {
                    Ok(0) => {
                        return Err(LocalPacketError::Io(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(count) => {
                        self.header_len += count;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(LocalPacketError::Io(error)),
                }
            }
            if expected < et_core::packet::HEADER_LEN {
                self.complete = true;
                return Err(LocalPacketError::MalformedPacket(PacketError::Short));
            }
            let body_len = expected - et_core::packet::HEADER_LEN;
            while self.filled < body_len {
                grow_payload(&mut self.payload, self.filled, body_len);
                match reader.read(&mut self.payload[self.filled..]) {
                    Ok(0) => {
                        return Err(LocalPacketError::Io(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(count) => {
                        self.filled += count;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(LocalPacketError::Io(error)),
                }
            }
            self.complete = true;
            return Ok(Some(Packet::raw(
                self.header[0] != 0,
                self.header[1],
                std::mem::take(&mut self.payload),
            )));
        }
        Ok(None)
    }

    pub fn finish(self) -> Result<(), LocalPacketError> {
        if self.complete {
            return Ok(());
        }
        if self.prefix_len < PREFIX_LEN {
            Err(LocalPacketError::TruncatedPrefix)
        } else {
            Err(LocalPacketError::TruncatedPayload)
        }
    }
}

impl LocalPacketDecoder {
    /// Stream bytes this decoder has consumed toward its packet.
    fn consumed(&self) -> usize {
        self.prefix_len + self.header_len + self.filled
    }
}

/// [`LocalPacketReader`]'s read-ahead: almost four terminal frames of 16 KiB
/// output plus framing, so a frame that straddles its end moves to the
/// front at most once every few frames.
const READ_AHEAD: usize = 64 * 1024;

/// Reads a stream of length-prefixed packets, one socket read for as many
/// packets as have arrived. [`LocalPacketDecoder`] reads each packet's
/// prefix, header and payload separately and probes for the next packet
/// with a read that would block, so it pays three or four reads per packet.
/// A packet larger than the read-ahead buffer is finished by a
/// [`LocalPacketDecoder`] reading straight into its payload.
pub struct LocalPacketReader {
    /// Allocated on the first read; `start..end` is not yet returned.
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    large: Option<LocalPacketDecoder>,
    /// The last read returned less than it had room for: the stream was
    /// empty at that moment.
    short_read: bool,
}

impl Default for LocalPacketReader {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPacketReader {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            start: 0,
            end: 0,
            large: None,
            short_read: false,
        }
    }

    /// No bytes of an unfinished packet are held.
    pub fn is_empty(&self) -> bool {
        self.buffered_len() == 0
    }

    /// Stream bytes read but not yet returned in a packet.
    pub fn buffered_len(&self) -> usize {
        self.end - self.start + self.large.as_ref().map_or(0, LocalPacketDecoder::consumed)
    }

    /// The next [`Self::read_from`] returns a packet (or its framing error)
    /// without reading the stream.
    pub fn has_packet(&self) -> bool {
        self.large.is_none()
            && match self.buffered_total() {
                Ok(Some(total)) => total <= self.end - self.start,
                Ok(None) => false,
                Err(_) => true,
            }
    }

    /// The stream ran dry during the last read and nothing complete is
    /// buffered: another read now would most likely block. Callers that
    /// poll before reading again can skip that read.
    pub fn likely_empty(&self) -> bool {
        self.short_read && !self.has_packet()
    }

    /// Length of the buffered packet, prefix included, once its prefix is in.
    fn buffered_total(&self) -> Result<Option<usize>, LocalPacketError> {
        let held = &self.buffer[self.start..self.end];
        let Some(prefix) = held.get(..PREFIX_LEN) else {
            return Ok(None);
        };
        let prefix = prefix
            .try_into()
            .expect("prefix slice has PREFIX_LEN bytes");
        Ok(Some(
            PREFIX_LEN + parse_length(prefix, MAX_LOCAL_PACKET_LEN)?,
        ))
    }

    /// The next packet: from what is buffered, else after reading the stream
    /// until a packet completes. `Ok(None)` when the stream would block or a
    /// read found it empty first; end of stream is `UnexpectedEof`, whether
    /// or not bytes of a packet are held (see [`Self::is_empty`]).
    pub fn read_from<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Packet>, LocalPacketError> {
        let mut ran_dry = false;
        loop {
            if let Some(decoder) = self.large.as_mut() {
                let packet = decoder.read_from(reader)?;
                if packet.is_some() {
                    self.large = None;
                }
                return Ok(packet);
            }
            let total = self.buffered_total()?;
            let held = self.end - self.start;
            match total {
                Some(total) if total <= held => {
                    let packet = LocalPacketDecoder::new()
                        .feed(&self.buffer[self.start..self.start + total])?
                        .ok_or(LocalPacketError::TruncatedPayload)?;
                    self.start += total;
                    if self.start == self.end {
                        self.start = 0;
                        self.end = 0;
                    }
                    return Ok(Some(packet));
                }
                Some(total) if total > READ_AHEAD => {
                    let mut decoder = LocalPacketDecoder::new();
                    decoder.feed(&self.buffer[self.start..self.end])?;
                    self.start = 0;
                    self.end = 0;
                    self.large = Some(decoder);
                    continue;
                }
                _ => {}
            }
            // A short read emptied the stream; the rest has not arrived.
            if ran_dry {
                return Ok(None);
            }
            if self.buffer.is_empty() {
                self.buffer = vec![0; READ_AHEAD];
            }
            // Move a partial packet to the front once the rest cannot fit.
            if self.start + total.unwrap_or(PREFIX_LEN) > READ_AHEAD {
                self.buffer.copy_within(self.start..self.end, 0);
                self.end = held;
                self.start = 0;
            }
            let room = READ_AHEAD - self.end;
            self.short_read = false;
            match read_ready(reader, &mut self.buffer[self.end..])? {
                None => return Ok(None),
                Some(count) => {
                    self.end += count;
                    self.short_read = count < room;
                    ran_dry = self.short_read;
                }
            }
        }
    }
}

/// Reads the router stream `etterminal` receives once a session runs.
///
/// Unlike [`LocalPacketDecoder`], one decoder reads the whole stream: each
/// complete message resets it. Every message comes back as a plaintext
/// [`Packet`], whatever its [`RouterFraming`].
pub struct RouterStreamDecoder(RouterStream);

enum RouterStream {
    Packets(LocalPacketDecoder),
    Upstream(UpstreamRouterDecoder),
}

impl RouterStreamDecoder {
    pub fn new(framing: RouterFraming) -> Self {
        Self(match framing {
            RouterFraming::Packets => RouterStream::Packets(LocalPacketDecoder::new()),
            RouterFraming::Upstream => RouterStream::Upstream(UpstreamRouterDecoder::default()),
        })
    }

    /// Read until one message is complete. `Ok(None)` means the reader would
    /// block; the partial message is kept for the next call.
    pub fn read_from<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Packet>, LocalPacketError> {
        match &mut self.0 {
            RouterStream::Packets(decoder) => {
                let packet = decoder.read_from(reader)?;
                if packet.is_some() {
                    *decoder = LocalPacketDecoder::new();
                }
                Ok(packet)
            }
            RouterStream::Upstream(decoder) => decoder.read_from(reader),
        }
    }
}

/// Upstream `UserTerminalHandler::runUserTerminal`: a type byte, then, except
/// for `TERMINAL_CLOSE`, `readProto`'s native `i64` length and protobuf.
#[derive(Default)]
struct UpstreamRouterDecoder {
    header: Option<u8>,
    length: [u8; PREFIX_LEN],
    length_len: usize,
    body_len: Option<usize>,
    payload: Vec<u8>,
    filled: usize,
}

impl UpstreamRouterDecoder {
    fn read_from<R: Read>(&mut self, reader: &mut R) -> Result<Option<Packet>, LocalPacketError> {
        let header = match self.header {
            Some(header) => header,
            None => {
                let mut byte = [0u8; 1];
                if read_ready(reader, &mut byte)?.is_none() {
                    return Ok(None);
                }
                match upstream_router_message(byte[0]) {
                    Some(UpstreamMessage::Close) => {
                        return Ok(Some(Packet::new(byte[0], Vec::new())))
                    }
                    Some(UpstreamMessage::Proto) => {
                        self.header = Some(byte[0]);
                        byte[0]
                    }
                    None => return Err(LocalPacketError::UnknownRouterMessage(byte[0])),
                }
            }
        };
        let body_len = loop {
            if let Some(body_len) = self.body_len {
                break body_len;
            }
            let start = self.length_len;
            let Some(count) = read_ready(reader, &mut self.length[start..])? else {
                return Ok(None);
            };
            self.length_len += count;
            if self.length_len == PREFIX_LEN {
                self.body_len = Some(parse_proto_length(self.length)?);
            }
        };
        while self.filled < body_len {
            grow_payload(&mut self.payload, self.filled, body_len);
            let Some(count) = read_ready(reader, &mut self.payload[self.filled..])? else {
                return Ok(None);
            };
            self.filled += count;
        }
        let packet = Packet::new(header, std::mem::take(&mut self.payload));
        *self = Self::default();
        Ok(Some(packet))
    }
}

/// Upstream `readProto` length: the protobuf alone, up to
/// [`MAX_LOCAL_PACKET_LEN`] like upstream's `DEFAULT_MAX_PROTO_LENGTH`.
fn parse_proto_length(prefix: [u8; PREFIX_LEN]) -> Result<usize, LocalPacketError> {
    parse_length(prefix, MAX_LOCAL_PACKET_LEN)
}

/// Make room for the next read of a `body_len`-byte payload whose first
/// `filled` bytes arrived: once those fill the initialized part, extend it by
/// at most one [`PAYLOAD_READ_STEP`]. A payload of up to one step gets its
/// exact size in one allocation.
fn grow_payload(payload: &mut Vec<u8>, filled: usize, body_len: usize) {
    if payload.len() == filled {
        let len = body_len.min(filled + PAYLOAD_READ_STEP);
        reserve_payload(payload, len, body_len);
        payload.resize(len, 0);
    }
}

/// Let `payload` hold `needed` bytes of a `body_len`-byte payload. The
/// capacity starts at one [`PAYLOAD_READ_STEP`] and at most doubles from
/// there, like upstream `BackedReader` appending to its partial message, so
/// it stays within twice the bytes received plus one step and never exceeds
/// `body_len`.
fn reserve_payload(payload: &mut Vec<u8>, needed: usize, body_len: usize) {
    if needed <= payload.capacity() {
        return;
    }
    let capacity = needed
        .max(PAYLOAD_READ_STEP)
        .max(payload.capacity().saturating_mul(2))
        .min(body_len);
    payload.reserve_exact(capacity - payload.len());
}

/// One `read` into a non-empty `buffer`: `Ok(None)` when it would block, and
/// end of stream as `UnexpectedEof`.
fn read_ready<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<Option<usize>, LocalPacketError> {
    loop {
        match reader.read(buffer) {
            Ok(0) => return Err(LocalPacketError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(count) => return Ok(Some(count)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(LocalPacketError::Io(error)),
        }
    }
}

fn parse_length(prefix: [u8; PREFIX_LEN], limit: usize) -> Result<usize, LocalPacketError> {
    let length = i64::from_ne_bytes(prefix);
    if length < 0 {
        return Err(LocalPacketError::NegativeLength);
    }
    usize::try_from(length)
        .ok()
        .filter(|length| *length <= limit)
        .ok_or(LocalPacketError::FrameTooLarge { length, limit })
}

fn read_exact_classified<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    truncated: LocalPacketError,
) -> Result<(), LocalPacketError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => return Err(truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(LocalPacketError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "local_packet_tests.rs"]
mod tests;
