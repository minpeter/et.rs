//! Native-`i64` framing for packets exchanged with local terminal processes.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use et_core::packet::{Packet, PacketError};

pub const MAX_LOCAL_PACKET_LEN: usize = 64 * 1024;
/// Local-only control packets. These values are deliberately outside the
/// protocol-v6 terminal enum and never cross the encrypted network transport.
pub const REGISTRATION_STATUS: u8 = 254;
pub const STARTUP_STATUS: u8 = 255;
pub const MAX_STATUS_MESSAGE: usize = 8 * 1024;
const PREFIX_LEN: usize = std::mem::size_of::<i64>();
/// How long a blocking local packet writer naps before retrying a `WouldBlock`
/// write on non-Unix or generic `Write` streams.
const BACKPRESSURE_RETRY: Duration = Duration::from_micros(100);

#[derive(Debug)]
pub enum LocalPacketError {
    Io(io::Error),
    TruncatedPrefix,
    TruncatedPayload,
    NegativeLength,
    FrameTooLarge { length: i64 },
    MalformedPacket(PacketError),
    TrailingData,
    AlreadyComplete,
}

impl std::fmt::Display for LocalPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "local packet I/O: {error}"),
            Self::TruncatedPrefix => write!(f, "local packet length prefix is truncated"),
            Self::TruncatedPayload => write!(f, "local packet payload is truncated"),
            Self::NegativeLength => write!(f, "local packet length is negative"),
            Self::FrameTooLarge { length } => {
                write!(f, "local packet length {length} exceeds 64 KiB")
            }
            Self::MalformedPacket(error) => write!(f, "malformed local packet: {error}"),
            Self::TrailingData => write!(f, "local registration contains trailing data"),
            Self::AlreadyComplete => write!(f, "local packet decoder is already complete"),
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
    let length = parse_length(prefix)?;
    let mut serialized = vec![0u8; length];
    read_exact_classified(reader, &mut serialized, LocalPacketError::TruncatedPayload)?;
    Packet::from_serialized(&serialized).map_err(LocalPacketError::MalformedPacket)
}

pub fn encode_local_packet(packet: &Packet) -> io::Result<Vec<u8>> {
    let wire_len = packet.wire_len();
    if wire_len > MAX_LOCAL_PACKET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local packet exceeds 64 KiB",
        ));
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
    /// Frame `output_len` bytes of terminal output; rejects frames over 64 KiB.
    pub fn new(output_len: usize, is_stderr: bool) -> io::Result<Self> {
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local packet exceeds 64 KiB",
            ));
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
    /// stream accepted. `output` must be the slice the frame was created for.
    /// `WouldBlock`/`Interrupted` are returned unchanged for the caller's loop.
    pub fn write_some<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        output: &[u8],
    ) -> io::Result<usize> {
        debug_assert_eq!(output.len(), self.output_len);
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

pub struct LocalPacketDecoder {
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
    pub fn new() -> Self {
        Self {
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
                let expected = parse_length(self.prefix)?;
                self.payload
                    .reserve(expected.saturating_sub(et_core::packet::HEADER_LEN));
                self.expected = Some(expected);
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
                let remaining = body_len.saturating_sub(self.filled);
                let count = remaining.min(input.len().saturating_sub(offset));
                if self.payload.len() == self.filled {
                    self.payload
                        .extend_from_slice(&input[offset..offset + count]);
                } else {
                    self.payload[self.filled..self.filled + count]
                        .copy_from_slice(&input[offset..offset + count]);
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
                        let expected = parse_length(self.prefix)?;
                        self.payload
                            .resize(expected.saturating_sub(et_core::packet::HEADER_LEN), 0);
                        self.expected = Some(expected);
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
                match reader.read(&mut self.payload[self.filled..body_len]) {
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

fn parse_length(prefix: [u8; PREFIX_LEN]) -> Result<usize, LocalPacketError> {
    let length = i64::from_ne_bytes(prefix);
    if length < 0 {
        return Err(LocalPacketError::NegativeLength);
    }
    if length > MAX_LOCAL_PACKET_LEN as i64 {
        return Err(LocalPacketError::FrameTooLarge { length });
    }
    usize::try_from(length).map_err(|_| LocalPacketError::FrameTooLarge { length })
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
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};

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
}
