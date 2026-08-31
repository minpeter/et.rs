//! Native-`i64` framing for packets exchanged with local terminal processes.

use std::io::{self, Read, Write};
use std::time::Duration;

use et_core::packet::{Packet, PacketError};

pub const MAX_LOCAL_PACKET_LEN: usize = 64 * 1024;
const PREFIX_LEN: usize = std::mem::size_of::<i64>();
/// How long a writer naps before retrying a `WouldBlock` write. Matches the
/// 10ms cadence the Windows pump loops already use.
const BACKPRESSURE_RETRY: Duration = Duration::from_millis(10);

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
    let serialized = packet.serialize();
    if serialized.len() > MAX_LOCAL_PACKET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local packet exceeds 64 KiB",
        ));
    }
    let length = i64::try_from(serialized.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local packet too large"))?;
    let mut frame = Vec::with_capacity(PREFIX_LEN + serialized.len());
    frame.extend_from_slice(&length.to_ne_bytes());
    frame.extend_from_slice(&serialized);
    Ok(frame)
}

pub fn write_local_packet<W: Write>(writer: &mut W, packet: &Packet) -> io::Result<()> {
    let frame = encode_local_packet(packet)?;
    write_all_blocking(writer, &frame)?;
    flush_blocking(writer)
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
fn write_all_blocking<W: Write>(writer: &mut W, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
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

fn flush_blocking<W: Write>(writer: &mut W) -> io::Result<()> {
    loop {
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
    payload: Vec<u8>,
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
            payload: Vec::new(),
            complete: false,
        }
    }

    pub fn required_bytes(&self) -> usize {
        match self.expected {
            None => PREFIX_LEN - self.prefix_len,
            Some(expected) => expected.saturating_sub(self.payload.len()),
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<Option<Packet>, LocalPacketError> {
        if self.complete {
            return Err(LocalPacketError::AlreadyComplete);
        }
        let mut offset = 0;
        if self.expected.is_none() {
            let count = self.required_bytes().min(input.len());
            self.prefix[self.prefix_len..self.prefix_len + count].copy_from_slice(&input[..count]);
            self.prefix_len += count;
            offset += count;
            if self.prefix_len == PREFIX_LEN {
                let expected = parse_length(self.prefix)?;
                self.payload.reserve(expected);
                self.expected = Some(expected);
            }
        }
        if let Some(expected) = self.expected {
            let remaining = expected.saturating_sub(self.payload.len());
            let count = remaining.min(input.len().saturating_sub(offset));
            self.payload
                .extend_from_slice(&input[offset..offset + count]);
            offset += count;
            if self.payload.len() == expected {
                if offset != input.len() {
                    return Err(LocalPacketError::TrailingData);
                }
                self.complete = true;
                return Packet::from_serialized(&self.payload)
                    .map(Some)
                    .map_err(LocalPacketError::MalformedPacket);
            }
        }
        if offset != input.len() {
            return Err(LocalPacketError::TrailingData);
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
