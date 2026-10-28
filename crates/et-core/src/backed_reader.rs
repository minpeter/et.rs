//! Pure state machine mirroring upstream `BackedReader`: reassembles 4-byte
//! big-endian framed packets, decrypts them, and replays catchup packets
//! queued during reconnect before resuming live reads. Owns no socket; bytes
//! arrive via [`BackedReader::feed`] and packets leave via [`BackedReader::pop`],
//! so framing and nonce-synchronised replay are testable without I/O.

use std::collections::VecDeque;

use crate::crypto::{CryptoHandler, DecryptError};
use crate::packet::{Packet, PacketError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadItem {
    Packet(Packet),
    NeedMore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Frame(crate::framing::FrameError),
    Packet(PacketError),
    Crypto(DecryptError),
    Unencrypted,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::Packet(e) => write!(f, "packet: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Unencrypted => write!(f, "unencrypted packet on encrypted stream"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Smallest socket read [`BackedReader::prepare_socket_read`] asks for: all an
/// idle or interactive connection ever zero-fills.
pub const MIN_SOCKET_READ: usize = 16 * 1024;
/// Largest socket read; a bulk stream reaches it after two full reads. Reads
/// align to frame boundaries (see `aligned_read_len`), so the cap only trades
/// syscalls and wakeups against buffer memory. Connections use
/// [`CLIENT_MAX_SOCKET_READ`] or [`SERVER_MAX_SOCKET_READ`].
pub const MAX_SOCKET_READ: usize = 256 * 1024;
/// Socket read cap of a client connection, upstream's `BackedReader` read
/// size. Terminal output the client has read but not painted cannot be
/// dropped by Ctrl+C and delays the echo of every keystroke behind it; what
/// stays in the kernel instead also holds back the server through TCP flow
/// control.
pub const CLIENT_MAX_SOCKET_READ: usize = 64 * 1024;
/// Socket read cap of a server connection. A server multiplexes many
/// sessions, so this buffer is what a bulk upload adds per session: one
/// aligned 64 KiB-packet frame per read keeps 16 concurrent uploads at 17 MB
/// of server RSS (ET-C++: 18 MB) for 2-3% more server CPU than 256 KiB reads.
pub const SERVER_MAX_SOCKET_READ: usize = 96 * 1024;

const KEEP_ALIVE: u8 = crate::proto::TerminalPacketType::KeepAlive as u8;

#[derive(Clone)]
pub struct BackedReader {
    crypto: CryptoHandler,
    partial: Vec<u8>,
    offset: usize,
    filled: usize,
    replay: VecDeque<Packet>,
    sequence: i64,
    /// `sequence` right after the latest packet that was not a keep-alive.
    data_sequence: i64,
    connected: bool,
    /// Size of the next socket read, adapted to how full recent reads were.
    read_hint: usize,
    /// Size of the socket read in flight, to tell a full read from a short one.
    read_requested: usize,
    /// Wire length (with its prefix) of the last frame decoded, 0 before one.
    last_frame_len: usize,
    /// Upper bound for `read_hint`.
    max_socket_read: usize,
}

impl BackedReader {
    pub fn new(crypto: CryptoHandler, connected: bool) -> Self {
        Self {
            crypto,
            partial: Vec::new(),
            offset: 0,
            filled: 0,
            replay: VecDeque::new(),
            sequence: 0,
            data_sequence: 0,
            connected,
            read_hint: MIN_SOCKET_READ,
            read_requested: 0,
            last_frame_len: 0,
            max_socket_read: MAX_SOCKET_READ,
        }
    }

    /// Cap socket reads at `bytes` instead of [`MAX_SOCKET_READ`].
    pub fn with_max_socket_read(mut self, bytes: usize) -> Self {
        self.max_socket_read = bytes.max(MIN_SOCKET_READ);
        self
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let slice = self.prepare_read_slice(bytes.len());
        slice[..bytes.len()].copy_from_slice(bytes);
        self.commit_read(bytes.len());
    }

    pub fn prepare_read_slice(&mut self, min_space: usize) -> &mut [u8] {
        if self.offset == self.filled {
            self.offset = 0;
            self.filled = 0;
        } else if self.offset > 0
            && (self.partial.len().saturating_sub(self.filled) < min_space
                || self.offset >= 64 * 1024
                || (self.filled - self.offset) <= 16 * 1024)
        {
            let remaining = self.filled - self.offset;
            self.partial.copy_within(self.offset..self.filled, 0);
            self.offset = 0;
            self.filled = remaining;
        }
        let required = self.filled + min_space;
        if self.partial.len() < required {
            self.partial.resize(required, 0);
        }
        &mut self.partial[self.filled..]
    }

    pub fn commit_read(&mut self, count: usize) {
        self.filled += count;
    }

    /// Space for the next socket read, sized by recent reads: it starts at
    /// [`MIN_SOCKET_READ`], so an idle connection never zero-fills a
    /// bulk-sized buffer, quadruples up to [`MAX_SOCKET_READ`] while reads
    /// fill it, and halves after a read returns less than a quarter of it. A
    /// drained buffer that grew for a burst is released once reads are back
    /// at the minimum. Report the result with [`Self::commit_socket_read`].
    pub fn prepare_socket_read(&mut self) -> &mut [u8] {
        if self.offset == self.filled
            && self.read_hint == MIN_SOCKET_READ
            && self.partial.capacity() > 4 * MIN_SOCKET_READ
        {
            self.partial = Vec::new();
            self.offset = 0;
            self.filled = 0;
        }
        let size = self.aligned_read_len(self.read_hint);
        self.read_requested = size;
        &mut self.prepare_read_slice(size)[..size]
    }

    /// A read size near `limit` that ends on a frame boundary when the frames
    /// that follow are as long as the last one: the rest of a pending frame
    /// plus whole frames. Uniform bulk frames then never leave a partial frame
    /// behind to move to the front of the buffer before the next read; small
    /// (interactive) frames are not worth aligning.
    fn aligned_read_len(&self, limit: usize) -> usize {
        let frame = self.last_frame_len;
        if frame < MIN_SOCKET_READ / 4 {
            return limit;
        }
        let pending = &self.partial[self.offset..self.filled];
        let rest = match pending.len() {
            0 => 0,
            1..=3 => return limit,
            _ => match crate::framing::parse_be_u32_len(pending) {
                Ok(len) => (4 + len).saturating_sub(pending.len()),
                Err(_) => return limit,
            },
        };
        if rest >= limit {
            return rest;
        }
        let whole = (limit - rest) / frame;
        if rest == 0 && whole == 0 {
            return limit;
        }
        rest + whole * frame
    }

    /// Record `count` bytes read into the slice from
    /// [`Self::prepare_socket_read`] and adapt the next read's size.
    pub fn commit_socket_read(&mut self, count: usize) {
        self.commit_read(count);
        if count >= self.read_requested {
            self.read_hint = (self.read_hint * 4).min(self.max_socket_read);
        } else if count < self.read_hint / 4 {
            self.read_hint = (self.read_hint / 2).max(MIN_SOCKET_READ);
        }
    }

    pub fn has_buffered_data(&self) -> bool {
        if !self.connected {
            return false;
        }
        if !self.replay.is_empty() {
            return true;
        }
        let available = &self.partial[self.offset..self.filled];
        if available.len() < 4 {
            return false;
        }
        match crate::framing::parse_be_u32_len(available) {
            Ok(len) => len < crate::packet::HEADER_LEN || available.len() >= 4 + len,
            Err(_) => true,
        }
    }

    pub fn pop(&mut self) -> Result<ReadItem, ReadError> {
        if !self.connected {
            return Ok(ReadItem::NeedMore);
        }
        if let Some(packet) = self.replay.pop_front() {
            return Ok(ReadItem::Packet(packet));
        }
        self.pop_live()
    }

    pub fn pop_live(&mut self) -> Result<ReadItem, ReadError> {
        if !self.connected {
            return Ok(ReadItem::NeedMore);
        }
        let available = &self.partial[self.offset..self.filled];
        if available.len() < 4 {
            return Ok(ReadItem::NeedMore);
        }
        let len = crate::framing::parse_be_u32_len(available).map_err(ReadError::Frame)?;
        // Reject impossible lengths before copying a body. A length below the
        // packet header cannot be a real frame (upstream #890 / 4545da5).
        if len < crate::packet::HEADER_LEN {
            return Err(ReadError::Frame(crate::framing::FrameError::TooSmall));
        }
        if available.len() < 4 + len {
            return Ok(ReadItem::NeedMore);
        }
        let start = self.offset + 4;
        let end = start + len;
        self.offset = end;
        self.last_frame_len = 4 + len;
        let result = Self::decode_packet(&mut self.crypto, &self.partial[start..end]);
        if self.offset == self.filled {
            self.offset = 0;
            self.filled = 0;
        }
        let packet = result?;
        self.sequence += 1;
        self.note_data(&packet);
        Ok(ReadItem::Packet(packet))
    }

    fn decode_packet(crypto: &mut CryptoHandler, serialized: &[u8]) -> Result<Packet, ReadError> {
        if serialized.len() < crate::packet::HEADER_LEN {
            return Err(ReadError::Packet(PacketError::Short));
        }
        if serialized[0] == 0 {
            return Err(ReadError::Unencrypted);
        }
        let ciphertext = &serialized[crate::packet::HEADER_LEN..];
        let plaintext = crypto.decrypt(ciphertext).map_err(ReadError::Crypto)?;
        Ok(Packet::raw(false, serialized[1], plaintext))
    }

    /// Zero sequence history and rekey. Used by authenticated reset recovery.
    pub fn reset(&mut self, salt: &[u8]) -> Result<(), crate::crypto::ProofError> {
        self.crypto.rekey(salt)?;
        self.partial.clear();
        self.offset = 0;
        self.filled = 0;
        self.replay.clear();
        self.sequence = 0;
        self.data_sequence = 0;
        self.connected = false;
        Ok(())
    }

    pub fn revive(&mut self, catchup: Vec<Vec<u8>>) -> Result<(), ReadError> {
        let mut crypto = self.crypto.clone();
        let mut decoded = VecDeque::with_capacity(catchup.len());
        for serialized in &catchup {
            let packet = Self::decode_packet(&mut crypto, serialized)?;
            decoded.push_back(packet);
        }
        let n = catchup.len();
        let carries_data = decoded.iter().any(|packet| packet.header() != KEEP_ALIVE);
        self.partial.clear();
        self.offset = 0;
        self.filled = 0;
        self.crypto = crypto;
        self.replay.append(&mut decoded);
        self.sequence += n as i64;
        if carries_data {
            self.data_sequence = self.sequence;
        }
        self.connected = true;
        Ok(())
    }

    /// Requeue a live packet consumed during recovery so it is returned by
    /// `pop()` after the catchup replay entries, preserving stream order.
    /// Must be called before any post-revive `pop()`; the recovery proof
    /// packet may be regular session traffic when the peer is the upstream
    /// C++ implementation, so it must not be lost.
    pub fn unread(&mut self, packet: Packet) {
        self.replay.push_back(packet);
    }

    pub fn invalidate(&mut self) {
        self.partial.clear();
        self.offset = 0;
        self.filled = 0;
        self.connected = false;
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// [`Self::sequence`] right after the latest packet read that was not a
    /// keep-alive, so an acknowledgement can tell whether it covers more than
    /// keep-alives (see [`crate::keepalive::AckSchedule`]).
    pub fn data_sequence(&self) -> i64 {
        self.data_sequence
    }

    fn note_data(&mut self, packet: &Packet) {
        if packet.header() != KEEP_ALIVE {
            self.data_sequence = self.sequence;
        }
    }

    pub fn connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
#[path = "backed_reader_tests.rs"]
mod tests;
