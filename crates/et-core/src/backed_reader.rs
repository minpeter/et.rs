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

#[derive(Clone)]
pub struct BackedReader {
    crypto: CryptoHandler,
    partial: Vec<u8>,
    replay: VecDeque<Packet>,
    sequence: i64,
    connected: bool,
}

impl BackedReader {
    pub fn new(crypto: CryptoHandler, connected: bool) -> Self {
        Self {
            crypto,
            partial: Vec::new(),
            replay: VecDeque::new(),
            sequence: 0,
            connected,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.partial.extend_from_slice(bytes);
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
        if self.partial.len() < 4 {
            return Ok(ReadItem::NeedMore);
        }
        let len = crate::framing::parse_be_u32_len(&self.partial).map_err(ReadError::Frame)?;
        if self.partial.len() < 4 + len {
            return Ok(ReadItem::NeedMore);
        }
        let serialized = self.partial[4..4 + len].to_vec();
        self.partial.drain(0..4 + len);
        let packet = self.decode_packet(&serialized)?;
        self.sequence += 1;
        Ok(ReadItem::Packet(packet))
    }

    fn decode_packet(&mut self, serialized: &[u8]) -> Result<Packet, ReadError> {
        let mut packet = Packet::from_serialized(serialized).map_err(ReadError::Packet)?;
        if !packet.is_encrypted() {
            return Err(ReadError::Unencrypted);
        }
        packet
            .decrypt(&mut self.crypto)
            .map_err(ReadError::Crypto)?;
        Ok(packet)
    }

    pub fn revive(&mut self, catchup: Vec<Vec<u8>>) -> Result<(), ReadError> {
        let mut crypto = self.crypto.clone();
        let mut decoded = VecDeque::with_capacity(catchup.len());
        for serialized in &catchup {
            let mut packet = Packet::from_serialized(serialized).map_err(ReadError::Packet)?;
            if !packet.is_encrypted() {
                return Err(ReadError::Unencrypted);
            }
            packet.decrypt(&mut crypto).map_err(ReadError::Crypto)?;
            decoded.push_back(packet);
        }
        let n = catchup.len();
        self.partial.clear();
        self.crypto = crypto;
        self.replay.append(&mut decoded);
        self.sequence += n as i64;
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
        self.connected = false;
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
#[path = "backed_reader_tests.rs"]
mod tests;
