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
    offset: usize,
    replay: VecDeque<Packet>,
    sequence: i64,
    connected: bool,
}

impl BackedReader {
    pub fn new(crypto: CryptoHandler, connected: bool) -> Self {
        Self {
            crypto,
            partial: Vec::new(),
            offset: 0,
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
        let available = &self.partial[self.offset..];
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
        let result = Self::decode_packet(&mut self.crypto, &self.partial[start..end]);
        if self.offset == self.partial.len() {
            self.partial.clear();
            self.offset = 0;
        } else if self.offset >= 64 * 1024 {
            self.partial.drain(0..self.offset);
            self.offset = 0;
        }
        let packet = result?;
        self.sequence += 1;
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
        if ciphertext.len() < crate::crypto::MAC_LEN {
            return Err(ReadError::Crypto(DecryptError::Short));
        }
        let pt_len = ciphertext.len() - crate::crypto::MAC_LEN;
        let mut plaintext = vec![0u8; pt_len];
        let decrypted_len = crypto
            .decrypt_into(&mut plaintext, ciphertext)
            .ok_or(ReadError::Crypto(DecryptError::BadMac))?;
        debug_assert_eq!(decrypted_len, pt_len);
        Ok(Packet::raw(false, serialized[1], plaintext))
    }

    /// Zero sequence history and rekey. Used by authenticated reset recovery.
    pub fn reset(&mut self, salt: &[u8]) -> Result<(), crate::crypto::ProofError> {
        self.crypto.rekey(salt)?;
        self.partial.clear();
        self.offset = 0;
        self.replay.clear();
        self.sequence = 0;
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
        self.partial.clear();
        self.offset = 0;
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
        self.offset = 0;
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
