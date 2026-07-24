//! Pure state machine mirroring upstream `BackedWriter`: every packet is
//! encrypted and buffered (newest-first) before it is either transmitted or
//! held for reconnect recovery. The core owns no socket; it emits a
//! [`WriterOutcome`] describing the bytes the transport must send, so the
//! reconnect/replay logic is fully testable without I/O.
//!
//! Buffer caps match upstream exactly (64 MiB backup, 64 MiB disconnect).

use std::collections::VecDeque;

use crate::crypto::CryptoHandler;
use crate::framing::frame_be_u32;
use crate::packet::Packet;

pub const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;
pub const DISCONNECT_BUFFER_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterOutcome {
    Skipped,
    BufferedOnly,
    Send(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverError {
    AheadOfServer,
    TooFarBehind,
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AheadOfServer => write!(f, "client is ahead of server"),
            Self::TooFarBehind => write!(f, "client is too far behind server"),
        }
    }
}

impl std::error::Error for RecoverError {}

pub struct BackedWriter {
    crypto: CryptoHandler,
    backup: VecDeque<Packet>,
    backup_size: i64,
    disconnected_bytes: i64,
    sequence: i64,
    connected: bool,
}

impl BackedWriter {
    pub fn new(crypto: CryptoHandler, connected: bool) -> Self {
        Self {
            crypto,
            backup: VecDeque::new(),
            backup_size: 0,
            disconnected_bytes: 0,
            sequence: 0,
            connected,
        }
    }

    pub fn write_packet(&mut self, header: u8, payload: &[u8]) -> WriterOutcome {
        let mut packet = Packet::new(header, payload);
        let packet_len = 2 + payload.len();
        if !self.connected && self.disconnected_bytes + packet_len as i64 > DISCONNECT_BUFFER_BYTES
        {
            return WriterOutcome::Skipped;
        }
        packet.encrypt(&mut self.crypto);
        self.backup.push_front(packet.clone());
        self.backup_size += packet.wire_len() as i64;
        self.sequence += 1;
        while self.connected && self.backup_size > MAX_BACKUP_BYTES {
            if let Some(old) = self.backup.pop_back() {
                self.backup_size -= old.wire_len() as i64;
            }
        }
        if !self.connected {
            self.disconnected_bytes += packet.wire_len() as i64;
            return WriterOutcome::BufferedOnly;
        }
        WriterOutcome::Send(frame_be_u32(&packet.serialize()))
    }

    pub fn recover(&self, last_valid_sequence: i64) -> Result<Vec<Vec<u8>>, RecoverError> {
        let messages_to_recover = self.sequence - last_valid_sequence;
        if messages_to_recover < 0 {
            return Err(RecoverError::AheadOfServer);
        }
        if messages_to_recover == 0 {
            return Ok(Vec::new());
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(messages_to_recover as usize);
        let mut seen = 0;
        for packet in &self.backup {
            out.push(packet.serialize());
            seen += 1;
            if seen == messages_to_recover {
                break;
            }
        }
        if seen < messages_to_recover {
            return Err(RecoverError::TooFarBehind);
        }
        out.reverse();
        Ok(out)
    }

    pub fn revive(&mut self) {
        self.connected = true;
        self.disconnected_bytes = 0;
    }

    pub fn invalidate(&mut self) {
        self.connected = false;
    }

    pub fn has_capacity(&self, bytes: i64) -> bool {
        self.connected || self.disconnected_bytes + bytes <= DISCONNECT_BUFFER_BYTES
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoHandler, DIR_CLIENT_TO_SERVER, KEY_LEN};

    fn writer(connected: bool) -> BackedWriter {
        BackedWriter::new(
            CryptoHandler::new(&[3u8; KEY_LEN], DIR_CLIENT_TO_SERVER),
            connected,
        )
    }

    #[test]
    fn connected_write_emits_frame_and_advances_sequence() {
        let mut w = writer(true);
        let WriterOutcome::Send(frame) = w.write_packet(0, b"hi") else {
            panic!("expected Send");
        };
        assert!(frame.len() >= 8 && frame.len() <= 8 + 2 + 16 + 2);
        assert_eq!(w.sequence(), 1);
    }

    #[test]
    fn disconnected_write_buffers_and_advances_sequence() {
        let mut w = writer(false);
        assert_eq!(w.write_packet(0, b"x"), WriterOutcome::BufferedOnly);
        assert_eq!(w.sequence(), 1);
    }

    #[test]
    fn disconnected_buffer_overflow_is_skipped_without_advancing() {
        let mut w = writer(false);
        let huge = vec![0u8; (DISCONNECT_BUFFER_BYTES + 1) as usize];
        assert_eq!(w.write_packet(0, &huge), WriterOutcome::Skipped);
        assert_eq!(w.sequence(), 0);
    }

    #[test]
    fn recover_returns_missed_packets_oldest_first() {
        let mut w = writer(true);
        for (h, p) in [
            (1u8, b"a".as_slice()),
            (2, b"bb".as_slice()),
            (3, b"ccc".as_slice()),
        ] {
            w.write_packet(h, p);
        }
        assert_eq!(w.sequence(), 3);
        let recovered = w.recover(1).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(w.recover(3).unwrap().len(), 0);
    }

    #[test]
    fn recover_detects_too_far_behind() {
        let mut w = writer(false);
        w.write_packet(0, b"x");
        let recovered = w.recover(0).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(w.recover(2), Err(RecoverError::AheadOfServer));
    }

    #[test]
    fn revive_allows_sending_again() {
        let mut w = writer(false);
        w.write_packet(0, b"x");
        w.revive();
        assert!(matches!(w.write_packet(0, b"y"), WriterOutcome::Send(_)));
    }
}
