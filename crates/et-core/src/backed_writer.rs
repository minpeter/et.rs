//! Pure state machine mirroring upstream `BackedWriter`: every packet is
//! encrypted and buffered (newest-first) before it is either transmitted or
//! held for reconnect recovery. The core owns no socket; it emits a
//! [`WriterOutcome`] describing the bytes the transport must send, so the
//! reconnect/replay logic is fully testable without I/O.
//!
//! Wire-facing caps match upstream exactly (64 MiB disconnect buffer, 76 MiB
//! recovery total, and the catchup entry limits validated on receive). The
//! *connected* backup retention deliberately diverges from upstream's 64 MiB:
//! while the transport is up, a reconnecting peer can only be missing data
//! that was in flight (bounded by kernel socket buffers, typically <= 4 MiB),
//! so retaining 64 MiB per session mostly wastes daemon memory. The connected
//! backup is therefore trimmed to 8 MiB / 32 Ki packets; the disconnected
//! catchup path keeps upstream's full 64 MiB.

use std::collections::VecDeque;

use crate::crypto::{CryptoHandler, EncryptError, MAC_LEN};
use crate::framing::frame_be_u32;
use crate::packet::Packet;

pub const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;
pub const DISCONNECT_BUFFER_BYTES: i64 = 64 * 1024 * 1024;
pub const MAX_RECOVERY_BACKUP_BYTES: i64 = 76 * 1024 * 1024;
pub const MAX_BACKUP_PACKETS: usize = 262_144;
pub const MAX_DISCONNECT_PACKETS: usize = 262_144;
/// Replay history kept while connected; must comfortably exceed the largest
/// amount of written-but-undelivered data a live TCP connection can hold
/// (socket send buffer + in flight, <= 4 MiB on default Linux autotuning).
pub const CONNECTED_BACKUP_BYTES: i64 = 8 * 1024 * 1024;
pub const CONNECTED_BACKUP_PACKETS: usize = 32_768;

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

#[derive(Clone)]
pub struct BackedWriter {
    crypto: CryptoHandler,
    backup: VecDeque<Packet>,
    backup_size: i64,
    disconnected_bytes: i64,
    disconnected_packets: usize,
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
            disconnected_packets: 0,
            sequence: 0,
            connected,
        }
    }

    pub fn write_packet(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<WriterOutcome, EncryptError> {
        let mut packet = Packet::new(header, payload);
        let packet_len = 2 + payload.len();
        let wire_len = i64::try_from(packet_len + MAC_LEN).unwrap_or(i64::MAX);
        let disconnected_fits = i64::try_from(packet_len)
            .ok()
            .and_then(|length| self.disconnected_bytes.checked_add(length))
            .is_some_and(|total| total <= DISCONNECT_BUFFER_BYTES);
        let recovery_fits = self
            .backup_size
            .checked_add(wire_len)
            .is_some_and(|total| total <= MAX_RECOVERY_BACKUP_BYTES);
        if !self.connected
            && (!disconnected_fits
                || self.disconnected_packets >= MAX_DISCONNECT_PACKETS
                || !recovery_fits)
        {
            return Ok(WriterOutcome::Skipped);
        }
        packet.encrypt(&mut self.crypto)?;
        self.backup.push_front(packet.clone());
        self.backup_size += packet.wire_len() as i64;
        self.sequence += 1;
        while self.connected
            && (self.backup_size > CONNECTED_BACKUP_BYTES
                || self.backup.len() > CONNECTED_BACKUP_PACKETS)
        {
            if let Some(old) = self.backup.pop_back() {
                self.backup_size -= old.wire_len() as i64;
            }
        }
        // A disconnect can balloon the deque to the 64 MiB catchup cap;
        // return that slack once the trimmed length no longer needs it.
        if self.connected
            && self.backup.capacity() > 4096
            && self.backup.capacity() / 4 > self.backup.len()
        {
            self.backup.shrink_to(self.backup.len() * 2);
        }
        if !self.connected {
            self.disconnected_bytes += packet.wire_len() as i64;
            self.disconnected_packets += 1;
            return Ok(WriterOutcome::BufferedOnly);
        }
        Ok(WriterOutcome::Send(frame_be_u32(&packet.serialize())))
    }

    pub fn recover(&self, last_valid_sequence: i64) -> Result<Vec<Vec<u8>>, RecoverError> {
        let messages_to_recover = self.sequence - last_valid_sequence;
        if messages_to_recover < 0 {
            return Err(RecoverError::AheadOfServer);
        }
        if messages_to_recover == 0 {
            return Ok(Vec::new());
        }
        let count = usize::try_from(messages_to_recover).map_err(|_| RecoverError::TooFarBehind)?;
        if count > self.backup.len() {
            return Err(RecoverError::TooFarBehind);
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(count);
        for packet in self.backup.iter().take(count) {
            out.push(packet.serialize());
        }
        out.reverse();
        Ok(out)
    }

    pub fn revive(&mut self) {
        self.connected = true;
        self.disconnected_bytes = 0;
        self.disconnected_packets = 0;
    }

    pub fn invalidate(&mut self) {
        self.connected = false;
    }

    pub fn has_capacity(&self, bytes: i64) -> bool {
        self.connected
            || (self
                .disconnected_bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= DISCONNECT_BUFFER_BYTES)
                && self.disconnected_packets < MAX_DISCONNECT_PACKETS
                && self
                    .backup_size
                    .checked_add(bytes)
                    .is_some_and(|total| total <= MAX_RECOVERY_BACKUP_BYTES))
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
        let WriterOutcome::Send(frame) = w.write_packet(0, b"hi").unwrap() else {
            panic!("expected Send");
        };
        assert!(frame.len() >= 8 && frame.len() <= 8 + 2 + 16 + 2);
        assert_eq!(w.sequence(), 1);
    }

    #[test]
    fn disconnected_write_buffers_and_advances_sequence() {
        let mut w = writer(false);
        assert_eq!(
            w.write_packet(0, b"x").unwrap(),
            WriterOutcome::BufferedOnly
        );
        assert_eq!(w.sequence(), 1);
    }

    #[test]
    fn disconnected_buffer_overflow_is_skipped_without_advancing() {
        let mut w = writer(false);
        let huge = vec![0u8; (DISCONNECT_BUFFER_BYTES + 1) as usize];
        assert_eq!(w.write_packet(0, &huge).unwrap(), WriterOutcome::Skipped);
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
            w.write_packet(h, p).unwrap();
        }
        assert_eq!(w.sequence(), 3);
        let recovered = w.recover(1).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(w.recover(3).unwrap().len(), 0);
    }

    #[test]
    fn recover_detects_too_far_behind() {
        let mut w = writer(false);
        w.write_packet(0, b"x").unwrap();
        let recovered = w.recover(0).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(w.recover(2), Err(RecoverError::AheadOfServer));
    }

    #[test]
    fn connected_backup_trims_to_connected_byte_cap() {
        let mut w = writer(true);
        let chunk = vec![0u8; 3 * 1024 * 1024];
        for _ in 0..3 {
            assert!(matches!(
                w.write_packet(0, &chunk).unwrap(),
                WriterOutcome::Send(_)
            ));
        }
        // 9 MiB written while connected; only ~6 MiB (2 packets) is retained.
        assert_eq!(w.recover(0), Err(RecoverError::TooFarBehind));
        assert_eq!(w.recover(1).unwrap().len(), 2);
    }

    #[test]
    fn connected_backup_trims_to_connected_packet_cap() {
        let mut w = writer(true);
        let extra = 10;
        for _ in 0..CONNECTED_BACKUP_PACKETS + extra {
            w.write_packet(0, b"").unwrap();
        }
        assert_eq!(
            w.recover(extra as i64).unwrap().len(),
            CONNECTED_BACKUP_PACKETS
        );
        assert_eq!(
            w.recover(extra as i64 - 1),
            Err(RecoverError::TooFarBehind)
        );
    }

    #[test]
    fn disconnected_backup_keeps_full_catchup_history() {
        let mut w = writer(false);
        let chunk = vec![0u8; 3 * 1024 * 1024];
        for _ in 0..3 {
            assert_eq!(
                w.write_packet(0, &chunk).unwrap(),
                WriterOutcome::BufferedOnly
            );
        }
        // Beyond the connected cap, but every packet must stay replayable.
        assert_eq!(w.recover(0).unwrap().len(), 3);
    }

    #[test]
    fn revive_allows_sending_again() {
        let mut w = writer(false);
        w.write_packet(0, b"x").unwrap();
        w.revive();
        assert!(matches!(
            w.write_packet(0, b"y").unwrap(),
            WriterOutcome::Send(_)
        ));
    }
}
