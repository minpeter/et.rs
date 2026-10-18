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

pub const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;
pub const DISCONNECT_BUFFER_BYTES: i64 = 64 * 1024 * 1024;
pub const MAX_RECOVERY_BACKUP_BYTES: i64 = 76 * 1024 * 1024;
pub const MAX_BACKUP_PACKETS: usize = 262_144;
pub const MAX_DISCONNECT_PACKETS: usize = 262_144;
/// Replay history kept while connected; must comfortably exceed the largest
/// amount of written-but-undelivered data a live TCP connection can hold.
/// Kernel buffers alone can exceed 8 MiB on an autotuned loopback, so
/// writers whose peer acknowledges delivery also stop producing at
/// [`MAX_UNACKNOWLEDGED_BYTES`] (see [`BackedWriter::delivery_backlog`]).
pub const CONNECTED_BACKUP_BYTES: i64 = 8 * 1024 * 1024;
pub const CONNECTED_BACKUP_PACKETS: usize = 32_768;
/// Unacknowledged bytes after which an acknowledging peer's writer should
/// stop producing until the next acknowledgement. Together with the retained
/// slack (<= [`ACK_RETAIN_FLOOR_PACKETS`] frames) this stays well inside
/// [`CONNECTED_BACKUP_BYTES`], so the connected cap never trims a packet the
/// peer could still request, and it bounds the replay memory a bulk transfer
/// pins regardless of how much the kernel is willing to buffer.
pub const MAX_UNACKNOWLEDGED_BYTES: i64 = 4 * 1024 * 1024;
/// Upper bound on acknowledged packets retained beyond an acknowledged
/// sequence (see [`BackedWriter::acknowledge`]).
pub const ACK_RETAIN_SLACK_PACKETS: usize = 1024;
/// Acknowledged history retained once [`ACK_RETAIN_FLOOR_PACKETS`] are kept.
/// Small interactive packets still keep the full packet slack; bulk
/// forwarding packets (up to 64 KiB) stop at the floor instead of pinning
/// the whole connected cap after every transfer.
pub const ACK_RETAIN_SLACK_BYTES: usize = 256 * 1024;
/// Acknowledged packets always retained, whatever their size.
///
/// An acknowledgement is normally per-hop and exact, but a jumphost that
/// relays keep-alives verbatim can deliver a *different* hop's reader
/// sequence. The two sequence domains only drift by packets the relay
/// injects outside the relayed stream: et.rs jumphosts up to et@0.0.7 relay
/// keep-alives verbatim and inject one proof keep-alive per recovery, so the
/// drift grows by one per recovery. Upstream C++ relays
/// (`TerminalServer::runJumpHost`, `UserJumphostHandler`) inject nothing:
/// recovery replays existing sequence numbers and each hop's
/// `INITIAL_PAYLOAD` is consumed and re-sent one-for-one. Retaining this many
/// packets keeps a foreign acknowledgement from trimming anything a genuine
/// recovery could request for the first 16 recoveries through such a legacy
/// relay, while bounding the bulk-transfer cost to 16 frames (<= 1 MiB).
pub const ACK_RETAIN_FLOOR_PACKETS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterOutcome {
    Skipped,
    BufferedOnly,
    Send(std::sync::Arc<Vec<u8>>),
}

pub struct ReservedWrite {
    prefix: [u8; 6],
    nonce: [u8; crate::crypto::NONCE_LEN],
    key: [u8; crate::crypto::KEY_LEN],
    packet_wire_len: usize,
}

impl ReservedWrite {
    pub fn encrypt(&self, payload: &[u8]) -> std::sync::Arc<Vec<u8>> {
        std::sync::Arc::new(CryptoHandler::encrypt_detached(
            &self.prefix,
            payload,
            &self.nonce,
            &self.key,
        ))
    }
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
    backup: VecDeque<std::sync::Arc<Vec<u8>>>,
    backup_size: i64,
    disconnected_bytes: i64,
    disconnected_packets: usize,
    sequence: i64,
    connected: bool,
    /// Latest plausible peer acknowledgement; `None` until the peer proves it
    /// acknowledges at all (legacy peers never do).
    acknowledged: Option<i64>,
    /// Wire bytes written after `acknowledged`, including packets the
    /// connected cap already dropped from `backup`.
    unacknowledged_bytes: i64,
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
            acknowledged: None,
            unacknowledged_bytes: 0,
        }
    }

    pub fn reserve_write(&mut self, header: u8, payload_len: usize) -> Option<ReservedWrite> {
        let packet_len = 2 + payload_len;
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
            return None;
        }
        let packet_wire_len = 2 + payload_len + MAC_LEN;
        let mut prefix = [0u8; 6];
        prefix[0..4].copy_from_slice(&(packet_wire_len as u32).to_be_bytes());
        prefix[4] = 1;
        prefix[5] = header;
        let (nonce, key) = self.crypto.next_nonce_and_key();
        Some(ReservedWrite {
            prefix,
            nonce,
            key,
            packet_wire_len,
        })
    }

    pub fn commit_write(
        &mut self,
        reserved: ReservedWrite,
        frame: std::sync::Arc<Vec<u8>>,
    ) -> WriterOutcome {
        let packet_wire_len = reserved.packet_wire_len;
        self.unacknowledged_bytes += packet_wire_len as i64;
        if !self.connected {
            self.backup.push_front(frame);
            self.backup_size += packet_wire_len as i64;
            self.sequence += 1;
            self.disconnected_bytes += packet_wire_len as i64;
            self.disconnected_packets += 1;
            return WriterOutcome::BufferedOnly;
        }
        self.backup.push_front(std::sync::Arc::clone(&frame));
        self.backup_size += packet_wire_len as i64;
        self.sequence += 1;
        while self.backup_size > CONNECTED_BACKUP_BYTES
            || self.backup.len() > CONNECTED_BACKUP_PACKETS
        {
            if let Some(old) = self.backup.pop_back() {
                self.backup_size -= (old.len() - 4) as i64;
            }
        }
        self.release_slack_capacity();
        WriterOutcome::Send(frame)
    }

    pub fn write_packet(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<WriterOutcome, EncryptError> {
        let Some(reserved) = self.reserve_write(header, payload.len()) else {
            return Ok(WriterOutcome::Skipped);
        };
        let frame = reserved.encrypt(payload);
        Ok(self.commit_write(reserved, frame))
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
        for frame in self.backup.iter().take(count) {
            out.push(frame[4..].to_vec());
        }
        out.reverse();
        Ok(out)
    }

    /// Drop backup packets the peer has confirmed it consumed.
    ///
    /// `acknowledged` is the peer's reader sequence, delivered on a
    /// keep-alive payload (see [`crate::keepalive`]). The still-unacknowledged
    /// tail is always kept, followed by up to [`ACK_RETAIN_SLACK_PACKETS`]
    /// acknowledged packets: at least [`ACK_RETAIN_FLOOR_PACKETS`] of them,
    /// and beyond that only while they fit [`ACK_RETAIN_SLACK_BYTES`]. An idle
    /// session's backup therefore stays near-empty and a bulk transfer stops
    /// pinning the full connected cap. Ignored while disconnected (a
    /// reconnect may replay any of it) and for implausible sequences.
    pub fn acknowledge(&mut self, acknowledged: i64) {
        if !self.connected || acknowledged < 0 || acknowledged > self.sequence {
            return;
        }
        let unacknowledged = usize::try_from(self.sequence - acknowledged).unwrap_or(usize::MAX);
        self.acknowledged = Some(acknowledged);
        self.unacknowledged_bytes = self
            .backup
            .iter()
            .take(unacknowledged)
            .map(|frame| (frame.len() - 4) as i64)
            .sum();
        let mut keep = unacknowledged.min(self.backup.len());
        let mut slack_packets = 0;
        let mut slack_bytes = 0;
        while slack_packets < ACK_RETAIN_SLACK_PACKETS {
            let Some(frame) = self.backup.get(keep) else {
                break;
            };
            let wire_len = frame.len() - 4;
            if slack_packets >= ACK_RETAIN_FLOOR_PACKETS
                && slack_bytes + wire_len > ACK_RETAIN_SLACK_BYTES
            {
                break;
            }
            slack_packets += 1;
            slack_bytes += wire_len;
            keep += 1;
        }
        while self.backup.len() > keep {
            if let Some(old) = self.backup.pop_back() {
                self.backup_size -= (old.len() - 4) as i64;
            }
        }
        self.release_slack_capacity();
    }

    /// The peer's latest acknowledged sequence and the wire bytes written
    /// since, or `None` while the peer has never acknowledged delivery.
    pub fn delivery_backlog(&self) -> Option<(i64, i64)> {
        self.acknowledged
            .map(|acknowledged| (acknowledged, self.unacknowledged_bytes))
    }

    /// A disconnect can balloon the deque to the 64 MiB catchup cap; return
    /// that slack once the trimmed length no longer needs it.
    fn release_slack_capacity(&mut self) {
        if self.backup.capacity() > 4096 && self.backup.capacity() / 4 > self.backup.len() {
            self.backup.shrink_to(self.backup.len() * 2);
        }
    }

    pub fn revive(&mut self) {
        self.connected = true;
        self.disconnected_bytes = 0;
        self.disconnected_packets = 0;
        // Drop the oldest history the way a connected write trims, so a quick
        // reconnect cannot stack another disconnect buffer on an untrimmed
        // backup (upstream #890 / e3e49d5). Newest packets stay: they are the
        // catchup a retry may still need. The live 8 MiB cap still applies on
        // the next connected write.
        while self.backup_size > MAX_BACKUP_BYTES {
            let Some(old) = self.backup.pop_back() else {
                break;
            };
            self.backup_size -= (old.len() - 4) as i64;
        }
        self.release_slack_capacity();
    }

    /// Zero sequence history and rekey from the original passkey.
    pub fn reset(&mut self, salt: &[u8]) -> Result<(), crate::crypto::ProofError> {
        self.crypto.rekey(salt)?;
        self.backup.clear();
        self.backup_size = 0;
        self.disconnected_bytes = 0;
        self.disconnected_packets = 0;
        self.sequence = 0;
        self.connected = false;
        self.acknowledged = None;
        self.unacknowledged_bytes = 0;
        Ok(())
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
        assert_eq!(w.recover(extra as i64 - 1), Err(RecoverError::TooFarBehind));
    }

    #[test]
    fn acknowledge_trims_to_the_unacknowledged_tail_plus_slack() {
        let mut w = writer(true);
        let total = ACK_RETAIN_SLACK_PACKETS + 100;
        for _ in 0..total {
            w.write_packet(0, b"x").unwrap();
        }
        w.acknowledge(w.sequence());
        // Everything is acknowledged; only the slack margin remains.
        let oldest_recoverable = (total - ACK_RETAIN_SLACK_PACKETS) as i64;
        assert_eq!(
            w.recover(oldest_recoverable).unwrap().len(),
            ACK_RETAIN_SLACK_PACKETS
        );
        assert_eq!(
            w.recover(oldest_recoverable - 1),
            Err(RecoverError::TooFarBehind)
        );
    }

    #[test]
    fn acknowledge_keeps_unacknowledged_packets() {
        let mut w = writer(true);
        for _ in 0..10 {
            w.write_packet(0, b"x").unwrap();
        }
        w.acknowledge(4);
        // Nothing may be dropped: 6 unacknowledged + slack exceeds the 10 kept.
        assert_eq!(w.recover(0).unwrap().len(), 10);
    }

    #[test]
    fn acknowledge_bounds_bulk_slack_to_the_packet_floor() {
        let mut w = writer(true);
        let chunk = vec![0u8; 64 * 1024];
        let total = 100;
        for _ in 0..total {
            w.write_packet(0, &chunk).unwrap();
        }
        let unacknowledged = 5;
        w.acknowledge(w.sequence() - unacknowledged);
        // Every unacknowledged frame plus exactly the floor of acknowledged
        // ones survive, even though the floor alone exceeds the byte slack.
        let kept = unacknowledged as usize + ACK_RETAIN_FLOOR_PACKETS;
        let oldest_recoverable = w.sequence() - kept as i64;
        assert_eq!(w.recover(oldest_recoverable).unwrap().len(), kept);
        assert_eq!(
            w.recover(oldest_recoverable - 1),
            Err(RecoverError::TooFarBehind)
        );
    }

    #[test]
    fn acknowledge_keeps_acknowledged_packets_within_the_byte_slack() {
        let mut w = writer(true);
        let payload = vec![0u8; 4 * 1024];
        for _ in 0..ACK_RETAIN_SLACK_PACKETS {
            w.write_packet(0, &payload).unwrap();
        }
        w.acknowledge(w.sequence());
        let wire_len = 2 + payload.len() + MAC_LEN;
        let kept = ACK_RETAIN_SLACK_BYTES / wire_len;
        assert!(kept > ACK_RETAIN_FLOOR_PACKETS);
        let oldest_recoverable = w.sequence() - kept as i64;
        assert_eq!(w.recover(oldest_recoverable).unwrap().len(), kept);
        assert_eq!(
            w.recover(oldest_recoverable - 1),
            Err(RecoverError::TooFarBehind)
        );
    }

    #[test]
    fn delivery_backlog_counts_bytes_written_after_the_latest_acknowledgement() {
        let mut w = writer(true);
        let payload = vec![0u8; 1000];
        let wire_len = (2 + payload.len() + MAC_LEN) as i64;
        for _ in 0..10 {
            w.write_packet(0, &payload).unwrap();
        }
        // A peer that never acknowledged is a legacy peer: no backlog signal.
        assert_eq!(w.delivery_backlog(), None);
        w.acknowledge(4);
        assert_eq!(w.delivery_backlog(), Some((4, 6 * wire_len)));
        w.write_packet(0, &payload).unwrap();
        assert_eq!(w.delivery_backlog(), Some((4, 7 * wire_len)));
        w.acknowledge(w.sequence());
        assert_eq!(w.delivery_backlog(), Some((11, 0)));
    }

    #[test]
    fn acknowledge_ignores_implausible_and_disconnected_states() {
        let mut w = writer(true);
        for _ in 0..ACK_RETAIN_SLACK_PACKETS + 50 {
            w.write_packet(0, b"x").unwrap();
        }
        let len = |w: &BackedWriter| w.recover(0).map(|out| out.len());
        let full = len(&w).unwrap();
        w.acknowledge(w.sequence() + 1); // ahead of what was written
        assert_eq!(len(&w), Ok(full));
        w.acknowledge(-1);
        assert_eq!(len(&w), Ok(full));
        w.invalidate();
        w.acknowledge(w.sequence());
        w.revive();
        assert_eq!(len(&w), Ok(full));
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
    fn revive_trims_oldest_history_above_the_backup_cap() {
        let mut writer = writer(true);
        let old = vec![0u8; 1024 * 1024];
        for _ in 0..6 {
            writer.write_packet(0, &old).unwrap();
        }
        writer.invalidate();
        let chunk = vec![0u8; 20 * 1024 * 1024];
        for _ in 0..3 {
            assert_eq!(
                writer.write_packet(0, &chunk).unwrap(),
                WriterOutcome::BufferedOnly
            );
        }
        let before = writer.recover(0).unwrap().len();
        assert!(before > 3);
        let sequence = writer.sequence();
        writer.revive();
        assert!(writer.recover(0).is_err());
        assert_eq!(writer.recover(sequence - 3).unwrap().len(), 3);
        assert!(matches!(
            writer.write_packet(0, b"y").unwrap(),
            WriterOutcome::Send(_)
        ));
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
