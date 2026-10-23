//! Delivery acknowledgements piggybacked on keep-alive packets.
//!
//! Upstream keep-alives carry an empty payload and every implementation
//! (upstream C++ `TerminalServer`/`TerminalClient` and released et.rs)
//! ignores the payload on receipt, so an et.rs peer can attach its reader
//! sequence number without breaking interop. A receiver that understands the
//! payload uses it to trim its replay backup down to the unacknowledged tail
//! (see [`crate::backed_writer::BackedWriter::acknowledge`]); every other
//! receiver keeps behaving as if the payload were empty.
//!
//! The payload is exactly 8 big-endian bytes so it can never be confused
//! with the legacy empty payload, and any other length is ignored. Only
//! keep-alives whose acknowledgement tells the peer something new carry it
//! (see [`AckSchedule`]); the rest keep upstream's empty payload.

use crate::backed_writer::ACK_RETAIN_FLOOR_PACKETS;

/// Wire length of an acknowledgement payload.
pub const ACK_PAYLOAD_LEN: usize = 8;

/// Payload bytes a client reads or writes before it sends an acknowledging
/// keep-alive outside the idle interval. Each side's replay backup then holds
/// roughly this much acknowledged-but-untrimmed data plus what is genuinely in
/// flight, instead of the whole connected cap. The server's echo carries its
/// own acknowledgement, so one client keep-alive trims both directions.
pub const ACK_INTERVAL_BYTES: usize = 512 * 1024;

/// Encode a reader sequence number as a keep-alive acknowledgement payload.
pub fn encode_ack(sequence: i64) -> [u8; ACK_PAYLOAD_LEN] {
    // Sequences are non-negative; clamp defensively so the wire value can
    // always be decoded back into an i64.
    sequence.max(0).to_be_bytes()
}

/// Decode a keep-alive payload into an acknowledged sequence number.
///
/// Returns `None` for the legacy empty payload, any other length, and
/// values outside the non-negative `i64` range.
pub fn decode_ack(payload: &[u8]) -> Option<i64> {
    let bytes: [u8; ACK_PAYLOAD_LEN] = payload.try_into().ok()?;
    let value = i64::from_be_bytes(bytes);
    (value >= 0).then_some(value)
}

/// The payload bytes of an optional acknowledgement: empty when `None`.
pub fn ack_bytes(ack: &Option<[u8; ACK_PAYLOAD_LEN]>) -> &[u8] {
    ack.as_ref().map_or(&[], |ack| ack.as_slice())
}

/// Which end of the keep-alive exchange a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckSide {
    /// Sends keep-alives (client, jump terminal). Its first keep-alive on
    /// each connection carries the acknowledgement even before the peer has
    /// acknowledged anything: that is how an et.rs server learns that its
    /// client acknowledges.
    Initiator,
    /// Echoes keep-alives (server). It attaches acknowledgements only once
    /// the peer has acknowledged, so an upstream C++ client keeps receiving
    /// upstream's empty keep-alives.
    Responder,
}

/// Decides which keep-alives carry the delivery acknowledgement.
///
/// Keep-alives are sequenced packets, so every one read moves the reader
/// sequence and a payload on each of them would always look new. The
/// acknowledgement goes out only when it carries information:
///
/// - on the first keep-alive of a connection (for an [`AckSide::Initiator`]
///   even before the peer acknowledged, see there);
/// - when it covers a packet that was not a keep-alive;
/// - when it advanced by at least [`ACK_RETAIN_FLOOR_PACKETS`] keep-alives,
///   so the peer's replay backup still trims during a long idle stretch;
/// - on a volume acknowledgement ([`ACK_INTERVAL_BYTES`]).
///
/// After the first keep-alive, nothing is attached for a peer that has never
/// acknowledged: legacy peers ignore the payload anyway.
#[derive(Clone, Copy, Debug, Default)]
pub struct AckSchedule {
    /// Reader sequence carried by the latest attached acknowledgement on this
    /// connection, `None` before the first one.
    attached: Option<i64>,
}

impl AckSchedule {
    /// The acknowledgement for the next keep-alive, or `None` to send the
    /// legacy empty payload.
    ///
    /// `sequence` and `data_sequence` are the reader's
    /// [`crate::backed_reader::BackedReader::sequence`] and
    /// [`crate::backed_reader::BackedReader::data_sequence`];
    /// `peer_acknowledges` is whether the peer has acknowledged this side's
    /// writer at least once.
    pub fn next(
        &mut self,
        side: AckSide,
        sequence: i64,
        data_sequence: i64,
        peer_acknowledges: bool,
        volume: bool,
    ) -> Option<[u8; ACK_PAYLOAD_LEN]> {
        let attach = match self.attached {
            None => peer_acknowledges || side == AckSide::Initiator,
            Some(attached) => {
                peer_acknowledges
                    && (volume
                        || data_sequence > attached
                        || sequence - attached >= ACK_RETAIN_FLOOR_PACKETS as i64)
            }
        };
        attach.then(|| {
            self.attached = Some(sequence);
            encode_ack(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for sequence in [0, 1, 42, i64::MAX] {
            assert_eq!(decode_ack(&encode_ack(sequence)), Some(sequence));
        }
    }

    #[test]
    fn legacy_empty_payload_is_ignored() {
        assert_eq!(decode_ack(&[]), None);
    }

    #[test]
    fn wrong_lengths_are_ignored() {
        assert_eq!(decode_ack(&[0; 7]), None);
        assert_eq!(decode_ack(&[0; 9]), None);
    }

    #[test]
    fn negative_values_are_rejected() {
        assert_eq!(decode_ack(&i64::MIN.to_be_bytes()), None);
        assert_eq!(decode_ack(&(-1i64).to_be_bytes()), None);
    }

    #[test]
    fn negative_sequences_encode_as_zero() {
        assert_eq!(decode_ack(&encode_ack(-5)), Some(0));
    }

    #[test]
    fn initiator_announces_then_attaches_only_news() {
        let mut acks = AckSchedule::default();
        // The first keep-alive tells an et.rs server its client acknowledges.
        assert_eq!(
            acks.next(AckSide::Initiator, 3, 3, false, false),
            Some(encode_ack(3))
        );
        // Only keep-alives were read since: nothing new to say.
        assert_eq!(acks.next(AckSide::Initiator, 4, 3, true, false), None);
        // Terminal output was read.
        assert_eq!(
            acks.next(AckSide::Initiator, 6, 5, true, false),
            Some(encode_ack(6))
        );
        assert_eq!(acks.next(AckSide::Initiator, 7, 5, true, false), None);
        // A volume acknowledgement always carries the sequence.
        assert_eq!(
            acks.next(AckSide::Initiator, 7, 5, true, true),
            Some(encode_ack(7))
        );
    }

    #[test]
    fn idle_acknowledgements_advance_every_retain_floor() {
        let mut acks = AckSchedule::default();
        assert!(acks.next(AckSide::Initiator, 0, 0, false, false).is_some());
        let floor = ACK_RETAIN_FLOOR_PACKETS as i64;
        for sequence in 1..floor {
            assert_eq!(
                acks.next(AckSide::Initiator, sequence, 0, true, false),
                None
            );
        }
        assert_eq!(
            acks.next(AckSide::Initiator, floor, 0, true, false),
            Some(encode_ack(floor))
        );
        assert_eq!(
            acks.next(AckSide::Initiator, floor + 1, 0, true, false),
            None
        );
    }

    #[test]
    fn legacy_peers_get_empty_keepalives() {
        // An upstream C++ server never acknowledges: after the announcement
        // the client sends upstream's empty payload, even for data or volume.
        let mut client = AckSchedule::default();
        assert!(client
            .next(AckSide::Initiator, 0, 0, false, false)
            .is_some());
        assert_eq!(client.next(AckSide::Initiator, 40, 40, false, true), None);
        // An upstream C++ client never acknowledges, so the server's echoes
        // stay empty from the start.
        let mut server = AckSchedule::default();
        assert_eq!(server.next(AckSide::Responder, 1, 0, false, false), None);
        assert_eq!(server.next(AckSide::Responder, 40, 40, false, true), None);
        // Once the client acknowledged, the first echo carries the sequence.
        assert_eq!(
            server.next(AckSide::Responder, 41, 40, true, false),
            Some(encode_ack(41))
        );
    }

    #[test]
    fn a_new_connection_announces_again() {
        let mut acks = AckSchedule::default();
        assert!(acks.next(AckSide::Initiator, 5, 5, true, false).is_some());
        assert_eq!(acks.next(AckSide::Initiator, 6, 5, true, false), None);
        // Recovery builds a fresh schedule for the new transport.
        let mut acks = AckSchedule::default();
        assert!(acks.next(AckSide::Initiator, 6, 5, true, false).is_some());
    }

    #[test]
    fn idle_hour_of_keepalives_keeps_both_replay_backups_bounded() {
        use crate::backed_reader::{BackedReader, ReadItem};
        use crate::backed_writer::{BackedWriter, WriterOutcome, ACK_RETAIN_SLACK_PACKETS};
        use crate::crypto::{CryptoHandler, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN};
        use crate::packet::Packet;
        use crate::proto::TerminalPacketType;

        fn deliver(writer: &mut BackedWriter, reader: &mut BackedReader, ack: &[u8]) -> Packet {
            let outcome = writer
                .write_packet(TerminalPacketType::KeepAlive as u8, ack)
                .unwrap();
            let WriterOutcome::Send(frame) = outcome else {
                panic!("connected writer must send, got {outcome:?}");
            };
            reader.feed(&frame);
            match reader.pop().unwrap() {
                ReadItem::Packet(packet) => packet,
                ReadItem::NeedMore => panic!("a whole frame was fed"),
            }
        }

        let key = [3u8; KEY_LEN];
        let up = || CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let down = || CryptoHandler::new(&key, DIR_SERVER_TO_CLIENT);
        let mut client_writer = BackedWriter::new(up(), true);
        let mut server_reader = BackedReader::new(up(), true);
        let mut server_writer = BackedWriter::new(down(), true);
        let mut client_reader = BackedReader::new(down(), true);
        let mut client_acks = AckSchedule::default();
        let mut server_acks = AckSchedule::default();
        let mut attached = [0usize; 2];
        // `et --keepalive 1`: one probe and one echo per second for an hour.
        let exchanges = 3600;
        for _ in 0..exchanges {
            let ack = client_acks.next(
                AckSide::Initiator,
                client_reader.sequence(),
                client_reader.data_sequence(),
                client_writer.delivery_backlog().is_some(),
                false,
            );
            attached[0] += usize::from(ack.is_some());
            let probe = deliver(&mut client_writer, &mut server_reader, ack_bytes(&ack));
            if let Some(sequence) = decode_ack(probe.payload()) {
                server_writer.acknowledge(sequence);
            }
            let ack = server_acks.next(
                AckSide::Responder,
                server_reader.sequence(),
                server_reader.data_sequence(),
                server_writer.delivery_backlog().is_some(),
                false,
            );
            attached[1] += usize::from(ack.is_some());
            let echo = deliver(&mut server_writer, &mut client_reader, ack_bytes(&ack));
            if let Some(sequence) = decode_ack(echo.payload()) {
                client_writer.acknowledge(sequence);
            }
        }
        // Unacknowledged keep-alives plus the acknowledged slack, far below
        // the hour of keep-alives an unacknowledged backup would hold.
        let bound = ACK_RETAIN_SLACK_PACKETS + ACK_RETAIN_FLOOR_PACKETS + 1;
        assert!(bound < exchanges);
        for writer in [&client_writer, &server_writer] {
            assert!(
                writer
                    .recover(writer.sequence() - bound as i64 - 1)
                    .is_err(),
                "replay backup grew past {bound} keep-alives"
            );
        }
        for count in attached {
            assert!(count <= exchanges / ACK_RETAIN_FLOOR_PACKETS + 1, "{count}");
        }
    }
}
