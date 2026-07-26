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
//! with the legacy empty payload, and any other length is ignored.

/// Wire length of an acknowledgement payload.
pub const ACK_PAYLOAD_LEN: usize = 8;

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
}
