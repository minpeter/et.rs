//! HTM message framing, mirroring `SocketHandler::writeB64`/`readB64` and the
//! per-message layouts in upstream `HtmServer.cpp` / `MultiplexerState.cpp`.
//!
//! Every message is `header : u8`, then the length as base64 of a native
//! little-endian `int32` (8 bytes on the wire), then a payload whose layout
//! depends on the header. Some payload fields are raw bytes (UUIDs, JSON,
//! debug keys) and some are base64 (terminal data), exactly as upstream.

use std::io::{self, Read, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Encoded size of `count` raw bytes in padded base64, matching
/// `Base64::EncodedLength`.
pub fn encoded_length(count: usize) -> usize {
    count.div_ceil(3) * 4
}

pub fn encode(bytes: &[u8]) -> Vec<u8> {
    STANDARD.encode(bytes).into_bytes()
}

pub fn decode(bytes: &[u8]) -> io::Result<Vec<u8>> {
    STANDARD
        .decode(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "b64 decode failed"))
}

/// Write the base64-encoded little-endian length field.
pub fn write_length(writer: &mut impl Write, length: i32) -> io::Result<()> {
    writer.write_all(&encode(&length.to_le_bytes()))
}

/// Read the base64-encoded little-endian length field.
pub fn read_length(reader: &mut impl Read) -> io::Result<i32> {
    let mut encoded = [0u8; 8];
    reader.read_exact(&mut encoded)?;
    let raw = decode(&encoded)?;
    let bytes: [u8; 4] = raw
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid length field"))?;
    Ok(i32::from_le_bytes(bytes))
}

pub fn read_exact_vec(reader: &mut impl Read, length: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Read a UUID-shaped raw field.
pub fn read_uuid(reader: &mut impl Read) -> io::Result<String> {
    let raw = read_exact_vec(reader, super::codes::UUID_LENGTH)?;
    String::from_utf8(raw).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid uuid"))
}

/// `APPEND_TO_PANE`: raw pane id followed by base64 terminal data.
pub fn write_append_to_pane(writer: &mut impl Write, pane_id: &str, data: &[u8]) -> io::Result<()> {
    let length = encoded_length(data.len()) + pane_id.len();
    writer.write_all(&[super::codes::APPEND_TO_PANE])?;
    write_length(writer, i32::try_from(length).unwrap_or(i32::MAX))?;
    writer.write_all(pane_id.as_bytes())?;
    writer.write_all(&encode(data))?;
    writer.flush()
}

/// `SERVER_CLOSE_PANE`: raw pane id.
pub fn write_close_pane(writer: &mut impl Write, pane_id: &str) -> io::Result<()> {
    writer.write_all(&[super::codes::SERVER_CLOSE_PANE])?;
    write_length(writer, i32::try_from(pane_id.len()).unwrap_or(i32::MAX))?;
    writer.write_all(pane_id.as_bytes())?;
    writer.flush()
}

/// `INIT_STATE`: raw JSON payload (not base64), like upstream.
pub fn write_init_state(writer: &mut impl Write, json: &str) -> io::Result<()> {
    writer.write_all(&[super::codes::INIT_STATE])?;
    write_length(writer, i32::try_from(json.len()).unwrap_or(i32::MAX))?;
    writer.write_all(json.as_bytes())?;
    writer.flush()
}

/// `DEBUG_LOG`: base64 message, length is the *encoded* length.
pub fn write_debug(writer: &mut impl Write, message: &str) -> io::Result<()> {
    let length = encoded_length(message.len());
    writer.write_all(&[super::codes::DEBUG_LOG])?;
    write_length(writer, i32::try_from(length).unwrap_or(i32::MAX))?;
    writer.write_all(&encode(message.as_bytes()))?;
    writer.flush()
}

/// `INSERT_KEYS`: raw pane id followed by base64 keystrokes.
pub fn write_insert_keys(writer: &mut impl Write, pane_id: &str, data: &[u8]) -> io::Result<()> {
    let length = encoded_length(data.len()) + pane_id.len();
    writer.write_all(&[super::codes::INSERT_KEYS])?;
    write_length(writer, i32::try_from(length).unwrap_or(i32::MAX))?;
    writer.write_all(pane_id.as_bytes())?;
    writer.write_all(&encode(data))?;
    writer.flush()
}

/// `NEW_TAB`: raw tab id followed by raw pane id.
pub fn write_new_tab(writer: &mut impl Write, tab_id: &str, pane_id: &str) -> io::Result<()> {
    writer.write_all(&[super::codes::NEW_TAB])?;
    write_length(
        writer,
        i32::try_from(tab_id.len() + pane_id.len()).unwrap_or(i32::MAX),
    )?;
    writer.write_all(tab_id.as_bytes())?;
    writer.write_all(pane_id.as_bytes())?;
    writer.flush()
}

/// `NEW_SPLIT`: raw source id, raw new pane id, then `'1'`/`'0'` orientation.
pub fn write_new_split(
    writer: &mut impl Write,
    source_id: &str,
    pane_id: &str,
    vertical: bool,
) -> io::Result<()> {
    writer.write_all(&[super::codes::NEW_SPLIT])?;
    write_length(
        writer,
        i32::try_from(source_id.len() + pane_id.len() + 1).unwrap_or(i32::MAX),
    )?;
    writer.write_all(source_id.as_bytes())?;
    writer.write_all(pane_id.as_bytes())?;
    writer.write_all(&[if vertical { b'1' } else { b'0' }])?;
    writer.flush()
}

/// `RESIZE_PANE`: base64 cols, base64 rows, raw pane id.
pub fn write_resize_pane(
    writer: &mut impl Write,
    pane_id: &str,
    cols: i32,
    rows: i32,
) -> io::Result<()> {
    writer.write_all(&[super::codes::RESIZE_PANE])?;
    write_length(
        writer,
        i32::try_from(16 + pane_id.len()).unwrap_or(i32::MAX),
    )?;
    write_length(writer, cols)?;
    write_length(writer, rows)?;
    writer.write_all(pane_id.as_bytes())?;
    writer.flush()
}

/// `CLIENT_CLOSE_PANE`: raw pane id.
pub fn write_client_close_pane(writer: &mut impl Write, pane_id: &str) -> io::Result<()> {
    writer.write_all(&[super::codes::CLIENT_CLOSE_PANE])?;
    write_length(writer, i32::try_from(pane_id.len()).unwrap_or(i32::MAX))?;
    writer.write_all(pane_id.as_bytes())?;
    writer.flush()
}

/// `INSERT_DEBUG_KEYS`: raw key bytes.
pub fn write_debug_keys(writer: &mut impl Write, keys: &[u8]) -> io::Result<()> {
    writer.write_all(&[super::codes::INSERT_DEBUG_KEYS])?;
    write_length(writer, i32::try_from(keys.len()).unwrap_or(i32::MAX))?;
    writer.write_all(keys)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_length_matches_padded_base64() {
        for (raw, encoded) in [(0, 0), (1, 4), (2, 4), (3, 4), (4, 8), (6, 8), (7, 12)] {
            assert_eq!(encoded_length(raw), encoded);
            assert_eq!(encode(&vec![0u8; raw]).len(), encoded);
        }
    }

    #[test]
    fn length_field_is_base64_little_endian_int32() {
        let mut buffer = Vec::new();
        write_length(&mut buffer, 300).unwrap();
        assert_eq!(buffer.len(), 8);
        assert_eq!(read_length(&mut buffer.as_slice()).unwrap(), 300);
        // Little-endian: 300 == 0x0000012C
        assert_eq!(decode(&buffer).unwrap(), vec![0x2c, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn append_to_pane_layout_matches_upstream() {
        let pane = "a".repeat(super::super::codes::UUID_LENGTH);
        let mut buffer = Vec::new();
        write_append_to_pane(&mut buffer, &pane, b"hello").unwrap();
        assert_eq!(buffer[0], super::super::codes::APPEND_TO_PANE);
        let mut cursor = &buffer[1..];
        let length = read_length(&mut cursor).unwrap() as usize;
        assert_eq!(length, encoded_length(5) + pane.len());
        let id = read_uuid(&mut cursor).unwrap();
        assert_eq!(id, pane);
        let payload_len = length - pane.len();
        let payload = read_exact_vec(&mut cursor, payload_len).unwrap();
        assert_eq!(decode(&payload).unwrap(), b"hello");
    }

    #[test]
    fn init_state_payload_is_raw_json() {
        let mut buffer = Vec::new();
        write_init_state(&mut buffer, "{\"a\":1}").unwrap();
        let mut cursor = &buffer[1..];
        let length = read_length(&mut cursor).unwrap() as usize;
        assert_eq!(length, 7);
        assert_eq!(read_exact_vec(&mut cursor, length).unwrap(), b"{\"a\":1}");
    }

    #[test]
    fn resize_pane_carries_two_encoded_dimensions() {
        let pane = "b".repeat(super::super::codes::UUID_LENGTH);
        let mut buffer = Vec::new();
        write_resize_pane(&mut buffer, &pane, 120, 40).unwrap();
        let mut cursor = &buffer[1..];
        let length = read_length(&mut cursor).unwrap() as usize;
        assert_eq!(length, 16 + pane.len());
        assert_eq!(read_length(&mut cursor).unwrap(), 120);
        assert_eq!(read_length(&mut cursor).unwrap(), 40);
        assert_eq!(read_uuid(&mut cursor).unwrap(), pane);
    }
}
