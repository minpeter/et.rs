//! Length-encoded packet: `[encrypted_flag:1][header:1][payload]`.
//! Mirrors upstream `Packet.hpp` exactly, including the two-byte fixed header
//! used by both `BackedReader`/`BackedWriter` framing.

use crate::crypto::CryptoHandler;

pub const HEADER_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    encrypted: bool,
    header: u8,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(header: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            encrypted: false,
            header,
            payload: payload.into(),
        }
    }

    pub fn raw(encrypted: bool, header: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            encrypted,
            header,
            payload: payload.into(),
        }
    }

    pub fn from_serialized(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::Short);
        }
        Ok(Self {
            encrypted: bytes[0] != 0,
            header: bytes[1],
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }

    pub fn from_serialized_vec(mut bytes: Vec<u8>) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::Short);
        }
        let encrypted = bytes[0] != 0;
        let header = bytes[1];
        bytes.drain(..HEADER_LEN);
        Ok(Self {
            encrypted,
            header,
            payload: bytes,
        })
    }

    pub fn encrypt(
        &mut self,
        crypto: &mut CryptoHandler,
    ) -> Result<(), crate::crypto::EncryptError> {
        debug_assert!(!self.encrypted, "encrypting an already-encrypted packet");
        self.payload = crypto.encrypt(&self.payload)?;
        self.encrypted = true;
        Ok(())
    }

    pub fn decrypt(
        &mut self,
        crypto: &mut CryptoHandler,
    ) -> Result<(), crate::crypto::DecryptError> {
        if !self.encrypted {
            return Ok(());
        }
        self.payload = crypto.decrypt(&self.payload)?;
        self.encrypted = false;
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn header(&self) -> u8 {
        self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.push(self.encrypted as u8);
        out.push(self.header);
        out.extend_from_slice(&self.payload);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    Short,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "packet shorter than the 2-byte header"),
        }
    }
}

impl std::error::Error for PacketError {}

/// Zero-copy slice decoder for canonical `TerminalBuffer` payloads
/// (`tag 0x0a` length-delimited `buffer` + optional `tag 0x10` `is_stderr`).
/// Returns `None` if unknown/repeated fields or non-canonical wire tags appear,
/// allowing the caller to fall back to `prost::Message::decode`.
pub fn decode_terminal_buffer(payload: &[u8]) -> Option<(&[u8], bool)> {
    if payload.is_empty() {
        return None;
    }
    if payload[0] != 0x0a {
        return None;
    }
    let mut len: usize = 0;
    let mut shift = 0u32;
    let mut idx = 1;
    loop {
        let b = *payload.get(idx)?;
        idx += 1;
        len |= usize::from(b & 0x7f).checked_shl(shift)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    let end = idx.checked_add(len)?;
    let buf = payload.get(idx..end)?;
    match &payload[end..] {
        [] => Some((buf, false)),
        [0x10, 0] => Some((buf, false)),
        [0x10, 1] => Some((buf, true)),
        _ => None,
    }
}

/// Encode a `TerminalBuffer` protobuf payload directly from a byte slice
/// without allocating an intermediate `Vec<u8>` for `TerminalBuffer.buffer`.
pub fn encode_terminal_buffer(bytes: &[u8], is_stderr: bool) -> Vec<u8> {
    let mut len_varint = [0u8; 10];
    let mut v = bytes.len();
    let mut v_len = 0;
    while v >= 0x80 {
        len_varint[v_len] = (v as u8) | 0x80;
        v >>= 7;
        v_len += 1;
    }
    len_varint[v_len] = v as u8;
    v_len += 1;
    let stderr_len = if is_stderr { 2 } else { 0 };
    let mut out = Vec::with_capacity(1 + v_len + bytes.len() + stderr_len);
    out.push(0x0a);
    out.extend_from_slice(&len_varint[..v_len]);
    out.extend_from_slice(bytes);
    if is_stderr {
        out.push(0x10);
        out.push(0x01);
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_unencrypted() {
        let p = Packet::new(0, "hello");
        assert_eq!(p.serialize(), [0x00, 0x00, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn serialize_encrypted_flag_and_header() {
        let p = Packet {
            encrypted: true,
            header: 254,
            payload: b"k".to_vec(),
        };
        assert_eq!(p.serialize(), [0x01, 0xfe, b'k']);
    }

    #[test]
    fn roundtrip_serialize() {
        let p = Packet::new(7, vec![1, 2, 3]);
        let s = p.serialize();
        let q = Packet::from_serialized(&s).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn rejects_short() {
        assert_eq!(
            Packet::from_serialized(&[0x00]).unwrap_err(),
            PacketError::Short
        );
    }
}
