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
