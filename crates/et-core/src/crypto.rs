//! `crypto_secretbox` (XSalsa20-Poly1305) with the EternalTerminal nonce
//! scheme: a 24-byte counter whose most significant byte (index 23) is the
//! stream-direction discriminator (0 = client→server, 1 = server→client).
//! The counter increments, little-endian with carry, *before* each call.
//!
//! This is the highest-risk interop point; parity is pinned by
//! `fixtures/wire.json` (generated from upstream `CryptoHandler.cpp`).

use xsalsa20poly1305::aead::{Aead, KeyInit};
use xsalsa20poly1305::{Nonce, XSalsa20Poly1305};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;

pub const DIR_CLIENT_TO_SERVER: u8 = 0;
pub const DIR_SERVER_TO_CLIENT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    Short,
    BadMac,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "ciphertext shorter than the 16-byte tag"),
            Self::BadMac => write!(f, "poly1305 verification failed"),
        }
    }
}

impl std::error::Error for DecryptError {}

#[derive(Clone)]
pub struct CryptoHandler {
    cipher: XSalsa20Poly1305,
    nonce: [u8; NONCE_LEN],
}

impl CryptoHandler {
    pub fn new(key: &[u8; KEY_LEN], direction: u8) -> Self {
        let cipher = XSalsa20Poly1305::new(key.into());
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = direction;
        Self { cipher, nonce }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.bump();
        self.cipher
            .encrypt(Nonce::from_slice(&self.nonce), plaintext)
            .expect("xsalsa20poly1305 encrypt is infallible for a 24-byte nonce")
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() < MAC_LEN {
            return Err(DecryptError::Short);
        }
        self.bump();
        self.cipher
            .decrypt(Nonce::from_slice(&self.nonce), ciphertext)
            .map_err(|_| DecryptError::BadMac)
    }

    fn bump(&mut self) {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_both_directions() {
        let key = [0x42u8; KEY_LEN];
        let pt = b"the quick brown fox";
        let mut enc = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        assert_eq!(dec.decrypt(&enc.encrypt(pt)).unwrap(), pt);
        assert_eq!(dec.decrypt(&enc.encrypt(b"")).unwrap(), b"");
        assert_eq!(dec.decrypt(&enc.encrypt(pt)).unwrap(), pt);
    }

    #[test]
    fn wrong_direction_does_not_roundtrip() {
        let key = [7u8; KEY_LEN];
        let mut enc = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec = CryptoHandler::new(&key, DIR_SERVER_TO_CLIENT);
        let ct = enc.encrypt(b"x");
        assert_eq!(dec.decrypt(&ct), Err(DecryptError::BadMac));
    }

    #[test]
    fn nonce_advances_every_call() {
        let key = [1u8; KEY_LEN];
        let mut h = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let a = h.encrypt(b"x");
        let b = h.encrypt(b"x");
        let c = h.encrypt(b"x");
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
