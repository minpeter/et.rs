//! `crypto_secretbox` (XSalsa20-Poly1305) with the EternalTerminal nonce
//! scheme: a 24-byte counter whose most significant byte (index 23) is the
//! stream-direction discriminator (0 = client→server, 1 = server→client).
//! The counter increments, little-endian with carry, *before* each call.
//!
//! This is the highest-risk interop point; parity is pinned by
//! `fixtures/wire.json` (generated from upstream `CryptoHandler.cpp`).

use blake2::digest::consts::U32;
use blake2::digest::{KeyInit as BlakeKeyInit, Mac};
use blake2::Blake2bMac;
use crypto_secretbox::aead::Aead;
use crypto_secretbox::{Nonce, XSalsa20Poly1305};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;
/// libsodium `crypto_generichash_BYTES` (BLAKE2b-256).
pub const GENERICHASH_BYTES: usize = 32;
/// Fresh `ConnectResponse.authChallenge` length (`CryptoHandler::AUTH_CHALLENGE_BYTES`).
pub const AUTH_CHALLENGE_BYTES: usize = 32;
/// `ConnectResponse.resetSalt` / epoch rekey salt (`CryptoHandler::EPOCH_SALT_BYTES`).
pub const EPOCH_SALT_BYTES: usize = 32;

pub const DIR_CLIENT_TO_SERVER: u8 = 0;
pub const DIR_SERVER_TO_CLIENT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    Short,
    BadMac,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError;

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plaintext exceeds the cipher message limit")
    }
}

impl std::error::Error for EncryptError {}

impl std::fmt::Display for RekeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid epoch salt")
    }
}

impl std::error::Error for RekeyError {}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid connection proof inputs")
    }
}

impl std::error::Error for ProofError {}

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
    base_key: [u8; KEY_LEN],
    direction: u8,
}

impl CryptoHandler {
    pub fn new(key: &[u8; KEY_LEN], direction: u8) -> Self {
        let cipher = XSalsa20Poly1305::new(key.into());
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = direction;
        Self {
            cipher,
            nonce,
            base_key: *key,
            direction,
        }
    }

    /// Derive a new epoch key from the original key and reset the nonce.
    /// Matches upstream `CryptoHandler::rekey`.
    pub fn rekey(&mut self, salt: &[u8]) -> Result<(), RekeyError> {
        if salt.len() != EPOCH_SALT_BYTES {
            return Err(RekeyError);
        }
        let derived = keyed_blake2b(&self.base_key, salt);
        self.cipher = XSalsa20Poly1305::new((&derived).into());
        self.nonce = [0u8; NONCE_LEN];
        self.nonce[NONCE_LEN - 1] = self.direction;
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        self.bump();
        self.cipher
            .encrypt(Nonce::from_slice(&self.nonce), plaintext)
            .map_err(|_| EncryptError)
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

/// Keyed BLAKE2b-256. Matches libsodium `crypto_generichash` with a 32-byte key
/// and a 32-byte output (`crypto_generichash_BYTES`).
fn keyed_blake2b(key: &[u8], message: &[u8]) -> [u8; GENERICHASH_BYTES] {
    let mut mac = <Blake2bMac<U32> as BlakeKeyInit>::new_from_slice(key)
        .expect("blake2b accepts the 32-byte ET session key");
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; GENERICHASH_BYTES];
    out.copy_from_slice(&digest);
    out
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// `CryptoHandler::connectionProof`: keyed proof over client id, protocol
/// version, challenge, and reset intent.
pub fn connection_proof(
    key: &[u8],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent: bool,
) -> Result<Vec<u8>, ProofError> {
    if key.len() != KEY_LEN || challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(ProofError);
    }
    let message = connection_proof_message(client_id, protocol_version, challenge, reset_intent);
    Ok(keyed_blake2b(key, &message).to_vec())
}

pub fn verify_connection_proof(
    proof: &[u8],
    key: &[u8],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent: bool,
) -> bool {
    if proof.len() != GENERICHASH_BYTES
        || key.len() != KEY_LEN
        || challenge.len() != AUTH_CHALLENGE_BYTES
    {
        return false;
    }
    let Ok(expected) = connection_proof(key, client_id, protocol_version, challenge, reset_intent)
    else {
        return false;
    };
    ct_eq(proof, &expected)
}

/// `CryptoHandler::resetDecisionProof`: binds status, resetRequired, and salt
/// to this handshake's challenge.
pub fn reset_decision_proof(
    key: &[u8],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    status: i32,
    reset_required: bool,
    reset_salt: &[u8],
) -> Result<Vec<u8>, ProofError> {
    if key.len() != KEY_LEN || challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(ProofError);
    }
    if (reset_required && reset_salt.len() != EPOCH_SALT_BYTES)
        || (!reset_required && !reset_salt.is_empty())
    {
        return Err(ProofError);
    }
    let message = reset_decision_message(
        client_id,
        protocol_version,
        challenge,
        status,
        reset_required,
        reset_salt,
    );
    Ok(keyed_blake2b(key, &message).to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_reset_decision_proof(
    proof: &[u8],
    key: &[u8],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    status: i32,
    reset_required: bool,
    reset_salt: &[u8],
) -> bool {
    if proof.len() != GENERICHASH_BYTES
        || key.len() != KEY_LEN
        || challenge.len() != AUTH_CHALLENGE_BYTES
    {
        return false;
    }
    let Ok(expected) = reset_decision_proof(
        key,
        client_id,
        protocol_version,
        challenge,
        status,
        reset_required,
        reset_salt,
    ) else {
        return false;
    };
    ct_eq(proof, &expected)
}

fn connection_proof_message(
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent: bool,
) -> Vec<u8> {
    let mut message = b"EternalTerminal connect auth v2".to_vec();
    message.push(0);
    message.extend(protocol_version.to_string().into_bytes());
    message.push(0);
    message.extend(client_id.len().to_string().into_bytes());
    message.push(0);
    message.extend(client_id.as_bytes());
    message.push(0);
    message.extend(challenge.len().to_string().into_bytes());
    message.push(0);
    message.extend(challenge);
    message.push(0);
    message.push(if reset_intent { b'1' } else { b'0' });
    message
}

fn reset_decision_message(
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    status: i32,
    reset_required: bool,
    reset_salt: &[u8],
) -> Vec<u8> {
    let mut message = b"EternalTerminal reset decision v3".to_vec();
    message.push(0);
    message.extend(protocol_version.to_string().into_bytes());
    message.push(0);
    message.extend(client_id.as_bytes());
    message.push(0);
    message.extend(challenge.len().to_string().into_bytes());
    message.push(0);
    message.extend(challenge);
    message.push(0);
    message.extend(status.to_string().into_bytes());
    message.push(0);
    message.push(if reset_required { b'1' } else { b'0' });
    message.push(0);
    message.extend(reset_salt.len().to_string().into_bytes());
    message.push(0);
    message.extend(reset_salt);
    message
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
        assert_eq!(dec.decrypt(&enc.encrypt(pt).unwrap()).unwrap(), pt);
        assert_eq!(dec.decrypt(&enc.encrypt(b"").unwrap()).unwrap(), b"");
        assert_eq!(dec.decrypt(&enc.encrypt(pt).unwrap()).unwrap(), pt);
    }

    #[test]
    fn wrong_direction_does_not_roundtrip() {
        let key = [7u8; KEY_LEN];
        let mut enc = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec = CryptoHandler::new(&key, DIR_SERVER_TO_CLIENT);
        let ct = enc.encrypt(b"x").unwrap();
        assert_eq!(dec.decrypt(&ct), Err(DecryptError::BadMac));
    }

    #[test]
    fn keyed_blake2b_matches_python_hashlib_and_libsodium_generichash() {
        // hashlib.blake2b(b"hello", key=bytes([7])*32, digest_size=32)
        // matches libsodium crypto_generichash with a 32-byte key and no
        // salt or personalization.
        let digest = keyed_blake2b(&[7u8; KEY_LEN], b"hello");
        assert_eq!(
            digest,
            [
                0x42, 0x30, 0xb2, 0x62, 0x45, 0x42, 0x8e, 0xb3, 0x15, 0xa0, 0x6d, 0x69, 0x32, 0x22,
                0xbc, 0x0d, 0xfd, 0xcf, 0x3c, 0x29, 0x0f, 0x6b, 0xba, 0xc2, 0x48, 0xb3, 0x6c, 0x28,
                0xee, 0xcb, 0x85, 0xa1,
            ]
        );
    }

    #[test]
    fn connection_proof_rejects_a_flipped_reset_intent() {
        let key = [9u8; KEY_LEN];
        let challenge = [3u8; AUTH_CHALLENGE_BYTES];
        let proof = connection_proof(&key, "client-id-16byte", 6, &challenge, true).unwrap();
        assert!(verify_connection_proof(
            &proof,
            &key,
            "client-id-16byte",
            6,
            &challenge,
            true
        ));
        assert!(!verify_connection_proof(
            &proof,
            &key,
            "client-id-16byte",
            6,
            &challenge,
            false
        ));
        assert!(!verify_connection_proof(
            &proof,
            &key,
            "other-id-16bytes",
            6,
            &challenge,
            true
        ));
    }

    #[test]
    fn reset_decision_proof_binds_salt_and_status() {
        let key = [4u8; KEY_LEN];
        let challenge = [8u8; AUTH_CHALLENGE_BYTES];
        let salt = [1u8; EPOCH_SALT_BYTES];
        let proof =
            reset_decision_proof(&key, "abcdefghijklmnop", 6, &challenge, 2, true, &salt).unwrap();
        assert!(verify_reset_decision_proof(
            &proof,
            &key,
            "abcdefghijklmnop",
            6,
            &challenge,
            2,
            true,
            &salt
        ));
        let mut other = salt;
        other[0] ^= 1;
        assert!(!verify_reset_decision_proof(
            &proof,
            &key,
            "abcdefghijklmnop",
            6,
            &challenge,
            2,
            true,
            &other
        ));
        assert!(
            reset_decision_proof(&key, "abcdefghijklmnop", 6, &challenge, 2, false, &salt).is_err()
        );
        assert!(
            reset_decision_proof(&key, "abcdefghijklmnop", 6, &challenge, 1, false, &[]).is_ok()
        );
    }

    #[test]
    fn rekey_changes_ciphertext_and_resets_the_nonce() {
        let key = [2u8; KEY_LEN];
        let salt = [5u8; EPOCH_SALT_BYTES];
        let mut original = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let first = original.encrypt(b"epoch").unwrap();
        let mut rebound = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        rebound.rekey(&salt).unwrap();
        let second = rebound.encrypt(b"epoch").unwrap();
        assert_ne!(first, second);
        let mut peer = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        peer.rekey(&salt).unwrap();
        assert_eq!(peer.decrypt(&second).unwrap(), b"epoch");
        assert!(rebound.rekey(&[0u8; 16]).is_err());
    }

    #[test]
    fn nonce_advances_every_call() {
        let key = [1u8; KEY_LEN];
        let mut h = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let a = h.encrypt(b"x").unwrap();
        let b = h.encrypt(b"x").unwrap();
        let c = h.encrypt(b"x").unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
