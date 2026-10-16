//! `crypto_secretbox` (XSalsa20-Poly1305) with the EternalTerminal nonce
//! scheme: a 24-byte counter whose most significant byte (index 23) is the
//! stream-direction discriminator (0 = client→server, 1 = server→client).
//! The counter increments, little-endian with carry, *before* each call.
//!
//! This is the highest-risk interop point; parity is pinned by
//! `fixtures/wire.json` (generated from upstream `CryptoHandler.cpp`).

use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;
/// libsodium `crypto_generichash_BYTES` / `CryptoHandler::AUTH_CHALLENGE_BYTES`.
pub const AUTH_CHALLENGE_BYTES: usize = 32;
/// libsodium keyed BLAKE2b output and `CryptoHandler::EPOCH_SALT_BYTES`.
pub const EPOCH_SALT_BYTES: usize = 32;
pub const PROOF_BYTES: usize = 32;

pub const DIR_CLIENT_TO_SERVER: u8 = 0;
pub const DIR_SERVER_TO_CLIENT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    Short,
    BadMac,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptError;

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plaintext exceeds the cipher message limit")
    }
}

impl std::error::Error for EncryptError {}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "ciphertext shorter than the 16-byte tag"),
            Self::BadMac => write!(f, "poly1305 verification failed"),
        }
    }
}

impl std::error::Error for DecryptError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError;

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connection proof is invalid")
    }
}

impl std::error::Error for ProofError {}

/// Keyed BLAKE2b-256, matching libsodium `crypto_generichash`.
pub fn generichash(key: &[u8], message: &[u8]) -> Result<[u8; PROOF_BYTES], ProofError> {
    let mut mac = <Blake2bMac<U32> as blake2::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| ProofError)?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; PROOF_BYTES];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
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

pub fn connection_proof(
    key: &[u8; KEY_LEN],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent: bool,
) -> Result<[u8; PROOF_BYTES], ProofError> {
    if challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(ProofError);
    }
    generichash(
        key,
        &connection_proof_message(client_id, protocol_version, challenge, reset_intent),
    )
}

pub fn verify_connection_proof(
    proof: &[u8],
    key: &[u8; KEY_LEN],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent: bool,
) -> bool {
    if proof.len() != PROOF_BYTES || challenge.len() != AUTH_CHALLENGE_BYTES {
        return false;
    }
    let Ok(expected) = connection_proof(key, client_id, protocol_version, challenge, reset_intent)
    else {
        return false;
    };
    constant_time_eq(proof, &expected)
}

pub fn reset_decision_proof(
    key: &[u8; KEY_LEN],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    status: i32,
    reset_required: bool,
    reset_salt: &[u8],
) -> Result<[u8; PROOF_BYTES], ProofError> {
    if challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(ProofError);
    }
    if reset_required && reset_salt.len() != EPOCH_SALT_BYTES {
        return Err(ProofError);
    }
    if !reset_required && !reset_salt.is_empty() {
        return Err(ProofError);
    }
    generichash(
        key,
        &reset_decision_message(
            client_id,
            protocol_version,
            challenge,
            status,
            reset_required,
            reset_salt,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_reset_decision_proof(
    proof: &[u8],
    key: &[u8; KEY_LEN],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    status: i32,
    reset_required: bool,
    reset_salt: &[u8],
) -> bool {
    if proof.len() != PROOF_BYTES || challenge.len() != AUTH_CHALLENGE_BYTES {
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
    constant_time_eq(proof, &expected)
}

#[derive(Clone)]
pub struct CryptoHandler {
    /// The passkey-derived key every reset derives from. Never overwritten:
    /// a fresh client process only knows the passkey, so the server's Nth
    /// reset must derive from the original key, not from the previous epoch.
    original_key: [u8; KEY_LEN],
    base_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    direction: u8,
}

impl CryptoHandler {
    pub fn new(key: &[u8; KEY_LEN], direction: u8) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = direction;
        Self {
            original_key: *key,
            base_key: *key,
            nonce,
            direction,
        }
    }

    /// Derive a new epoch key from the original key and reset the nonce.
    pub fn rekey(&mut self, salt: &[u8]) -> Result<(), ProofError> {
        if salt.len() != EPOCH_SALT_BYTES {
            return Err(ProofError);
        }
        let derived = generichash(&self.original_key, salt)?;
        self.base_key = derived;
        self.nonce = [0u8; NONCE_LEN];
        self.nonce[NONCE_LEN - 1] = self.direction;
        Ok(())
    }

    pub fn encrypt_into(
        &mut self,
        out: &mut [u8],
        plaintext: &[u8],
    ) -> Result<usize, EncryptError> {
        if out.len() < plaintext.len() + MAC_LEN {
            return Err(EncryptError);
        }
        self.bump();
        Ok(et_sodium::secretbox_into(
            out,
            plaintext,
            &self.nonce,
            &self.base_key,
        ))
    }

    pub fn decrypt_into(&mut self, out: &mut [u8], ciphertext: &[u8]) -> Option<usize> {
        if ciphertext.len() < MAC_LEN || out.len() < ciphertext.len() - MAC_LEN {
            return None;
        }
        let saved = self.nonce;
        self.bump();
        match et_sodium::secretbox_open_into(out, ciphertext, &self.nonce, &self.base_key) {
            Some(len) => Some(len),
            None => {
                self.nonce = saved;
                None
            }
        }
    }

    pub fn decrypt_in_place(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if buffer.len() < MAC_LEN {
            return None;
        }
        let saved = self.nonce;
        self.bump();
        match et_sodium::secretbox_open_in_place(buffer, &self.nonce, &self.base_key) {
            Some(len) => Some(len),
            None => {
                self.nonce = saved;
                None
            }
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut out = vec![0u8; plaintext.len() + MAC_LEN];
        self.encrypt_into(&mut out, plaintext)
            .map_err(|_| EncryptError)?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() < MAC_LEN {
            return Err(DecryptError::Short);
        }
        let mut out = vec![0u8; ciphertext.len() - MAC_LEN];
        match self.decrypt_into(&mut out, ciphertext) {
            Some(len) => {
                debug_assert_eq!(len, out.len());
                Ok(out)
            }
            None => Err(DecryptError::BadMac),
        }
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
        assert_eq!(dec.decrypt(&enc.encrypt(pt).unwrap()).unwrap(), pt);
        assert_eq!(dec.decrypt(&enc.encrypt(b"").unwrap()).unwrap(), b"");
        assert_eq!(dec.decrypt(&enc.encrypt(pt).unwrap()).unwrap(), pt);
    }

    #[test]
    fn into_and_in_place_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let pt = b"the quick brown fox";
        let mut enc = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);

        // encrypt_into with too small buffer fails without bumping nonce
        let mut small = [0u8; 10];
        assert!(enc.encrypt_into(&mut small, pt).is_err());

        // encrypt_into and decrypt_into
        let mut ct = vec![0u8; pt.len() + MAC_LEN];
        assert!(enc.encrypt_into(&mut ct, pt).is_ok());
        let mut recovered = vec![0u8; pt.len()];
        assert_eq!(dec.decrypt_into(&mut recovered, &ct), Some(pt.len()));
        assert_eq!(&recovered, pt);

        // decrypt_into with too small buffer returns None without consuming nonce
        let mut small_out = [0u8; 5];
        assert_eq!(dec.decrypt_into(&mut small_out, &ct), None);

        // decrypt_in_place
        let mut enc2 = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec2 = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut in_place_buf = vec![0u8; pt.len() + MAC_LEN];
        assert!(enc2.encrypt_into(&mut in_place_buf, pt).is_ok());
        assert_eq!(dec2.decrypt_in_place(&mut in_place_buf), Some(pt.len()));
        assert_eq!(&in_place_buf[..pt.len()], pt);
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
    fn rejected_ciphertext_does_not_advance_the_nonce() {
        let key = [9u8; KEY_LEN];
        let mut enc = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let mut dec = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let good = enc.encrypt(b"hello").unwrap();
        let mut tampered = good.clone();
        tampered[0] ^= 0xff;
        assert_eq!(dec.decrypt(&tampered), Err(DecryptError::BadMac));
        assert_eq!(dec.decrypt(&good).unwrap(), b"hello");
        assert_eq!(dec.decrypt(&[0u8; MAC_LEN - 1]), Err(DecryptError::Short));
        assert_eq!(
            dec.decrypt(&enc.encrypt(b"next").unwrap()).unwrap(),
            b"next"
        );
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

    #[test]
    fn connection_proof_matches_libsodium_blake2b() {
        // hashlib.blake2b(..., digest_size=32) / libsodium crypto_generichash.
        let key = [0x11u8; KEY_LEN];
        let challenge = [0x22u8; AUTH_CHALLENGE_BYTES];
        let proof = connection_proof(&key, "client-id", 6, &challenge, false).unwrap();
        assert_eq!(
            proof,
            [
                0x4a, 0x27, 0xc7, 0xb8, 0x3c, 0x68, 0x61, 0x2c, 0xc6, 0xc6, 0x2d, 0x5d, 0xac, 0x1c,
                0x00, 0xde, 0xb4, 0x1f, 0xe1, 0xe2, 0xf2, 0x01, 0x7f, 0x42, 0xb5, 0xbd, 0xdb, 0x8d,
                0xda, 0x62, 0x25, 0xaa,
            ]
        );
        let derived = generichash(&[0x66; KEY_LEN], &[0x77; EPOCH_SALT_BYTES]).unwrap();
        assert_eq!(
            derived,
            [
                0x1a, 0xad, 0x8d, 0x08, 0xcf, 0x2e, 0xcb, 0x6c, 0x81, 0x90, 0x29, 0xc6, 0x5b, 0x9f,
                0xa2, 0x8c, 0xe1, 0xf1, 0x56, 0x2e, 0xd1, 0x4c, 0x2d, 0x80, 0x8f, 0xb0, 0x41, 0xfb,
                0x9e, 0xe8, 0xd1, 0xfe,
            ]
        );
    }

    #[test]
    fn connection_proof_binds_challenge_and_reset_intent() {
        let key = [0x11u8; KEY_LEN];
        let challenge = [0x22u8; AUTH_CHALLENGE_BYTES];
        let proof = connection_proof(&key, "client-id", 6, &challenge, false).unwrap();
        assert!(verify_connection_proof(
            &proof,
            &key,
            "client-id",
            6,
            &challenge,
            false
        ));
        assert!(!verify_connection_proof(
            &proof,
            &key,
            "client-id",
            6,
            &challenge,
            true
        ));
        assert!(!verify_connection_proof(
            &proof, &key, "other", 6, &challenge, false
        ));
        assert!(connection_proof(&key, "client-id", 6, &[0; 16], false).is_err());
    }

    #[test]
    fn reset_decision_rejects_a_salt_that_does_not_match_the_flag() {
        let key = [0x33u8; KEY_LEN];
        let challenge = [0x44u8; AUTH_CHALLENGE_BYTES];
        let salt = [0x55u8; EPOCH_SALT_BYTES];
        let proof = reset_decision_proof(&key, "id", 6, &challenge, 2, true, &salt).unwrap();
        assert!(verify_reset_decision_proof(
            &proof, &key, "id", 6, &challenge, 2, true, &salt
        ));
        assert!(!verify_reset_decision_proof(
            &proof, &key, "id", 6, &challenge, 1, true, &salt
        ));
        assert!(reset_decision_proof(&key, "id", 6, &challenge, 1, false, &salt).is_err());
        assert!(reset_decision_proof(&key, "id", 6, &challenge, 2, true, &[]).is_err());
    }

    #[test]
    fn rekey_restarts_the_nonce_from_the_original_key() {
        let key = [0x66u8; KEY_LEN];
        let salt = [0x77u8; EPOCH_SALT_BYTES];
        let mut handler = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        let before = handler.encrypt(b"x").unwrap();
        handler.rekey(&salt).unwrap();
        let after = handler.encrypt(b"x").unwrap();
        assert_ne!(before, after);
        let mut peer = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        peer.rekey(&salt).unwrap();
        assert_eq!(peer.decrypt(&after).unwrap(), b"x");
    }

    #[test]
    fn repeated_rekeys_still_derive_from_the_original_key() {
        // A fresh client process only knows the passkey: the server's Nth
        // reset must match a peer that rekeys once from the original key.
        let key = [0x42u8; KEY_LEN];
        let first_salt = [0x11u8; EPOCH_SALT_BYTES];
        let second_salt = [0x22u8; EPOCH_SALT_BYTES];
        let mut handler = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        handler.rekey(&first_salt).unwrap();
        let _ = handler.encrypt(b"epoch one").unwrap();
        handler.rekey(&second_salt).unwrap();
        let epoch_two = handler.encrypt(b"epoch two").unwrap();

        let mut fresh = CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER);
        fresh.rekey(&second_salt).unwrap();
        assert_eq!(fresh.decrypt(&epoch_two).unwrap(), b"epoch two");
    }
}
