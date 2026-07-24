//! Credential generation and derivation. The EternalTerminal passkey is a
//! 32-character alphanumeric string whose raw ASCII bytes ARE the 32-byte
//! `crypto_secretbox` key (upstream does no hashing), so this module mirrors
//! [`genRandomAlphaNum`](Headers.hpp) and the `id/passkey` format exactly.

use rand::Rng;

const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ID_LEN: usize = 16;
const PASSKEY_LEN: usize = 32;

pub fn gen_id_passkey() -> (String, String) {
    let mut rng = rand::thread_rng();
    let id: String = (0..ID_LEN)
        .map(|_| ALPHANUM[rng.gen_range(0..ALPHANUM.len())] as char)
        .collect();
    let passkey: String = (0..PASSKEY_LEN)
        .map(|_| ALPHANUM[rng.gen_range(0..ALPHANUM.len())] as char)
        .collect();
    (id, passkey)
}

pub fn passkey_to_key(passkey: &str) -> Option<[u8; crate::crypto::KEY_LEN]> {
    if passkey.len() != PASSKEY_LEN {
        return None;
    }
    let mut key = [0u8; crate::crypto::KEY_LEN];
    key.copy_from_slice(passkey.as_bytes());
    Some(key)
}

pub fn parse_id_passkey(s: &str) -> Option<(String, String)> {
    let (id, passkey) = s.split_once('/')?;
    if id.is_empty() || passkey.len() != PASSKEY_LEN {
        return None;
    }
    Some((id.to_string(), passkey.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_passkey_lengths() {
        let (id, pk) = gen_id_passkey();
        assert_eq!(id.len(), ID_LEN);
        assert_eq!(pk.len(), PASSKEY_LEN);
    }

    #[test]
    fn generated_chars_are_alphanumeric() {
        for _ in 0..100 {
            let (id, pk) = gen_id_passkey();
            for c in id.chars().chain(pk.chars()) {
                assert!(c.is_ascii_alphanumeric());
            }
        }
    }

    #[test]
    fn passkey_maps_to_key_bytes() {
        let pk = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
        let key = passkey_to_key(pk).unwrap();
        assert_eq!(&key[..], pk.as_bytes());
    }

    #[test]
    fn bad_passkey_length_rejected() {
        assert!(passkey_to_key("short").is_none());
    }

    #[test]
    fn parse_roundtrip() {
        let (id, pk) = gen_id_passkey();
        let s = format!("{id}/{pk}");
        let parsed = parse_id_passkey(&s).unwrap();
        assert_eq!(parsed.0, id);
        assert_eq!(parsed.1, pk);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_id_passkey("nodelimiter").is_none());
        assert!(parse_id_passkey("/short").is_none());
        assert!(parse_id_passkey("id/short").is_none());
    }
}
