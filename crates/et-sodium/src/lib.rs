//! Safe wrapper over libsodium `crypto_secretbox_easy`/`crypto_secretbox_open_easy`
//! (XSalsa20-Poly1305).
//!
//! This is the workspace's only FFI boundary: the workspace lint
//! `unsafe_code = "forbid"` is relaxed for exactly these two audited calls.
//! The EternalTerminal wire layout is libsodium's own: the 16-byte MAC tag is
//! prepended to the ciphertext, and this crate preserves that layout
//! byte-for-byte.

/// XSalsa20-Poly1305 key length.
pub const KEYBYTES: usize = 32;
/// XSalsa20-Poly1305 nonce length.
pub const NONCEBYTES: usize = 24;
/// Prepended Poly1305 tag length.
pub const MACBYTES: usize = 16;

/// Encrypt `plaintext`, returning the MAC tag prepended to the ciphertext.
pub fn secretbox(plaintext: &[u8], nonce: &[u8; NONCEBYTES], key: &[u8; KEYBYTES]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len() + MACBYTES];
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_easy(
            out.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    debug_assert_eq!(rc, 0);
    out
}

/// Decrypt a tag-prepended `ciphertext`. `None` when authentication fails.
pub fn secretbox_open(
    ciphertext: &[u8],
    nonce: &[u8; NONCEBYTES],
    key: &[u8; KEYBYTES],
) -> Option<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return None;
    }
    let mut out = vec![0u8; ciphertext.len() - MACBYTES];
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            out.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    (rc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_rejection() {
        let key = [7u8; KEYBYTES];
        let nonce = [9u8; NONCEBYTES];
        for len in [0usize, 1, 31, 32, 33, 1024, 64 * 1024] {
            let pt = vec![0xabu8; len];
            let ct = secretbox(&pt, &nonce, &key);
            assert_eq!(ct.len(), len + MACBYTES);
            assert_eq!(secretbox_open(&ct, &nonce, &key).unwrap(), pt);
            let mut tampered = ct.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(secretbox_open(&tampered, &nonce, &key).is_none());
        }
    }
}
