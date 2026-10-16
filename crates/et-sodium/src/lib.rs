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

/// Encrypt `plaintext` into caller-provided buffer `out`, writing the MAC tag prepended
/// to the ciphertext. Returns `Ok(())` on success.
///
/// # Panics
/// Panics if `out.len() < plaintext.len() + MACBYTES`.
pub fn secretbox_into(
    out: &mut [u8],
    plaintext: &[u8],
    nonce: &[u8; NONCEBYTES],
    key: &[u8; KEYBYTES],
) -> usize {
    assert!(out.len() >= plaintext.len() + MACBYTES);
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
    plaintext.len() + MACBYTES
}

/// Decrypt a tag-prepended `ciphertext` into caller-provided buffer `out`.
/// Returns `Some(plaintext_len)` on success, or `None` on failure or if buffers are insufficient.
pub fn secretbox_open_into(
    out: &mut [u8],
    ciphertext: &[u8],
    nonce: &[u8; NONCEBYTES],
    key: &[u8; KEYBYTES],
) -> Option<usize> {
    if ciphertext.len() < MACBYTES || out.len() < ciphertext.len() - MACBYTES {
        return None;
    }
    let pt_len = ciphertext.len() - MACBYTES;
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            out.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    (rc == 0).then_some(pt_len)
}

/// Decrypt a tag-prepended `buffer` in place.
/// Returns `Some(plaintext_len)` on success, or `None` on failure or if `buffer.len() < MACBYTES`.
/// On success, `buffer[..plaintext_len]` contains the decrypted plaintext.
pub fn secretbox_open_in_place(
    buffer: &mut [u8],
    nonce: &[u8; NONCEBYTES],
    key: &[u8; KEYBYTES],
) -> Option<usize> {
    if buffer.len() < MACBYTES {
        return None;
    }
    let pt_len = buffer.len() - MACBYTES;
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            buffer.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    (rc == 0).then_some(pt_len)
}

/// Encrypt `plaintext`, returning the MAC tag prepended to the ciphertext.
pub fn secretbox(plaintext: &[u8], nonce: &[u8; NONCEBYTES], key: &[u8; KEYBYTES]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len() + MACBYTES];
    secretbox_into(&mut out, plaintext, nonce, key);
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
    let len = secretbox_open_into(&mut out, ciphertext, nonce, key)?;
    out.truncate(len);
    Some(out)
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
            // Test secretbox_into and secretbox_open_into
            let mut out = vec![0u8; len + MACBYTES];
            assert_eq!(secretbox_into(&mut out, &pt, &nonce, &key), len + MACBYTES);
            assert_eq!(out, ct);
            let mut decrypted = vec![0u8; len];
            let dec_len = secretbox_open_into(&mut decrypted, &out, &nonce, &key);
            assert_eq!(dec_len, Some(len));
            assert_eq!(decrypted, pt);

            // Short output buffer rejects
            if len > 0 {
                let mut short_out = vec![0u8; len - 1];
                assert_eq!(
                    secretbox_open_into(&mut short_out, &out, &nonce, &key),
                    None
                );
            }

            // Test secretbox_open_in_place
            let mut in_place = ct.clone();
            let ip_len = secretbox_open_in_place(&mut in_place, &nonce, &key);
            assert_eq!(ip_len, Some(len));
            assert_eq!(&in_place[..len], &pt[..]);
        }
    }
}
