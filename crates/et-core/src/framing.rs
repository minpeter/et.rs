//! Two framing layers used by EternalTerminal:
//! - [`frame_native_i64`]: handshaking/IPC messages — a native-endian `int64`
//!   length followed by the message bytes. Upstream uses native byte order,
//!   which is little-endian on every supported target (x86_64, arm64); this
//!   module rejects big-endian targets at compile time.
//! - [`frame_be_u32`]: encrypted stream packets — a 4-byte network-order
//!   (big-endian) `uint32` length followed by the packet bytes.

pub const MAX_PROTO_LEN: i64 = 128 * 1024 * 1024;

const _: () = {
    let big_endian: bool = cfg!(target_endian = "big");
    assert!(
        !big_endian,
        "et.rs IPC framing assumes a little-endian target"
    );
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Short,
    Negative,
    TooLarge,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short => write!(f, "frame truncated"),
            Self::Negative => write!(f, "negative length"),
            Self::TooLarge => write!(f, "length exceeds 128 MiB"),
        }
    }
}

impl std::error::Error for FrameError {}

pub fn frame_native_i64(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&(payload.len() as i64).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn parse_native_i64_len(buf: &[u8]) -> Result<usize, FrameError> {
    if buf.len() < 8 {
        return Err(FrameError::Short);
    }
    let len = i64::from_le_bytes(buf[..8].try_into().unwrap());
    if len < 0 {
        return Err(FrameError::Negative);
    }
    if len > MAX_PROTO_LEN {
        return Err(FrameError::TooLarge);
    }
    Ok(len as usize)
}

pub fn frame_be_u32(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn parse_be_u32_len(buf: &[u8]) -> Result<usize, FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Short);
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > MAX_PROTO_LEN as usize {
        return Err(FrameError::TooLarge);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_i64_roundtrip() {
        let payload = [0x08u8, 0x2a];
        let framed = frame_native_i64(&payload);
        assert_eq!(parse_native_i64_len(&framed).unwrap(), 2);
        assert_eq!(&framed[8..], &payload);
    }

    #[test]
    fn native_i64_empty() {
        let framed = frame_native_i64(&[]);
        assert_eq!(framed, [0u8; 8]);
        assert_eq!(parse_native_i64_len(&framed).unwrap(), 0);
    }

    #[test]
    fn native_i64_rejects_short() {
        assert_eq!(parse_native_i64_len(&[0; 7]), Err(FrameError::Short));
    }

    #[test]
    fn native_i64_rejects_negative_and_oversized() {
        let neg = (-1i64).to_le_bytes();
        assert_eq!(parse_native_i64_len(&neg), Err(FrameError::Negative));
        let big = (MAX_PROTO_LEN + 1).to_le_bytes();
        assert_eq!(parse_native_i64_len(&big), Err(FrameError::TooLarge));
    }

    #[test]
    fn be_u32_roundtrip() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let framed = frame_be_u32(&payload);
        assert_eq!(framed, [0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_be_u32_len(&framed).unwrap(), 4);
    }
}
