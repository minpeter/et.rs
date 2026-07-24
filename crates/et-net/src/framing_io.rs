use std::io::{self, Read, Write};

use et_core::framing::MAX_PROTO_LEN;
use prost::Message;

pub fn write_proto<W: Write, M: Message>(w: &mut W, msg: &M) -> io::Result<()> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).map_err(io::Error::other)?;
    let len = i64::try_from(buf.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&buf)?;
    w.flush()
}

pub fn read_proto<R: Read, M: Message + Default>(r: &mut R) -> io::Result<M> {
    read_proto_limited(r, MAX_PROTO_LEN)
}

pub fn read_proto_limited<R: Read, M: Message + Default>(r: &mut R, max_len: i64) -> io::Result<M> {
    let mut len_buf = [0u8; 8];
    r.read_exact(&mut len_buf)?;
    let len = i64::from_le_bytes(len_buf);
    if !(0..=max_len).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length out of bounds",
        ));
    }
    let frame_len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative frame length"))?;
    let mut buf = vec![0u8; frame_len];
    r.read_exact(&mut buf)?;
    M::decode(&*buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::proto::SequenceHeader;

    #[test]
    fn write_read_roundtrip() {
        let mut buf = Vec::new();
        let msg = SequenceHeader {
            sequence_number: Some(42),
        };
        write_proto(&mut buf, &msg).unwrap();
        let back: SequenceHeader = read_proto(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(back.sequence_number, Some(42));
    }

    #[test]
    fn rejects_negative_length() {
        let buf = (-1i64).to_le_bytes();
        let result: io::Result<SequenceHeader> = read_proto(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_oversized_length() {
        let buf = (MAX_PROTO_LEN + 1).to_le_bytes();
        let result: io::Result<SequenceHeader> = read_proto(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }
}
