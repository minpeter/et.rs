use std::io::{self, Read, Write};

use et_core::framing::MAX_PROTO_LEN;
use prost::Message;

pub fn write_proto<W: Write, M: Message>(writer: &mut W, message: &M) -> io::Result<()> {
    write_proto_limited(writer, message, MAX_PROTO_LEN)
}

pub fn write_proto_limited<W: Write, M: Message>(
    writer: &mut W,
    message: &M,
    max_len: i64,
) -> io::Result<()> {
    let mut buffer = Vec::new();
    message.encode(&mut buffer).map_err(io::Error::other)?;
    let length = i64::try_from(buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    if !(0..=max_len).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message length exceeds configured limit",
        ));
    }
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&buffer)?;
    writer.flush()
}

pub fn read_proto<R: Read, M: Message + Default>(reader: &mut R) -> io::Result<M> {
    read_proto_limited(reader, MAX_PROTO_LEN)
}

pub fn read_proto_limited<R: Read, M: Message + Default>(
    reader: &mut R,
    max_len: i64,
) -> io::Result<M> {
    let mut length_buffer = [0u8; 8];
    reader.read_exact(&mut length_buffer)?;
    let length = i64::from_le_bytes(length_buffer);
    if !(0..=max_len).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length out of bounds",
        ));
    }
    let frame_len = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative frame length"))?;
    let mut buffer = vec![0u8; frame_len];
    reader.read_exact(&mut buffer)?;
    M::decode(&*buffer).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::proto::SequenceHeader;

    #[test]
    fn write_read_roundtrip() {
        let mut buffer = Vec::new();
        let message = SequenceHeader {
            sequence_number: Some(42),
        };
        write_proto(&mut buffer, &message).unwrap();
        let back: SequenceHeader = read_proto(&mut std::io::Cursor::new(&buffer)).unwrap();
        assert_eq!(back.sequence_number, Some(42));
    }

    #[test]
    fn rejects_negative_and_oversized_lengths() {
        for length in [-1, MAX_PROTO_LEN + 1] {
            let result: io::Result<SequenceHeader> =
                read_proto(&mut std::io::Cursor::new(length.to_le_bytes()));
            assert!(result.is_err());
        }
    }

    #[test]
    fn limited_writer_rejects_before_writing() {
        let mut buffer = Vec::new();
        let message = SequenceHeader {
            sequence_number: Some(42),
        };
        assert!(write_proto_limited(&mut buffer, &message, 0).is_err());
        assert!(buffer.is_empty());
    }
}
