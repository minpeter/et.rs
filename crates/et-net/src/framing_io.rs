use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

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

pub fn write_proto_limited_deadline<M: Message>(
    stream: &mut TcpStream,
    message: &M,
    max_len: i64,
    deadline: Instant,
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
    write_all_deadline(stream, &length.to_le_bytes(), deadline)?;
    write_all_deadline(stream, &buffer, deadline)
}

pub fn read_proto_limited_deadline<M: Message + Default>(
    stream: &mut TcpStream,
    max_len: i64,
    deadline: Instant,
) -> io::Result<M> {
    let buffer = read_frame_limited_deadline(stream, max_len, deadline)?;
    M::decode(&*buffer).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn read_frame_limited_deadline(
    stream: &mut TcpStream,
    max_len: i64,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut length_buffer = [0u8; 8];
    read_exact_deadline(stream, &mut length_buffer, deadline)?;
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
    read_exact_deadline(stream, &mut buffer, deadline)?;
    Ok(buffer)
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !buffer.is_empty() {
        set_deadline_timeout(stream, deadline)?;
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_deadline(
    stream: &mut TcpStream,
    mut buffer: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !buffer.is_empty() {
        set_deadline_timeout(stream, deadline)?;
        match stream.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn set_deadline_timeout(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame deadline elapsed"))?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::proto::SequenceHeader;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

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

    #[test]
    fn deadline_reader_rejects_a_drip_fed_prefix() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (first_tx, first_rx) = std::sync::mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            for (index, byte) in 1i64.to_le_bytes().into_iter().enumerate() {
                client.write_all(&[byte]).unwrap();
                if index == 0 {
                    first_tx.send(()).unwrap();
                }
                thread::sleep(Duration::from_millis(40));
            }
            release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        });
        first_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let error = read_proto_limited_deadline::<SequenceHeader>(
            &mut server,
            MAX_PROTO_LEN,
            Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(200));
        release_tx.send(()).unwrap();
        writer.join().unwrap();
    }
}
