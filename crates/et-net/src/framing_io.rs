use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use et_core::framing::MAX_PROTO_LEN;
use prost::Message;

/// Idle-gap timeout used by [`read_exact_with_deadlines`] when the caller
/// asks for EternalTerminal `readAll(..., true)` behavior. Progress resets
/// this timer; a slow trickle can keep it from firing.
pub const SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute read deadline used with [`SOCKET_IDLE_TIMEOUT`]. Unlike the idle
/// timeout, this is never reset when bytes arrive (ANT-2026-5PETM5BV).
pub const SOCKET_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(60);

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
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    read_exact_with_deadlines(stream, buffer, Some(SOCKET_IDLE_TIMEOUT), Some(deadline))
}

/// Read exactly `buffer.len()` bytes, enforcing an idle-gap timeout and/or an
/// absolute deadline on every loop iteration so a slow trickle cannot reset
/// the timer forever (EternalTerminal #784 / ANT-2026-5PETM5BV).
pub fn read_exact_with_deadlines(
    stream: &mut TcpStream,
    mut buffer: &mut [u8],
    idle: Option<Duration>,
    absolute: Option<Instant>,
) -> io::Result<()> {
    let mut idle_deadline = idle.and_then(|idle| Instant::now().checked_add(idle));
    while !buffer.is_empty() {
        let now = Instant::now();
        if idle_deadline.is_some_and(|idle| now >= idle)
            || absolute.is_some_and(|absolute| now >= absolute)
        {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "socket timeout"));
        }
        let next = match (idle_deadline, absolute) {
            (Some(idle), Some(absolute)) => Some(idle.min(absolute)),
            (Some(idle), None) => Some(idle),
            (None, Some(absolute)) => Some(absolute),
            (None, None) => None,
        };
        if let Some(next) = next {
            set_deadline_timeout(stream, next)?;
        }
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                buffer = &mut buffer[count..];
                idle_deadline = idle.and_then(|idle| Instant::now().checked_add(idle));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if next.is_some()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                // SO_RCVTIMEO and non-blocking reads surface as WouldBlock /
                // TimedOut. Recheck Instant deadlines on the next iteration
                // so a trickle cannot reset the absolute timer (ET #784).
            }
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

    #[test]
    fn absolute_deadline_fires_under_per_byte_trickle() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trickle_stop = stop.clone();
        let writer = thread::spawn(move || {
            while !trickle_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if client.write_all(b"x").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(80));
            }
        });
        let started = Instant::now();
        let mut buffer = [0u8; 256];
        let error = read_exact_with_deadlines(
            &mut server,
            &mut buffer,
            Some(Duration::from_secs(30)),
            Some(Instant::now() + Duration::from_millis(400)),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "absolute deadline waited {:?}; trickle reset the idle timer",
            started.elapsed()
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();
    }
}
