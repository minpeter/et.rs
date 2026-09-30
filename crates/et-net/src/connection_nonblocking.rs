use std::io::{self, Read, Write};
use std::net::TcpStream;

use et_core::backed_reader::{BackedReader, ReadItem};
use et_core::packet::Packet;

use crate::connection::ConnError;

// Darwin live writes keep O_NONBLOCK set on the shared socket. Preserve the
// Connection's synchronous API without toggling flags on another clone.
pub(crate) fn read_blocking(mut stream: &TcpStream, buffer: &mut [u8]) -> io::Result<usize> {
    #[cfg(target_vendor = "apple")]
    return blocking_io(
        stream,
        rustix::event::PollFlags::IN,
        stream.read_timeout()?,
        || stream.read(buffer),
    );
    #[cfg(not(target_vendor = "apple"))]
    stream.read(buffer)
}

pub(crate) fn write_blocking(mut stream: &TcpStream, buffer: &[u8]) -> io::Result<usize> {
    #[cfg(target_vendor = "apple")]
    return blocking_io(
        stream,
        rustix::event::PollFlags::OUT,
        stream.write_timeout()?,
        || stream.write(buffer),
    );
    #[cfg(not(target_vendor = "apple"))]
    stream.write(buffer)
}

#[cfg(target_vendor = "apple")]
fn blocking_io(
    stream: &TcpStream,
    events: rustix::event::PollFlags,
    timeout: Option<std::time::Duration>,
    mut operation: impl FnMut() -> io::Result<usize>,
) -> io::Result<usize> {
    use rustix::event::{poll, PollFd, Timespec};
    use std::time::Instant;

    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
        loop {
            let remaining = deadline
                .map(|deadline| {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    Timespec::try_from(remaining).map_err(io::Error::other)
                })
                .transpose()?;
            let mut descriptors = [PollFd::new(stream, events)];
            match poll(&mut descriptors, remaining.as_ref()) {
                Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
                Ok(_) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

pub(crate) fn try_read(
    stream: &mut TcpStream,
    reader: &mut BackedReader,
) -> Result<Option<Packet>, ConnError> {
    match reader.pop()? {
        ReadItem::Packet(packet) => return Ok(Some(packet)),
        ReadItem::NeedMore => {}
    }
    let mut buffer = [0u8; 8192];
    #[cfg(unix)]
    let read = rustix::net::recv(stream, &mut buffer, rustix::net::RecvFlags::DONTWAIT)
        .map(|(count, _)| count)
        .map_err(io::Error::from);
    #[cfg(windows)]
    let read = {
        stream.set_nonblocking(true)?;
        let read = stream.read(&mut buffer);
        stream.set_nonblocking(false)?;
        read
    };
    match read {
        Ok(0) => Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into())),
        Ok(count) => {
            reader.feed(&buffer[..count]);
            match reader.pop()? {
                ReadItem::Packet(packet) => Ok(Some(packet)),
                ReadItem::NeedMore => Ok(None),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
        Err(error) => Err(ConnError::Io(error)),
    }
}
