use std::io::{self, Read, Write};
use std::net::TcpStream;
#[cfg(windows)]
use std::time::Duration;
use std::time::Instant;

use et_core::backed_reader::{BackedReader, ReadItem};
use et_core::packet::Packet;

use crate::connection::ConnError;

// Darwin and Windows live writes keep nonblocking mode set on the shared socket. Preserve the
// Connection's synchronous API without toggling flags on another clone.
pub(crate) fn read_blocking(mut stream: &TcpStream, buffer: &mut [u8]) -> io::Result<usize> {
    #[cfg(target_vendor = "apple")]
    return blocking_io(
        stream,
        rustix::event::PollFlags::IN,
        stream.read_timeout()?,
        || stream.read(buffer),
    );
    #[cfg(windows)]
    return blocking_io(stream, Readiness::Read, stream.read_timeout()?, || {
        stream.read(buffer)
    });
    #[cfg(not(any(target_vendor = "apple", windows)))]
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
    #[cfg(windows)]
    return blocking_io(stream, Readiness::Write, stream.write_timeout()?, || {
        stream.write(buffer)
    });
    #[cfg(not(any(target_vendor = "apple", windows)))]
    stream.write(buffer)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum Readiness {
    Read,
    Write,
}

/// Wait until a nonblocking socket may make progress. Error and hangup events
/// also wake the caller so the actual I/O operation reports the socket error.
#[cfg(windows)]
fn wait_ready(
    stream: &TcpStream,
    readiness: Readiness,
    deadline: Option<Instant>,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use winapi::um::winsock2::{POLLIN, POLLOUT, WSAPOLLFD};

    let mut descriptors = [WSAPOLLFD {
        fd: stream.as_raw_socket() as _,
        events: match readiness {
            Readiness::Read => POLLIN,
            Readiness::Write => POLLOUT,
        },
        revents: 0,
    }];
    loop {
        let timeout = match deadline {
            None => -1,
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                // WSAPoll takes integral milliseconds; round up so an absolute
                // deadline is never shortened by a sub-millisecond remainder.
                let has_fractional_millisecond = remaining.subsec_nanos() % 1_000_000 != 0;
                i32::try_from(
                    remaining
                        .as_millis()
                        .saturating_add(u128::from(has_fractional_millisecond)),
                )
                .unwrap_or(i32::MAX)
            }
        };
        match winapi_wsapoll::wsa_poll(&mut descriptors, timeout) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn blocking_io(
    stream: &TcpStream,
    readiness: Readiness,
    timeout: Option<Duration>,
    mut operation: impl FnMut() -> io::Result<usize>,
) -> io::Result<usize> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(stream, readiness, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

pub(crate) fn wait_writable(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut descriptors = [PollFd::new(stream, PollFlags::OUT)];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let timeout = Timespec::try_from(remaining)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write poll range"))?;
            match poll(&mut descriptors, Some(&timeout)) {
                Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    #[cfg(windows)]
    wait_ready(stream, Readiness::Write, Some(deadline))
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
        stream.read(&mut buffer)
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
