//! `htm`: the client half of the HTM IPC pair, mirroring upstream
//! `HtmClient.cpp` + `IpcPairClient`.
//!
//! The client is a raw relay: stdin is forwarded to the daemon and daemon
//! output is written to stdout. The HTM protocol itself is interpreted by the
//! terminal emulator on the other side of stdout.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rustix::event::{poll, PollFd, PollFlags};

use crate::codes;

/// 10ms poll interval, matching upstream's select() timeout.
const POLL_TIMEOUT: rustix::event::Timespec = rustix::event::Timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

const BUF_SIZE: usize = 1024;
const CONNECT_RETRIES: usize = 5;

/// Connect to the daemon, retrying like upstream `IpcPairClient`.
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    let mut last_error = None;
    for _ in 0..CONNECT_RETRIES {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("Connect to IPC failed")))
}

/// Relay until the daemon closes or sends `SESSION_END`.
pub fn run(
    stream: &mut UnixStream,
    input: &mut impl ReadFd,
    output: &mut impl Write,
) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let mut buffer = [0u8; BUF_SIZE];
    loop {
        let mut descriptors = [
            PollFd::new(&*stream, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
            PollFd::new(input, PollFlags::IN | PollFlags::HUP),
        ];
        poll(&mut descriptors, Some(&POLL_TIMEOUT)).map_err(io::Error::from)?;
        let daemon_events = descriptors[0].revents();
        let input_events = descriptors[1].revents();

        if input_events.contains(PollFlags::IN) {
            match input.read(&mut buffer) {
                Ok(0) => return Err(io::Error::other("stdin has closed abruptly.")),
                Ok(count) => stream.write_all(&buffer[..count])?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }

        if daemon_events.contains(PollFlags::IN) {
            match stream.read(&mut buffer) {
                // htmd has closed.
                Ok(0) => return Ok(()),
                // Session end is a single-byte control message.
                Ok(1) if buffer[0] == codes::SESSION_END => return Ok(()),
                Ok(count) => {
                    output.write_all(&buffer[..count])?;
                    output.flush()?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }

        if daemon_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
    }
}

/// A readable input source that can be polled (stdin in practice).
pub trait ReadFd: Read + AsFd {}
impl<T: Read + AsFd> ReadFd for T {}

/// Helper so callers can poll borrowed stdin.
pub struct Stdin(pub std::io::Stdin);

impl Read for Stdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buffer)
    }
}

impl AsFd for Stdin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_end_stops_the_relay() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let (mut input, _input_writer) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        daemon.write_all(&[codes::SESSION_END]).unwrap();
        let mut output = Vec::new();
        run(&mut client, &mut input, &mut output).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn daemon_output_is_relayed_until_the_daemon_closes() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let (mut input, _input_writer) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        daemon.write_all(b"pane output").unwrap();
        // Closing the daemon end is the other upstream stop condition.
        drop(daemon);
        let mut output = Vec::new();
        run(&mut client, &mut input, &mut output).unwrap();
        assert_eq!(output, b"pane output");
    }

    #[test]
    fn stdin_is_forwarded_to_the_daemon() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let (mut input, mut input_writer) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        input_writer.write_all(b"keys").unwrap();
        drop(input_writer);
        let mut output = Vec::new();
        // The relay stops once stdin reaches EOF.
        let error = run(&mut client, &mut input, &mut output).unwrap_err();
        assert!(error.to_string().contains("stdin has closed"));
        daemon.set_nonblocking(true).unwrap();
        let mut received = [0u8; 4];
        daemon.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"keys");
    }
}
