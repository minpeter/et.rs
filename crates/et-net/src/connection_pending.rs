//! A single replay-owned live frame, advanced without monopolizing the reader.
use std::io;
use std::net::{Shutdown, TcpStream};
use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::{ConnError, Connection, PreparedWrite, WritePacketError};

// One syscall and at most this many bytes per pump turn, even on a fast socket.
const WRITE_QUANTUM: usize = 64 * 1024;

pub(super) struct PendingWrite {
    stream: TcpStream,
    frame: Vec<u8>,
    offset: usize,
    deadline: Instant,
}

impl PreparedWrite {
    pub(super) fn into_pending(self) -> Option<PendingWrite> {
        self.live.map(|(stream, frame, timeout)| PendingWrite {
            stream,
            frame,
            offset: 0,
            deadline: Instant::now() + timeout,
        })
    }
}

impl PendingWrite {
    fn advance(&mut self) -> io::Result<bool> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "live write deadline elapsed",
            ));
        }
        let end = self.frame.len().min(self.offset + WRITE_QUANTUM);
        // Darwin uses a socket option rather than MSG_NOSIGNAL. Do not rely
        // on the embedding process ignoring SIGPIPE globally.
        #[cfg(target_vendor = "apple")]
        let flags = {
            if self.offset == 0 {
                rustix::net::sockopt::set_socket_nosigpipe(&self.stream, true)?;
            }
            rustix::net::SendFlags::DONTWAIT
        };
        #[cfg(not(target_vendor = "apple"))]
        let flags = rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL;
        match rustix::net::send(&self.stream, &self.frame[self.offset..end], flags) {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                self.offset += count;
                Ok(self.offset == self.frame.len())
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    // Synchronous callers (including the server's independent output worker)
    // retain their API. The connection mutex is not held by that worker.
    pub(super) fn finish(mut self) -> Result<(), WritePacketError> {
        (|| {
            while !self.advance()? {
                let remaining = self.deadline.saturating_duration_since(Instant::now());
                let timeout = Timespec::try_from(remaining)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write poll range"))?;
                let mut descriptors = [PollFd::new(&self.stream, PollFlags::OUT)];
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
            Ok(())
        })()
        .map_err(ConnError::Io)
        .map_err(WritePacketError::ReplayOwned)
    }
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        if self.offset != self.frame.len() {
            // Abandoning a partial record must also abandon its transport.
            // The complete encrypted record remains exclusively in replay.
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }
}

impl Connection {
    /// Admit exactly one packet to replay and advance its live write once.
    /// Success means replay owns it, not that the peer has received it.
    pub fn start_write_packet_owned(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<(), WritePacketError> {
        self.pending_live = self.prepare_write_packet(header, payload)?.into_pending();
        self.advance_write().map(|_| ())
    }

    pub fn write_pending(&self) -> bool {
        self.pending_live.is_some()
    }

    /// Block (bounded by the frame's original deadline) until the retained
    /// partial frame is on the wire. For terminal paths such as a final
    /// `TerminalClose`, which must follow that frame rather than be refused.
    pub fn finish_pending_write(&mut self) -> Result<(), WritePacketError> {
        let Some(pending) = self.pending_live.take() else {
            return Ok(());
        };
        let result = pending.finish();
        if result.is_err() {
            self.disconnect();
        }
        result
    }

    pub fn pending_write_deadline(&self) -> Option<Instant> {
        self.pending_live.as_ref().map(|pending| pending.deadline)
    }

    /// Advance one bounded partial write. Call on writable readiness, or at
    /// its absolute deadline; reads remain independently serviceable.
    pub fn advance_write(&mut self) -> Result<bool, WritePacketError> {
        let Some(pending) = self.pending_live.as_mut() else {
            return Ok(true);
        };
        match pending.advance() {
            Ok(true) => {
                self.pending_live = None;
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                self.disconnect();
                Err(WritePacketError::ReplayOwned(ConnError::Io(error)))
            }
        }
    }
}

#[cfg(test)]
#[path = "connection_pending_tests.rs"]
mod tests;
