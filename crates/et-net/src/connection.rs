use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use et_core::backed_reader::{BackedReader, ReadError, ReadItem};
use et_core::backed_writer::{BackedWriter, RecoverError, WriterOutcome};
use et_core::crypto::{
    CryptoHandler, EncryptError, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN,
};
use et_core::packet::Packet;
#[path = "connection_recovery.rs"]
mod recovery;

pub use recovery::{DEFAULT_RECOVERY_TIMEOUT, MAX_RECOVERY_PROTO_LEN};

/// Upper bound on how long a live socket write may block.
///
/// A blackholed peer (laptop sleep, silent NAT drop, Wi-Fi loss without FIN)
/// used to make an unbounded write hang for minutes while holding the server
/// session's connection mutex. That blocked `ActiveSession::recover` and left
/// clients stuck after `ReturningClient`. Live frames go through
/// [`write_all_until`] with this deadline so the transport soft-disconnects
/// and recovery can proceed.
pub const DEFAULT_LIVE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum ConnError {
    Io(io::Error),
    Read(ReadError),
    Recover(RecoverError),
    Encrypt(EncryptError),
    Backpressure,
    SequenceOutOfRange(i64),
    InvalidRecoverySequence(Option<i32>),
}

pub struct Connection {
    stream: TcpStream,
    writer: BackedWriter,
    reader: BackedReader,
}

impl Connection {
    pub fn new_client(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(stream, key, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT)
    }

    pub fn new_server(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(stream, key, DIR_SERVER_TO_CLIENT, DIR_CLIENT_TO_SERVER)
    }

    fn new(stream: TcpStream, key: &[u8; KEY_LEN], encrypt: u8, decrypt: u8) -> Self {
        Self {
            stream,
            writer: BackedWriter::new(CryptoHandler::new(key, encrypt), true),
            reader: BackedReader::new(CryptoHandler::new(key, decrypt), true),
        }
    }

    pub fn write_packet(&mut self, header: u8, payload: &[u8]) -> Result<(), ConnError> {
        self.write_packet_with_deadline(header, payload, None)
    }

    fn write_packet_with_deadline(
        &mut self,
        header: u8,
        payload: &[u8],
        deadline: Option<Instant>,
    ) -> Result<(), ConnError> {
        // Probe first so a half-closed peer (laptop sleep, Wi-Fi drop) moves
        // the writer into the disconnected catch-up buffer before we try to
        // push bytes onto a dead socket.
        if let Err(_error) = self.refresh_connectivity() {
            self.disconnect();
        }
        match self.writer.write_packet(header, payload)? {
            WriterOutcome::Send(frame) => {
                let deadline = deadline.unwrap_or_else(|| {
                    Instant::now()
                        .checked_add(DEFAULT_LIVE_WRITE_TIMEOUT)
                        .unwrap_or_else(Instant::now)
                });
                if let Err(_error) = self.write_live_frame_until(&frame, deadline) {
                    // The encrypted packet is already in the replay backup
                    // (BackedWriter pushes before returning Send). Mark the
                    // transport disconnected so further writes buffer for a
                    // returning client instead of tearing the session down.
                    self.disconnect();
                }
                Ok(())
            }
            WriterOutcome::BufferedOnly => Ok(()),
            WriterOutcome::Skipped => Err(ConnError::Backpressure),
        }
    }

    /// Write initialization traffic only while the current transport is live.
    ///
    /// Active sessions intentionally buffer output after a soft disconnect,
    /// but lifecycle transitions must not treat that buffered-only outcome as
    /// proof that the peer received a handshake packet.
    pub fn write_packet_live(&mut self, header: u8, payload: &[u8]) -> Result<(), ConnError> {
        if !self.connected() {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        }
        self.write_packet(header, payload)?;
        if self.connected() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotConnected).into())
        }
    }

    /// Write a handshake packet and require it to reach a live transport.
    pub fn write_packet_strict(&mut self, header: u8, payload: &[u8]) -> Result<(), ConnError> {
        self.write_packet_live(header, payload)
    }

    pub fn write_packet_live_until(
        &mut self,
        header: u8,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<(), ConnError> {
        if !self.connected() {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        }
        self.write_packet_with_deadline(header, payload, Some(deadline))?;
        if self.connected() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotConnected).into())
        }
    }

    /// Write a framed packet to a still-connected peer with a bounded timeout.
    ///
    /// Uses a write loop (not bare `write_all`) so each `write` is capped by
    /// the remaining deadline. On any incomplete write we error out and the
    /// caller soft-disconnects: the old TCP path is abandoned (and shut down
    /// by the soft-disconnect path) so a partial frame left on the wire cannot
    /// desync a later recovery, which always uses a new stream.
    ///
    /// Restores a cleared write timeout afterwards so recovery / handshake
    /// code that sets its own deadlines is not left with a stale value.
    fn write_live_frame_until(&mut self, frame: &[u8], deadline: Instant) -> io::Result<()> {
        let result = write_all_until(&mut self.stream, frame, deadline);
        // Best-effort restore: a failed clear must not hide a write error.
        let clear = self.stream.set_write_timeout(None);
        match (result, clear) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) => {
                // Force the peer off the half-written frame so it reconnects
                // rather than blocking on the rest of a truncated record.
                let _ = self.stream.shutdown(Shutdown::Both);
                Err(error)
            }
            (Ok(()), Err(error)) => Err(error),
        }
    }

    pub fn read_packet(&mut self) -> Result<Packet, ConnError> {
        loop {
            match self.reader.pop() {
                Ok(ReadItem::Packet(packet)) => return Ok(packet),
                Ok(ReadItem::NeedMore) => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Read(error));
                }
            }
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.disconnect();
                    return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => self.reader.feed(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Io(error));
                }
            }
        }
    }

    pub fn read_packet_until(&mut self, deadline: Instant) -> Result<Packet, ConnError> {
        loop {
            match self.reader.pop() {
                Ok(ReadItem::Packet(packet)) => {
                    self.stream.set_read_timeout(None).map_err(ConnError::Io)?;
                    return Ok(packet);
                }
                Ok(ReadItem::NeedMore) => {}
                Err(error) => {
                    let _ = self.stream.set_read_timeout(None);
                    self.disconnect();
                    return Err(ConnError::Read(error));
                }
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    self.disconnect();
                    ConnError::Io(io::ErrorKind::TimedOut.into())
                })?;
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(ConnError::Io)?;
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    let _ = self.stream.set_read_timeout(None);
                    self.disconnect();
                    return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => self.reader.feed(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = self.stream.set_read_timeout(None);
                    self.disconnect();
                    return Err(ConnError::Io(error));
                }
            }
        }
    }

    pub fn try_read_packet(&mut self) -> Result<Option<Packet>, ConnError> {
        match crate::connection_nonblocking::try_read(&mut self.stream, &mut self.reader) {
            Ok(packet) => Ok(packet),
            Err(error) => {
                self.disconnect();
                Err(error)
            }
        }
    }

    pub fn write_terminal(&mut self, bytes: &[u8]) -> Result<(), ConnError> {
        self.write_packet(0, bytes)
    }

    pub fn read_terminal(&mut self) -> Result<Vec<u8>, ConnError> {
        self.read_packet().map(|packet| packet.payload().to_vec())
    }

    pub fn disconnect(&mut self) {
        self.writer.invalidate();
        self.reader.invalidate();
    }

    pub fn shutdown(&mut self) -> Result<(), ConnError> {
        self.disconnect();
        match self.stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(ConnError::Io(error)),
        }
    }

    pub fn try_clone_stream(&self) -> Result<TcpStream, ConnError> {
        self.stream.try_clone().map_err(ConnError::Io)
    }

    pub fn connected(&self) -> bool {
        self.writer.connected()
    }

    pub fn can_buffer_write(&self, bytes: i64) -> bool {
        self.writer.has_capacity(bytes)
    }

    /// Apply a peer delivery acknowledgement (keep-alive payload) to the
    /// replay backup. Implausible values are ignored.
    pub fn acknowledge_delivery(&mut self, sequence: i64) {
        self.writer.acknowledge(sequence);
    }

    /// Keep-alive payload acknowledging everything read so far.
    pub fn keepalive_ack(&self) -> [u8; et_core::keepalive::ACK_PAYLOAD_LEN] {
        et_core::keepalive::encode_ack(self.reader.sequence())
    }

    pub fn set_io_timeout(&self, timeout: Option<Duration>) -> Result<(), ConnError> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn writer_sequence(&self) -> i64 {
        self.writer.sequence()
    }

    pub fn reader_sequence(&self) -> i64 {
        self.reader.sequence()
    }

    fn refresh_connectivity(&mut self) -> Result<(), ConnError> {
        if !self.writer.connected() {
            return Ok(());
        }
        if let Err(error) = self.stream.set_nonblocking(true) {
            self.disconnect();
            return Err(ConnError::Io(error));
        }
        let mut byte = [0u8; 1];
        let probe = self.stream.peek(&mut byte);
        if let Err(error) = self.stream.set_nonblocking(false) {
            self.disconnect();
            return Err(ConnError::Io(error));
        }
        match probe {
            Ok(0) => self.disconnect(),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                self.disconnect();
            }
            Err(error) => {
                self.disconnect();
                return Err(ConnError::Io(error));
            }
        }
        Ok(())
    }
}

/// Write the full buffer before `deadline`, refreshing the socket write
/// timeout on each attempt so a blackholed peer cannot pin the caller.
fn write_all_until(stream: &mut TcpStream, mut buffer: &[u8], deadline: Instant) -> io::Result<()> {
    while !buffer.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "live write deadline elapsed")
            })?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
