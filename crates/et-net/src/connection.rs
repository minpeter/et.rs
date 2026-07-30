use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use et_core::backed_reader::{BackedReader, ReadError, ReadItem};
use et_core::backed_writer::{BackedWriter, RecoverError, WriterOutcome};
use et_core::crypto::{
    CryptoHandler, EncryptError, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN,
};
use et_core::packet::Packet;
#[path = "connection_recovery.rs"]
mod recovery;

pub use recovery::{DEFAULT_RECOVERY_TIMEOUT, MAX_RECOVERY_PROTO_LEN};

/// Upper bound on how long a live `write_all` may block.
///
/// A blackholed peer (laptop sleep, silent NAT drop, Wi-Fi loss without FIN)
/// used to make `write_all` hang for minutes while holding the server
/// session's connection mutex. That blocked `ActiveSession::recover` and
/// left clients stuck after `ReturningClient`. Bound the write so the
/// transport soft-disconnects and recovery can proceed.
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
        // Probe first so a half-closed peer (laptop sleep, Wi-Fi drop) moves
        // the writer into the disconnected catch-up buffer before we try to
        // push bytes onto a dead socket.
        if let Err(_error) = self.refresh_connectivity() {
            self.disconnect();
        }
        match self.writer.write_packet(header, payload)? {
            WriterOutcome::Send(frame) => {
                if let Err(_error) = self.write_live_frame(&frame) {
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

    /// Write a framed packet to a still-connected peer with a bounded timeout.
    ///
    /// Restores a cleared write timeout afterwards so recovery / handshake
    /// code that sets its own deadlines is not left with a stale value.
    fn write_live_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(DEFAULT_LIVE_WRITE_TIMEOUT))?;
        let result = self.stream.write_all(frame);
        // Best-effort restore: a failed clear must not hide a write error.
        let clear = self.stream.set_write_timeout(None);
        match (result, clear) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) => Err(error),
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
