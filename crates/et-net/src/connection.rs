use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::connection_nonblocking::read_blocking;
use et_core::backed_reader::{BackedReader, ReadError, ReadItem};
use et_core::backed_writer::{BackedWriter, RecoverError, WriterOutcome};
use et_core::crypto::{
    CryptoHandler, EncryptError, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN,
};
use et_core::packet::Packet;
use socket2::SockRef;
#[path = "connection_pending.rs"]
mod pending;
#[path = "connection_recovery.rs"]
mod recovery;

pub use recovery::{RecoveryExchange, DEFAULT_RECOVERY_TIMEOUT, MAX_RECOVERY_PROTO_LEN};

/// Upper bound on how long a live socket write may block.
///
/// A blackholed peer (laptop sleep, silent NAT drop, Wi-Fi loss without FIN)
/// used to make an unbounded write hang for minutes while holding the server
/// session's connection mutex. That blocked `ActiveSession::recover` and left
/// clients stuck after `ReturningClient`. Live frames go through
/// a retained pending write with this deadline so the transport soft-disconnects
/// and recovery can proceed.
pub const DEFAULT_LIVE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
pub const FLOW_CONTROL_LIVE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const FLOW_CONTROL_SOCKET_BUFFER_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum ConnError {
    Io(io::Error),
    Read(ReadError),
    Recover(RecoverError),
    Encrypt(EncryptError),
    Backpressure,
    PacketTooLarge,
    SequenceOutOfRange(i64),
    InvalidRecoverySequence(Option<i32>),
}

pub struct Connection {
    stream: Arc<TcpStream>,
    writer: BackedWriter,
    /// Shared with [`ConnectionReader`] handles, so a dedicated reader thread
    /// receives and decrypts without the lock that serializes the writer.
    reader: Arc<Mutex<BackedReader>>,
    live_write_timeout: Duration,
    pending_live: Option<pending::PendingWrite>,
}

/// Receive half of a [`Connection`].
///
/// A server session's terminal bridge is its only transport reader, while its
/// output writer takes the session's connection lock for every frame. Reading
/// through this handle keeps receive and decryption off that lock. The handle
/// shares the connection's reader state, so a recovery snapshot, disconnect,
/// or keep-alive acknowledgement through the connection observes every packet
/// read here.
pub struct ConnectionReader {
    stream: Arc<TcpStream>,
    reader: Arc<Mutex<BackedReader>>,
}

impl ConnectionReader {
    /// Read one packet without blocking. An error invalidates the shared
    /// reader only; the owner disconnects the writer through the connection.
    pub fn try_read_packet(&self) -> Result<Option<Packet>, ConnError> {
        let mut reader = lock_reader(&self.reader);
        let result = crate::connection_nonblocking::try_read(&self.stream, &mut reader);
        if result.is_err() {
            reader.invalidate();
        }
        result
    }

    pub fn has_buffered_read(&self) -> bool {
        lock_reader(&self.reader).has_buffered_data()
    }

    /// Keep-alive payload acknowledging everything read so far.
    pub fn keepalive_ack(&self) -> [u8; et_core::keepalive::ACK_PAYLOAD_LEN] {
        et_core::keepalive::encode_ack(lock_reader(&self.reader).sequence())
    }
}

// Every reader mutation completes before it can fail, so state behind a
// poisoned lock is still consistent.
fn lock_reader(reader: &Mutex<BackedReader>) -> MutexGuard<'_, BackedReader> {
    reader.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct PreparedWrite {
    live: Option<(Arc<TcpStream>, Arc<Vec<u8>>, Duration)>,
}

#[derive(Debug)]
pub enum WritePacketError {
    BeforeReplay(ConnError),
    ReplayOwned(ConnError),
}

impl WritePacketError {
    pub fn into_inner(self) -> ConnError {
        match self {
            Self::BeforeReplay(error) | Self::ReplayOwned(error) => error,
        }
    }
}

impl PreparedWrite {
    pub fn send(self) -> Result<(), WritePacketError> {
        match self.into_pending() {
            Some(pending) => pending.finish(),
            None => Ok(()),
        }
    }

    fn send_until(self, deadline: Instant) -> Result<(), WritePacketError> {
        let Some(mut pending) = self.into_pending() else {
            return Ok(());
        };
        pending.deadline = deadline;
        pending.finish()
    }
}

impl Connection {
    pub fn new_client(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(
            stream,
            key,
            DIR_CLIENT_TO_SERVER,
            DIR_SERVER_TO_CLIENT,
            et_core::backed_reader::MAX_SOCKET_READ,
        )
    }

    /// A server connection reads with a smaller cap: a server holds one per
    /// session (see [`et_core::backed_reader::SERVER_MAX_SOCKET_READ`]).
    pub fn new_server(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(
            stream,
            key,
            DIR_SERVER_TO_CLIENT,
            DIR_CLIENT_TO_SERVER,
            et_core::backed_reader::SERVER_MAX_SOCKET_READ,
        )
    }

    fn new(
        stream: TcpStream,
        key: &[u8; KEY_LEN],
        encrypt: u8,
        decrypt: u8,
        max_socket_read: usize,
    ) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            stream: Arc::new(stream),
            writer: BackedWriter::new(CryptoHandler::new(key, encrypt), true),
            reader: Arc::new(Mutex::new(
                BackedReader::new(CryptoHandler::new(key, decrypt), true)
                    .with_max_socket_read(max_socket_read),
            )),
            live_write_timeout: DEFAULT_LIVE_WRITE_TIMEOUT,
            pending_live: None,
        }
    }

    pub fn write_packet(&mut self, header: u8, payload: &[u8]) -> Result<(), ConnError> {
        self.write_packet_owned(header, payload)
            .map_err(WritePacketError::into_inner)
    }

    pub fn write_packet_owned(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<(), WritePacketError> {
        self.write_packet_owned_until(header, payload, None)
    }

    fn write_packet_owned_until(
        &mut self,
        header: u8,
        payload: &[u8],
        deadline: Option<Instant>,
    ) -> Result<(), WritePacketError> {
        let prepared = self.prepare_write_packet(header, payload)?;
        let result = match deadline {
            Some(deadline) => prepared.send_until(deadline),
            None => prepared.send(),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.disconnect();
                Err(error)
            }
        }
    }

    pub fn prepare_write_packet(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<PreparedWrite, WritePacketError> {
        if self.pending_live.is_some() {
            return Err(WritePacketError::BeforeReplay(ConnError::Backpressure));
        }
        #[cfg(unix)]
        if self.refresh_connectivity().is_err() {
            self.disconnect();
        }
        #[cfg(windows)]
        if let Err(error) = self.refresh_connectivity() {
            self.disconnect();
            return Err(WritePacketError::BeforeReplay(error));
        }
        let live_stream = self.writer.connected().then(|| Arc::clone(&self.stream));
        match self
            .writer
            .write_packet(header, payload)
            .map_err(ConnError::Encrypt)
            .map_err(WritePacketError::BeforeReplay)?
        {
            WriterOutcome::Send(frame) => Ok(PreparedWrite {
                live: live_stream.map(|stream| (stream, frame, self.live_write_timeout)),
            }),
            WriterOutcome::BufferedOnly => Ok(PreparedWrite { live: None }),
            WriterOutcome::Skipped => Err(WritePacketError::BeforeReplay(ConnError::Backpressure)),
        }
    }

    pub fn prepare_write_packet_unprobed(
        &mut self,
        header: u8,
        payload: &[u8],
    ) -> Result<PreparedWrite, WritePacketError> {
        if self.pending_live.is_some() {
            return Err(WritePacketError::BeforeReplay(ConnError::Backpressure));
        }
        let live_stream = self.writer.connected().then(|| Arc::clone(&self.stream));
        match self
            .writer
            .write_packet(header, payload)
            .map_err(ConnError::Encrypt)
            .map_err(WritePacketError::BeforeReplay)?
        {
            WriterOutcome::Send(frame) => Ok(PreparedWrite {
                live: live_stream.map(|stream| (stream, frame, self.live_write_timeout)),
            }),
            WriterOutcome::BufferedOnly => Ok(PreparedWrite { live: None }),
            WriterOutcome::Skipped => Err(WritePacketError::BeforeReplay(ConnError::Backpressure)),
        }
    }

    /// Reserve the next frame for an output writer whose session has its own
    /// transport reader (see [`ConnectionReader`]). That reader observes a
    /// peer close, so on Unix this skips the per-frame `MSG_PEEK` probe that
    /// would contend for the socket lock with its receives. Windows still
    /// probes: the probe also switches the shared socket to nonblocking mode
    /// before replay admission.
    pub fn reserve_write_packet(
        &mut self,
        header: u8,
        payload_len: usize,
    ) -> Result<et_core::backed_writer::ReservedWrite, WritePacketError> {
        if self.pending_live.is_some() {
            return Err(WritePacketError::BeforeReplay(ConnError::Backpressure));
        }
        #[cfg(windows)]
        if let Err(error) = self.refresh_connectivity() {
            self.disconnect();
            return Err(WritePacketError::BeforeReplay(error));
        }
        self.writer
            .reserve_write(header, payload_len)
            .ok_or(WritePacketError::BeforeReplay(ConnError::Backpressure))
    }

    pub fn commit_write_packet(
        &mut self,
        reserved: et_core::backed_writer::ReservedWrite,
        frame: Arc<Vec<u8>>,
    ) -> PreparedWrite {
        let live_stream = self.writer.connected().then(|| Arc::clone(&self.stream));
        match self.writer.commit_write(reserved, frame) {
            WriterOutcome::Send(frame) => PreparedWrite {
                live: live_stream.map(|stream| (stream, frame, self.live_write_timeout)),
            },
            WriterOutcome::BufferedOnly | WriterOutcome::Skipped => PreparedWrite { live: None },
        }
    }

    pub fn prepare_write_packet_with<F>(
        &mut self,
        header: u8,
        payload: &[u8],
        clone_stream: F,
    ) -> Result<PreparedWrite, WritePacketError>
    where
        F: FnOnce(&TcpStream) -> io::Result<TcpStream>,
    {
        // No later frame may acquire a nonce or reach the socket ahead of a
        // retained partial frame, including synchronous/bootstrap callers.
        if self.pending_live.is_some() {
            return Err(WritePacketError::BeforeReplay(ConnError::Backpressure));
        }
        // Probe first so a half-closed peer (laptop sleep, Wi-Fi drop) moves
        // the writer into the disconnected catch-up buffer before we try to
        // push bytes onto a dead socket.
        #[cfg(unix)]
        if self.refresh_connectivity().is_err() {
            self.disconnect();
        }
        #[cfg(windows)]
        if let Err(error) = self.refresh_connectivity() {
            self.disconnect();
            return Err(WritePacketError::BeforeReplay(error));
        }
        // Clone before encryption advances the nonce/sequence and inserts
        // replay history; all fallible Windows nonblocking setup above is
        // likewise complete before the writer owns this frame.
        let live_stream = self
            .writer
            .connected()
            .then(|| {
                clone_stream(&self.stream)
                    .map(Arc::new)
                    .map_err(ConnError::Io)
                    .map_err(WritePacketError::BeforeReplay)
            })
            .transpose()?;
        match self
            .writer
            .write_packet(header, payload)
            .map_err(ConnError::Encrypt)
            .map_err(WritePacketError::BeforeReplay)?
        {
            WriterOutcome::Send(frame) => Ok(PreparedWrite {
                live: live_stream.map(|stream| (stream, frame, self.live_write_timeout)),
            }),
            WriterOutcome::BufferedOnly => Ok(PreparedWrite { live: None }),
            WriterOutcome::Skipped => Err(WritePacketError::BeforeReplay(ConnError::Backpressure)),
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
        self.write_packet_owned(header, payload)
            .map_err(WritePacketError::into_inner)?;
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
        self.write_packet_owned_until(header, payload, Some(deadline))
            .map_err(WritePacketError::into_inner)?;
        if self.connected() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotConnected).into())
        }
    }

    pub fn read_packet(&mut self) -> Result<Packet, ConnError> {
        loop {
            let item = self.reader().pop();
            match item {
                Ok(ReadItem::Packet(packet)) => return Ok(packet),
                Ok(ReadItem::NeedMore) => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Read(error));
                }
            }
            let mut buffer = [0u8; 8192];
            match read_blocking(&self.stream, &mut buffer) {
                Ok(0) => {
                    self.disconnect();
                    return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => self.reader().feed(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Io(error));
                }
            }
        }
    }

    pub fn read_packet_deadline(&mut self, deadline: Instant) -> Result<Packet, ConnError> {
        self.read_packet_until(deadline)
    }

    pub fn read_packet_until(&mut self, deadline: Instant) -> Result<Packet, ConnError> {
        loop {
            let item = self.reader().pop();
            match item {
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
            match read_blocking(&self.stream, &mut buffer) {
                Ok(0) => {
                    let _ = self.stream.set_read_timeout(None);
                    self.disconnect();
                    return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => self.reader().feed(&buffer[..count]),
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
        let result = crate::connection_nonblocking::try_read(&self.stream, &mut self.reader());
        if result.is_err() {
            self.disconnect();
        }
        result
    }

    pub fn has_buffered_read(&self) -> bool {
        self.reader().has_buffered_data()
    }

    /// Receive half sharing this connection's reader state. Recovery replaces
    /// the whole connection, so a handle reads only the transport it was
    /// taken from.
    pub fn reader_handle(&self) -> ConnectionReader {
        ConnectionReader {
            stream: Arc::clone(&self.stream),
            reader: Arc::clone(&self.reader),
        }
    }

    fn reader(&self) -> MutexGuard<'_, BackedReader> {
        lock_reader(&self.reader)
    }

    pub fn write_terminal(&mut self, bytes: &[u8]) -> Result<(), ConnError> {
        self.write_packet(0, bytes)
    }

    pub fn read_terminal(&mut self) -> Result<Vec<u8>, ConnError> {
        self.read_packet().map(|packet| packet.payload().to_vec())
    }

    pub fn disconnect(&mut self) {
        self.pending_live = None;
        self.writer.invalidate();
        self.reader().invalidate();
    }

    pub fn shutdown(&mut self) -> Result<(), ConnError> {
        self.disconnect();
        match self.stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(ConnError::Io(error)),
        }
    }

    /// Clone the transport for readiness polling or shutdown. On Apple and Windows,
    /// live sends leave the shared socket nonblocking; use Connection's
    /// packet APIs rather than assuming blocking I/O on this raw clone.
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

    /// Latest peer acknowledgement and the wire bytes written since; `None`
    /// for a peer that has never acknowledged delivery (legacy peers).
    pub fn delivery_backlog(&self) -> Option<(i64, i64)> {
        self.writer.delivery_backlog()
    }

    /// Keep-alive payload acknowledging everything read so far.
    pub fn keepalive_ack(&self) -> [u8; et_core::keepalive::ACK_PAYLOAD_LEN] {
        et_core::keepalive::encode_ack(self.reader().sequence())
    }

    pub fn set_io_timeout(&self, timeout: Option<Duration>) -> Result<(), ConnError> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }

    /// Keep opt-in flow-control backlog in the application queue instead of
    /// letting the kernel send queue autotune to multiple megabytes. The cap
    /// stays above a single forwarding frame so one full packet does not stall
    /// the session loop's write batch on every iteration.
    pub fn minimize_output_buffering(&mut self) -> Result<(), ConnError> {
        self.live_write_timeout = FLOW_CONTROL_LIVE_WRITE_TIMEOUT;
        let socket = SockRef::from(&*self.stream);
        socket
            .set_send_buffer_size(FLOW_CONTROL_SOCKET_BUFFER_BYTES)
            .map_err(ConnError::Io)?;
        #[cfg(target_os = "linux")]
        socket
            .set_tcp_notsent_lowat((FLOW_CONTROL_SOCKET_BUFFER_BYTES / 4) as u32)
            .map_err(ConnError::Io)?;
        Ok(())
    }

    /// Shrink BOTH transport directions to a tiny window.
    ///
    /// Loopback negotiates mss 65483 with a ~190 KB window, so a bounded
    /// forwarding backlog never fills there and a default-buffer test cannot
    /// reproduce the saturation seen on a real link (mss 1228, cwnd 64-99).
    /// Tests use this to force the same pressure deterministically.
    pub fn shrink_transport_window_for_tests(&self, bytes: usize) -> Result<(), ConnError> {
        let socket = SockRef::from(&*self.stream);
        socket.set_send_buffer_size(bytes).map_err(ConnError::Io)?;
        socket.set_recv_buffer_size(bytes).map_err(ConnError::Io)?;
        #[cfg(target_os = "linux")]
        socket
            .set_tcp_notsent_lowat(bytes as u32)
            .map_err(ConnError::Io)?;
        Ok(())
    }

    pub fn writer_sequence(&self) -> i64 {
        self.writer.sequence()
    }

    pub fn reader_sequence(&self) -> i64 {
        self.reader().sequence()
    }

    fn refresh_connectivity(&mut self) -> Result<(), ConnError> {
        if !self.writer.connected() {
            return Ok(());
        }
        let mut byte = [0u8; 1];
        // Socket clones share the same underlying nonblocking mode.
        // Toggling O_NONBLOCK here can make an in-flight PreparedWrite on a
        // sibling clone fail with EAGAIN and tear down a healthy transport.
        #[cfg(unix)]
        let probe = rustix::net::recv(
            &self.stream,
            &mut byte,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        )
        .map(|(count, _)| count)
        .map_err(io::Error::from);
        #[cfg(windows)]
        let probe = {
            self.stream.set_nonblocking(true)?;
            self.stream.peek(&mut byte)
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    #[test]
    fn clone_failure_does_not_advance_writer_nonce_or_sequence() {
        // Given: an authenticated connection whose transport clone fails.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
        let (server_stream, _) = listener.accept().unwrap();
        let client_stream = connector.join().unwrap();
        let key = [19u8; KEY_LEN];
        let mut sender = Connection::new_client(client_stream, &key);
        let mut receiver = Connection::new_server(server_stream, &key);

        // When: preparation fails, then the same logical packet is retried.
        let failure = sender.prepare_write_packet_with(7, b"once", |_| {
            Err(io::Error::other("injected clone failure"))
        });
        assert!(matches!(
            failure,
            Err(WritePacketError::BeforeReplay(ConnError::Io(_)))
        ));
        assert_eq!(sender.writer_sequence(), 0);
        sender.write_packet(7, b"once").unwrap();

        // Then: the peer decrypts sequence zero exactly once.
        let packet = receiver.read_packet().unwrap();
        assert_eq!((packet.header(), packet.payload()), (7, b"once".as_slice()));
        assert_eq!(sender.writer_sequence(), 1);
        assert_eq!(receiver.reader_sequence(), 1);
    }
}
