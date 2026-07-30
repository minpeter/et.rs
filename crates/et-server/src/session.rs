use et_net::local::LocalStream;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use et_core::proto::TerminalPacketType;
use et_net::connection::DEFAULT_RECOVERY_TIMEOUT;
use et_net::connection::{ConnError, Connection};

/// How long `recover` may wait for the session mutexes.
///
/// Must stay at or below [`DEFAULT_RECOVERY_TIMEOUT`]: if the terminal bridge
/// is mid-`write_all` on a blackholed socket, recover used to park forever on
/// `connection.lock()`. With a bounded live write timeout plus this lock
/// deadline, piled-up returning clients fail fast and retry instead of
/// blocking the accept path for minutes.
const RECOVERY_LOCK_TIMEOUT: Duration = DEFAULT_RECOVERY_TIMEOUT;

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
    control: Mutex<TcpStream>,
    terminal_control: Mutex<LocalStream>,
    wake_writer: Mutex<LocalStream>,
    wake_reader: Mutex<Option<LocalStream>>,
    shutdown: AtomicBool,
    /// Only one recover may run at a time. Concurrent returning clients used
    /// to queue on the connection mutex for minutes after a blackhole write.
    recovering: AtomicBool,
    connection_generation: AtomicU64,
}

pub(crate) enum SessionConnection {
    Starting(TcpStream),
    Active(Arc<ActiveSession>),
}

#[derive(Debug)]
pub enum SessionError {
    Connection(ConnError),
    Io(io::Error),
    Unavailable,
    /// Another recover is already in progress, or a session lock could not
    /// be acquired before [`RECOVERY_LOCK_TIMEOUT`].
    RecoverBusy,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(f, "session connection: {error}"),
            Self::Io(error) => write!(f, "session socket: {error}"),
            Self::Unavailable => write!(f, "session is unavailable"),
            Self::RecoverBusy => write!(
                f,
                "session recover busy (lock contention or concurrent recover)"
            ),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Unavailable | Self::RecoverBusy => None,
        }
    }
}

impl ActiveSession {
    pub(crate) fn new(
        connection: Connection,
        terminal: &LocalStream,
    ) -> Result<Self, SessionError> {
        let control = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        let terminal_control = terminal.try_clone().map_err(SessionError::Io)?;
        let (wake_reader, wake_writer) = et_net::local::wake_pair().map_err(SessionError::Io)?;
        Ok(Self {
            connection: Mutex::new(connection),
            control: Mutex::new(control),
            terminal_control: Mutex::new(terminal_control),
            wake_writer: Mutex::new(wake_writer),
            wake_reader: Mutex::new(Some(wake_reader)),
            shutdown: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            connection_generation: AtomicU64::new(0),
        })
    }

    pub(crate) fn send_packet(&self, header: u8, payload: &[u8]) -> Result<(), SessionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        connection
            .write_packet(header, payload)
            .map_err(SessionError::Connection)
    }

    /// Acquire the single-flight recover permit without speaking on the wire.
    ///
    /// Callers must send `ReturningClient` only after this succeeds, so a
    /// concurrent recover does not commit the peer to sequence exchange and
    /// then fail with `RecoverBusy`. The permit releases the flag on drop
    /// (including panic unwind).
    pub(crate) fn try_begin_recover(&self) -> Result<RecoverPermit<'_>, SessionError> {
        if self
            .recovering
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SessionError::RecoverBusy);
        }
        Ok(RecoverPermit { session: self })
    }

    fn recover_locked(&self, stream: TcpStream) -> Result<(), SessionError> {
        let mut control = lock_timeout(&self.control, RECOVERY_LOCK_TIMEOUT)?;
        let mut connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
        // Hold the session lock for the whole recover. Live writes are bounded
        // by DEFAULT_LIVE_WRITE_TIMEOUT so a blackholed peer cannot pin this
        // mutex indefinitely; lock_timeout above bounds waiters that arrive
        // while a recover (or a timed-out write) is still in progress.
        //
        // Do not soft-disconnect the incumbent transport until the candidate
        // authenticates: a failed recover must leave a healthy session alone.
        let mut candidate = connection
            .recovery_candidate(stream, DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        // Any packet that decrypts with the session key authenticates the
        // returning client; it is requeued and handled by the session loop.
        // Upstream C++ clients send regular traffic here (e.g. typed input or
        // a keep-alive), not a dedicated proof packet.
        candidate
            .authenticate_peer(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        // The proof keep-alive carries a delivery acknowledgement so an
        // et.rs client trims its replay backup right after recovery; legacy
        // clients ignore the payload.
        let ack = candidate.keepalive_ack();
        candidate
            .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
            .map_err(SessionError::Connection)?;
        let new_control = candidate
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        let old_control = std::mem::replace(&mut *control, new_control);
        let _ = old_control.shutdown(Shutdown::Both);
        *connection = candidate;
        self.connection_generation.fetch_add(1, Ordering::Release);
        drop(connection);
        drop(control);
        Ok(())
    }

    pub(crate) fn shutdown(&self) -> Result<(), SessionError> {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.signal();
        let terminal = self
            .terminal_control
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let _ = terminal.shutdown(Shutdown::Both);
        drop(terminal);
        let control = self.control.lock().map_err(|_| SessionError::Unavailable)?;
        match control.shutdown(Shutdown::Both) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Err(error) => return Err(SessionError::Io(error)),
        }
        drop(control);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        connection.shutdown().map_err(SessionError::Connection)
    }

    pub(crate) fn take_wake_reader(&self) -> Result<LocalStream, SessionError> {
        self.wake_reader
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .take()
            .ok_or(SessionError::Unavailable)
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn try_clone_stream(&self) -> Result<(TcpStream, u64), SessionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let generation = self.connection_generation.load(Ordering::Acquire);
        let stream = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        Ok((stream, generation))
    }

    pub(crate) fn try_read_packet(&self) -> Result<Option<et_core::packet::Packet>, SessionError> {
        self.connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .try_read_packet()
            .map_err(SessionError::Connection)
    }

    pub(crate) fn connection_state(&self) -> Result<(bool, u64), SessionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        Ok((
            connection.connected(),
            self.connection_generation.load(Ordering::Acquire),
        ))
    }

    /// Soft-drop the encrypted client transport without killing the terminal.
    ///
    /// Used when the client TCP path dies (sleep, Wi-Fi, NAT) so terminal
    /// output keeps buffering and a returning client can recover the same
    /// session. Does not set the session shutdown flag or close the terminal.
    pub(crate) fn mark_client_disconnected(
        &self,
        expected_generation: u64,
    ) -> Result<bool, SessionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if self.connection_generation.load(Ordering::Acquire) != expected_generation {
            return Ok(false);
        }
        connection.disconnect();
        Ok(true)
    }

    /// Apply a client delivery acknowledgement to the replay backup.
    pub(crate) fn acknowledge_delivery(&self, sequence: i64) -> Result<(), SessionError> {
        self.connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .acknowledge_delivery(sequence);
        Ok(())
    }

    /// Keep-alive payload acknowledging everything read from the client.
    pub(crate) fn keepalive_ack(
        &self,
    ) -> Result<[u8; et_core::keepalive::ACK_PAYLOAD_LEN], SessionError> {
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .keepalive_ack())
    }

    pub(crate) fn can_buffer_write(&self, bytes: i64) -> Result<bool, SessionError> {
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .can_buffer_write(bytes))
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    fn signal(&self) -> Result<(), SessionError> {
        self.wake_writer
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .write_all(&[1])
            .map_err(SessionError::Io)
    }
}

/// Single-flight recover permit. Dropping it (normally or on panic) always
/// clears [`ActiveSession::recovering`] and wakes the terminal bridge.
pub(crate) struct RecoverPermit<'a> {
    session: &'a ActiveSession,
}

impl RecoverPermit<'_> {
    /// Run the recovery handshake and install the new stream.
    pub(crate) fn complete(self, stream: TcpStream) -> Result<(), SessionError> {
        // `self` drops after this returns (or panics), clearing `recovering`.
        self.session.recover_locked(stream)
    }
}

impl Drop for RecoverPermit<'_> {
    fn drop(&mut self) {
        self.session.recovering.store(false, Ordering::Release);
        // Wake the bridge even on failure so it re-checks connection state.
        let _ = self.session.signal();
    }
}

/// Acquire a [`Mutex`] with a deadline so recover cannot park forever behind a
/// bridge thread blocked in a live write.
fn lock_timeout<T>(
    mutex: &Mutex<T>,
    timeout: Duration,
) -> Result<MutexGuard<'_, T>, SessionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(SessionError::RecoverBusy)?;
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(SessionError::Unavailable),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(SessionError::RecoverBusy);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

impl SessionConnection {
    pub(crate) fn shutdown(self) -> Result<(), SessionError> {
        match self {
            Self::Starting(stream) => match stream.shutdown(Shutdown::Both) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
                Err(error) => Err(SessionError::Io(error)),
            },
            Self::Active(session) => session.shutdown(),
        }
    }
}
