use et_net::local::LocalStream;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use et_core::backed_writer::{
    MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS, MAX_RECOVERY_BACKUP_BYTES,
};
use et_core::proto::TerminalPacketType;
use et_net::connection::DEFAULT_RECOVERY_TIMEOUT;
use et_net::connection::{ConnError, Connection};

/// How long `recover` may wait for the session mutexes.
///
/// Must stay at or below [`DEFAULT_RECOVERY_TIMEOUT`]: if the terminal bridge
/// is mid-write on a blackholed socket, recover used to park forever on
/// `connection.lock()`. With a bounded live write timeout plus this lock
/// deadline, piled-up returning clients fail fast and retry instead of
/// blocking the accept path for minutes. Recovery network I/O itself runs
/// *without* the connection mutex (see [`ActiveSession::recover_body`]).
const RECOVERY_LOCK_TIMEOUT: Duration = DEFAULT_RECOVERY_TIMEOUT;

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
    control: Mutex<TcpStream>,
    terminal_control: Mutex<LocalStream>,
    wake_writer: Mutex<LocalStream>,
    wake_reader: Mutex<Option<LocalStream>>,
    /// Terminal packets produced while `recovering` is set. Drained onto the
    /// new stream after install so the connection mutex is not held for the
    /// recovery network RTT.
    recover_hold: Mutex<Vec<(u8, Vec<u8>)>>,
    recover_hold_bytes: AtomicU64,
    shutdown: AtomicBool,
    /// Only one recover may run at a time. Concurrent returning clients used
    /// to queue on the connection mutex for minutes after a blackhole write.
    recovering: AtomicBool,
    connection_generation: AtomicU64,
    bridge_generation: Mutex<u64>,
    bridge_changed: Condvar,
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
            recover_hold: Mutex::new(Vec::new()),
            recover_hold_bytes: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            connection_generation: AtomicU64::new(0),
            bridge_generation: Mutex::new(0),
            bridge_changed: Condvar::new(),
        })
    }

    pub(crate) fn send_packet(&self, header: u8, payload: &[u8]) -> Result<(), SessionError> {
        // While a recover holds the single-flight permit, queue terminal
        // output instead of contending on the connection mutex for the
        // recovery network RTT. Flushed after the new stream is installed.
        if self.queue_if_recovering(header, payload)? {
            return Ok(());
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        // Recover may have started after the fast path check. Drop the
        // connection lock before taking `recover_hold` (flush takes hold
        // then connection — reverse order deadlocks).
        if self.recovering.load(Ordering::Acquire) {
            drop(connection);
            if self.queue_if_recovering(header, payload)? {
                return Ok(());
            }
            connection = self
                .connection
                .lock()
                .map_err(|_| SessionError::Unavailable)?;
        }
        connection
            .write_packet(header, payload)
            .map_err(SessionError::Connection)
    }

    fn queue_if_recovering(&self, header: u8, payload: &[u8]) -> Result<bool, SessionError> {
        if !self.recovering.load(Ordering::Acquire) {
            return Ok(false);
        }
        let mut hold = self
            .recover_hold
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        // Re-check under the hold lock so a recover that just finished does
        // not leave packets stranded in the hold after `recovering` clears.
        if !self.recovering.load(Ordering::Acquire) {
            return Ok(false);
        }
        let held_bytes = self.recover_hold_bytes.load(Ordering::Acquire);
        let payload_bytes = u64::try_from(payload.len()).map_err(|_| SessionError::Unavailable)?;
        if hold.len() >= MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS {
            return Err(SessionError::Unavailable);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let requested = i64::try_from(held_bytes.saturating_add(payload_bytes))
            .map_err(|_| SessionError::Unavailable)?;
        if requested > MAX_RECOVERY_BACKUP_BYTES || !connection.can_buffer_write(requested) {
            return Err(SessionError::Unavailable);
        }
        drop(connection);
        hold.push((header, payload.to_vec()));
        self.recover_hold_bytes
            .fetch_add(payload_bytes, Ordering::AcqRel);
        Ok(true)
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

    /// Prepare → network handshake off-lock → install → flush hold.
    ///
    /// The connection mutex is held only for soft-disconnect/snapshot and for
    /// installing the new stream, not for sequence exchange or peer auth.
    fn recover_body(&self, stream: TcpStream) -> Result<(), SessionError> {
        // Phase 1: soft-disconnect and snapshot under a short lock.
        let mut candidate = {
            let connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            // Snapshot onto the new stream without closing or disconnecting
            // the live victim socket (ET #784 / ANT-2026-VAMER5RC). Terminal
            // output during the off-lock handshake is queued in
            // `recover_hold` because `recovering` is set. A failed recover
            // must leave the existing session intact.
            connection.prepare_recovery_candidate(stream)
        };

        // Phase 2: recovery network I/O without the session connection lock.
        candidate
            .run_recovery_handshake(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        // Any packet that decrypts with the session key authenticates the
        // returning client; it is requeued and handled by the session loop.
        candidate
            .authenticate_peer(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        let ack = candidate.keepalive_ack();
        candidate
            .write_packet_live(TerminalPacketType::KeepAlive as u8, &ack)
            .map_err(SessionError::Connection)?;
        let new_control = candidate
            .try_clone_stream()
            .map_err(SessionError::Connection)?;

        // Phase 3: install under a short lock.
        {
            let mut control = lock_timeout(&self.control, RECOVERY_LOCK_TIMEOUT)?;
            let mut connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            let old_control = std::mem::replace(&mut *control, new_control);
            let _ = old_control.shutdown(Shutdown::Both);
            *connection = candidate;
            self.connection_generation.fetch_add(1, Ordering::Release);
        }

        // Phase 4: drain terminal output queued while the handshake ran.
        // Still under `recovering` so concurrent send_packet keeps queuing
        // until the permit drops; Drop flushes once more after clearing.
        self.flush_recover_hold()
    }

    fn flush_recover_hold(&self) -> Result<(), SessionError> {
        loop {
            let batch = {
                let mut hold = self
                    .recover_hold
                    .lock()
                    .map_err(|_| SessionError::Unavailable)?;
                if hold.is_empty() {
                    return Ok(());
                }
                std::mem::take(&mut *hold)
            };
            let batch_bytes = batch.iter().fold(0u64, |total, (_, payload)| {
                total.saturating_add(payload.len() as u64)
            });
            let mut connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            let mut remaining = batch.into_iter();
            while let Some((header, payload)) = remaining.next() {
                if let Err(error) = connection.write_packet(header, &payload) {
                    // Release the connection lock before taking `recover_hold`
                    // (send_packet may hold hold → connection; reverse deadlocks).
                    drop(connection);
                    // Put the failed packet and unwritten tail back ahead of
                    // anything concurrent senders queued after we took `batch`.
                    let mut hold = self
                        .recover_hold
                        .lock()
                        .map_err(|_| SessionError::Unavailable)?;
                    let concurrent = std::mem::take(&mut *hold);
                    hold.push((header, payload));
                    hold.extend(remaining);
                    hold.extend(concurrent);
                    return Err(SessionError::Connection(error));
                }
            }
            self.recover_hold_bytes
                .fetch_sub(batch_bytes, Ordering::AcqRel);
        }
    }

    pub(crate) fn finish_terminal(&self) -> Result<(), SessionError> {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.signal();
        let terminal = self
            .terminal_control
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let _ = terminal.shutdown(Shutdown::Both);
        drop(terminal);
        let control = self.control.lock().map_err(|_| SessionError::Unavailable)?;
        match control.shutdown(Shutdown::Write) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(SessionError::Io(error)),
        }
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

    pub(crate) fn note_bridge_generation(&self, generation: u64) -> Result<(), SessionError> {
        let mut observed = self
            .bridge_generation
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if generation > *observed {
            *observed = generation;
            self.bridge_changed.notify_all();
        }
        Ok(())
    }

    pub(crate) fn wait_for_bridge_generation(
        &self,
        expected: u64,
        timeout: Duration,
    ) -> Result<(), SessionError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(SessionError::Unavailable)?;
        let mut observed = self
            .bridge_generation
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        while *observed < expected {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(SessionError::RecoverBusy)?;
            let (next, result) = self
                .bridge_changed
                .wait_timeout(observed, remaining)
                .map_err(|_| SessionError::Unavailable)?;
            observed = next;
            if result.timed_out() && *observed < expected {
                return Err(SessionError::RecoverBusy);
            }
        }
        Ok(())
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
        let hold = self
            .recover_hold
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if hold.len() >= MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS {
            return Ok(false);
        }
        let held =
            i64::try_from(self.recover_hold_bytes.load(Ordering::Acquire)).unwrap_or(i64::MAX);
        let requested = held.checked_add(bytes).unwrap_or(i64::MAX);
        if requested > MAX_RECOVERY_BACKUP_BYTES {
            return Ok(false);
        }
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .can_buffer_write(requested))
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
        // `self` drops after this returns (or panics), clearing `recovering`
        // and flushing any straggler hold packets.
        self.session.recover_body(stream)
    }
}

impl Drop for RecoverPermit<'_> {
    fn drop(&mut self) {
        // Flush while still marked recovering so send_packet keeps queuing
        // rather than racing into a half-installed connection.
        let _ = self.session.flush_recover_hold();
        self.session.recovering.store(false, Ordering::Release);
        // Catch anything that observed `recovering` and queued after the first
        // flush but before the flag cleared (re-check is under the hold lock).
        let _ = self.session.flush_recover_hold();
        // Wake the bridge even on failure so it re-checks connection state.
        let _ = self.session.signal();
    }
}

/// Acquire a [`Mutex`] with a deadline so recover cannot park forever behind a
/// bridge thread blocked in a live write.
fn lock_timeout<T>(mutex: &Mutex<T>, timeout: Duration) -> Result<MutexGuard<'_, T>, SessionError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_recovery_hold_is_capacity_bounded_and_fifo() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (stream, _) = listener.accept().unwrap();
        let _peer = peer.join().unwrap();
        let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
        let session =
            ActiveSession::new(Connection::new_server(stream, &[7; 32]), &terminal).unwrap();
        let permit = session.try_begin_recover().unwrap();

        for index in 0..4u8 {
            assert!(session.queue_if_recovering(index, &[index; 8]).unwrap());
        }
        let payload = vec![b'x'; 64 * 1024];
        let mut accepted = 4usize;
        while session.queue_if_recovering(9, &payload).is_ok() {
            accepted += 1;
            assert!(accepted <= MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS);
        }
        assert!(!session.can_buffer_write(payload.len() as i64).unwrap());

        let mut hold = session.recover_hold.lock().unwrap();
        assert_eq!(hold.len(), accepted);
        for index in 0..4u8 {
            assert_eq!(hold[index as usize], (index, vec![index; 8]));
        }
        hold.clear();
        session.recover_hold_bytes.store(0, Ordering::Release);
        drop(hold);
        session.recovering.store(false, Ordering::Release);
        drop(permit);
    }
}
