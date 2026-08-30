use et_net::local::LocalStream;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError, Weak};
use std::time::{Duration, Instant};

use et_core::proto::TerminalPacketType;
use et_core::{
    flow_control::{FlowControlMode as QueueMode, OutputQueue},
    packet::Packet,
};
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
const FLOW_CONTROL_BUFFER_BYTES: usize = 64 * 1024;

struct FlowControlState {
    queue: Mutex<OutputQueue>,
    wake: Condvar,
    connected: AtomicBool,
    shutdown: AtomicBool,
}

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
    shutdown: AtomicBool,
    /// Only one recover may run at a time. Concurrent returning clients used
    /// to queue on the connection mutex for minutes after a blackhole write.
    recovering: AtomicBool,
    connection_generation: AtomicU64,
    flow_control: Option<Arc<FlowControlState>>,
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
        flow_control: Option<i32>,
    ) -> Result<Self, SessionError> {
        let queue_mode = queue_mode(flow_control);
        if queue_mode.is_some() {
            connection
                .minimize_output_buffering()
                .map_err(SessionError::Connection)?;
        }
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
            shutdown: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            connection_generation: AtomicU64::new(0),
            flow_control: queue_mode.map(|mode| {
                Arc::new(FlowControlState {
                    queue: Mutex::new(OutputQueue::new(mode, FLOW_CONTROL_BUFFER_BYTES)),
                    wake: Condvar::new(),
                    connected: AtomicBool::new(true),
                    shutdown: AtomicBool::new(false),
                })
            }),
        })
    }

    pub(crate) fn start_flow_writer(self: &Arc<Self>) {
        let Some(state) = self.flow_control.clone() else {
            return;
        };
        let session = Arc::downgrade(self);
        std::thread::spawn(move || run_flow_writer(session, state));
    }

    pub(crate) fn send_packet(&self, header: u8, payload: &[u8]) -> Result<(), SessionError> {
        if let Some(state) = &self.flow_control {
            let mut queue = state.queue.lock().map_err(|_| SessionError::Unavailable)?;
            queue
                .push(Packet::new(header, payload))
                .map_err(|_| SessionError::Connection(ConnError::Backpressure))?;
            drop(queue);
            state.wake.notify_one();
            return Ok(());
        }
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
        hold.push((header, payload.to_vec()));
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
        if self.flow_control.is_some() {
            candidate
                .minimize_output_buffering()
                .map_err(SessionError::Connection)?;
        }
        let ack = candidate.keepalive_ack();
        candidate
            .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
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
            if let Some(state) = &self.flow_control {
                state.connected.store(true, Ordering::Release);
                state.wake.notify_one();
            }
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
        }
    }

    pub(crate) fn finish_terminal(&self) -> Result<(), SessionError> {
        self.shutdown.store(true, Ordering::Release);
        self.stop_flow_writer();
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
        self.stop_flow_writer();
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
        if let Some(state) = &self.flow_control {
            state.connected.store(false, Ordering::Release);
            state.wake.notify_one();
        }
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
        if let Some(state) = &self.flow_control {
            let bytes = usize::try_from(bytes).map_err(|_| SessionError::Unavailable)?;
            return Ok(state
                .queue
                .lock()
                .map_err(|_| SessionError::Unavailable)?
                .can_accept_terminal(bytes));
        }
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

    fn stop_flow_writer(&self) {
        if let Some(state) = &self.flow_control {
            state.shutdown.store(true, Ordering::Release);
            state.wake.notify_one();
        }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.stop_flow_writer();
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
        if let Some(state) = &self.session.flow_control {
            let connected = self
                .session
                .connection
                .lock()
                .is_ok_and(|connection| connection.connected());
            state.connected.store(connected, Ordering::Release);
            state.wake.notify_one();
        }
        // Wake the bridge even on failure so it re-checks connection state.
        let _ = self.session.signal();
    }
}

fn queue_mode(value: Option<i32>) -> Option<QueueMode> {
    match value.and_then(|value| et_core::proto::FlowControlMode::try_from(value).ok()) {
        None | Some(et_core::proto::FlowControlMode::None) => None,
        Some(et_core::proto::FlowControlMode::Backpressure) => Some(QueueMode::Backpressure),
        Some(et_core::proto::FlowControlMode::Discard) => Some(QueueMode::Discard),
    }
}

fn run_flow_writer(session: Weak<ActiveSession>, state: Arc<FlowControlState>) {
    loop {
        let packet = {
            let Ok(queue) = state.queue.lock() else {
                return;
            };
            let Ok(mut queue) = state.wake.wait_while(queue, |queue| {
                !state.shutdown.load(Ordering::Acquire)
                    && (!state.connected.load(Ordering::Acquire) || queue.bytes() == 0)
            }) else {
                return;
            };
            if state.shutdown.load(Ordering::Acquire) {
                return;
            }
            queue.pop()
        };
        let Some(packet) = packet else {
            continue;
        };
        let Some(session) = session.upgrade() else {
            return;
        };
        let result = session
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)
            .and_then(|mut connection| {
                if !connection.connected() {
                    state.connected.store(false, Ordering::Release);
                    return Err(SessionError::Connection(ConnError::Backpressure));
                }
                let result = connection
                    .write_packet(packet.header(), packet.payload())
                    .map_err(SessionError::Connection);
                state
                    .connected
                    .store(connection.connected(), Ordering::Release);
                result
            });
        match result {
            Ok(()) => {}
            Err(SessionError::Connection(ConnError::Backpressure)) => {
                if let Ok(mut queue) = state.queue.lock() {
                    queue.push_front(packet);
                } else {
                    return;
                }
            }
            Err(error) => {
                crate::diag::info(format!("flow-control writer stopped: {error}"));
                state.shutdown.store(true, Ordering::Release);
                return;
            }
        }
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
