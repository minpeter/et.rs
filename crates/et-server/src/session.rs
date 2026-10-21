use et_net::local::LocalStream;
use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use et_core::backed_writer::{
    MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS, MAX_RECOVERY_BACKUP_BYTES,
};
use et_core::flow_control::FlowControlMode as QueueMode;
use et_core::packet::Packet;
use et_net::connection::{ConnError, Connection, ConnectionReader};

/// How long `recover` may wait for the session mutexes.
///
/// Must stay at or below [`DEFAULT_RECOVERY_TIMEOUT`]: if the terminal bridge
/// is mid-write on a blackholed socket, recover used to park forever on
/// `connection.lock()`. With a bounded live write timeout plus this lock
/// deadline, piled-up returning clients fail fast and retry instead of
/// blocking the accept path for minutes. Recovery network I/O itself runs
/// *without* the connection mutex (see [`ActiveSession::recover_body`]).
const RECOVERY_LOCK_TIMEOUT: Duration = et_net::connection::DEFAULT_RECOVERY_TIMEOUT;
const FLOW_CONTROL_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn disconnect_deadline_reached(
    started: &mut Option<Instant>,
    now: Instant,
    connected: bool,
    timeout: Option<Duration>,
) -> bool {
    if timeout.is_none_or(|timeout| timeout.is_zero()) || connected {
        *started = None;
        return false;
    }
    let timeout = timeout.expect("checked above");
    match *started {
        None => {
            *started = Some(now);
            false
        }
        Some(since) => now.saturating_duration_since(since) >= timeout,
    }
}

#[cfg(test)]
mod disconnect_deadline_tests {
    use super::disconnect_deadline_reached;
    use std::time::{Duration, Instant};

    #[test]
    fn first_disconnected_observation_does_not_fire() {
        let now = Instant::now();
        let mut started = None;
        assert!(!disconnect_deadline_reached(
            &mut started,
            now,
            false,
            Some(Duration::from_secs(30))
        ));
        assert!(started.is_some());
        assert!(!disconnect_deadline_reached(
            &mut started,
            now,
            false,
            Some(Duration::from_secs(30))
        ));
        assert!(disconnect_deadline_reached(
            &mut started,
            now + Duration::from_secs(30),
            false,
            Some(Duration::from_secs(30))
        ));
        assert!(!disconnect_deadline_reached(
            &mut started,
            now,
            true,
            Some(Duration::from_secs(30))
        ));
        assert!(started.is_none());
        assert!(!disconnect_deadline_reached(&mut started, now, false, None));
        assert!(!disconnect_deadline_reached(
            &mut started,
            now,
            false,
            Some(Duration::ZERO)
        ));
    }
}

#[cfg(test)]
#[path = "session_output_interrupt_test.rs"]
mod output_interrupt_tests;
#[path = "session_flow.rs"]
mod session_flow;
#[cfg(test)]
#[path = "session_flow_test.rs"]
mod session_flow_tests;
#[path = "session_io.rs"]
mod session_io;
#[path = "session_recovery.rs"]
mod session_recovery;
use session_flow::FlowControl;
#[cfg(unix)]
pub(crate) use session_flow::OutputPump;
pub(crate) use session_recovery::PeerProof;

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
    /// Receive half of `connection`. The terminal bridge is the session's only
    /// transport reader; reading here keeps receive and decryption off the
    /// connection lock that the output writer takes for every frame. Recovery
    /// replaces it together with `connection`.
    reader: Mutex<ConnectionReader>,
    // Always acquire before connection when assigning/sending output frames.
    write_serial: Mutex<()>,
    #[cfg(test)]
    prepared_write_hook: Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
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
    /// Set by [`ActiveSession::shutdown`] (full session teardown) and when a
    /// detached session with no client retires. Distinct from
    /// [`Self::shutdown`]: `finish_terminal` also sets that flag so the
    /// bridge can drain HUP, and recover must still complete.
    torn_down: AtomicBool,
    /// The router removed this session's slot after its terminal hung up,
    /// so no returning client can look the session up any more.
    detached: AtomicBool,
    /// Only one recover may run at a time. Concurrent returning clients used
    /// to queue on the connection mutex for minutes after a blackhole write.
    recovering: AtomicBool,
    /// Orders full teardown against the recovery admission claim. The
    /// recovery handshake itself runs without this lock.
    recover_admission: Mutex<()>,
    #[cfg(test)]
    recover_admission_hook: Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    connection_generation: AtomicU64,
    flow_control: Option<Arc<FlowControl>>,
    default_output: OnceLock<Arc<FlowControl>>,
    #[cfg(windows)]
    flow_writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    bridge_generation: Mutex<u64>,
    bridge_changed: Condvar,
    /// Raw pipe session (`InitialPayload.no_pty`). Binary stdin must not be
    /// treated as a terminal interrupt.
    pipe_mode: bool,
    /// Client set `InitialPayload.supports_exit_status`. Packet type 12 is
    /// forwarded only then; older clients abort on an unknown type.
    forward_exit_status: AtomicBool,
    /// Per-session disconnect timeout. `None` never fires (unset or 0).
    disconnect_timeout: Mutex<Option<Duration>>,
    /// First observation that the client was disconnected. Cleared on connect.
    disconnected_since: Mutex<Option<Instant>>,
    /// `TERMINAL_INFO` kill v1 was forwarded to etterminal.
    kill_requested: AtomicBool,
}

pub(crate) enum SessionConnection {
    Starting(TcpStream),
    Active(Arc<ActiveSession>),
}

#[derive(Debug)]
pub enum SessionWriteError {
    BeforeReplay(SessionError),
    ReplayOwned(SessionError),
}

impl SessionWriteError {
    fn into_inner(self) -> SessionError {
        match self {
            Self::BeforeReplay(error) | Self::ReplayOwned(error) => error,
        }
    }
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
        Self::new_with_pipe(connection, terminal, flow_control, false)
    }

    pub(crate) fn new_with_pipe(
        mut connection: Connection,
        terminal: &LocalStream,
        flow_control: Option<i32>,
        pipe_mode: bool,
    ) -> Result<Self, SessionError> {
        let queue_mode = queue_mode(flow_control);
        connection
            .minimize_output_buffering()
            .map_err(SessionError::Connection)?;
        let control = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        let reader = connection.reader_handle();
        let terminal_control = terminal.try_clone().map_err(SessionError::Io)?;
        let (wake_reader, wake_writer) = et_net::local::wake_pair().map_err(SessionError::Io)?;
        // A full wake channel already holds a pending wake; `signal` must not
        // block a producer while the bridge is not draining it.
        wake_writer
            .set_nonblocking(true)
            .map_err(SessionError::Io)?;
        Ok(Self {
            connection: Mutex::new(connection),
            reader: Mutex::new(reader),
            write_serial: Mutex::new(()),
            #[cfg(test)]
            prepared_write_hook: Mutex::new(None),
            control: Mutex::new(control),
            terminal_control: Mutex::new(terminal_control),
            wake_writer: Mutex::new(wake_writer),
            wake_reader: Mutex::new(Some(wake_reader)),
            recover_hold: Mutex::new(Vec::new()),
            recover_hold_bytes: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            torn_down: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            recover_admission: Mutex::new(()),
            #[cfg(test)]
            recover_admission_hook: Mutex::new(None),
            connection_generation: AtomicU64::new(0),
            flow_control: queue_mode.map(|mode| Arc::new(FlowControl::new(mode))),
            default_output: OnceLock::new(),
            #[cfg(windows)]
            flow_writer: Mutex::new(None),
            bridge_generation: Mutex::new(0),
            bridge_changed: Condvar::new(),
            pipe_mode,
            forward_exit_status: AtomicBool::new(false),
            disconnect_timeout: Mutex::new(None),
            disconnected_since: Mutex::new(None),
            kill_requested: AtomicBool::new(false),
        })
    }

    pub(crate) fn set_disconnect_timeout(&self, seconds: Option<i32>) {
        let timeout = seconds
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .map(Duration::from_secs);
        if let Ok(mut slot) = self.disconnect_timeout.lock() {
            *slot = timeout;
        }
    }

    pub(crate) fn request_kill(&self) {
        self.kill_requested.store(true, Ordering::Release);
    }

    pub(crate) fn kill_requested(&self) -> bool {
        self.kill_requested.load(Ordering::Acquire)
    }

    /// The router dropped this session's slot after its terminal hung up.
    /// Wakes the bridge so a session without a client stops waiting for one.
    pub(crate) fn detach(&self) {
        self.detached.store(true, Ordering::Release);
        let _ = self.signal();
    }

    /// Whether a detached session can end now: no client is connected and
    /// none is recovering, so nothing the bridge still holds can reach a
    /// client. Closes recover admission in the same step, so a handler that
    /// looked the session up before it was detached cannot start a recover
    /// that expects that output.
    pub(crate) fn retire_if_unreachable(&self) -> Result<bool, SessionError> {
        if !self.detached.load(Ordering::Acquire) {
            return Ok(false);
        }
        let _admission = self
            .recover_admission
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        // A finished recover installs its stream before it clears the flag.
        if self.recovering.load(Ordering::Acquire) || self.connection_state()?.0 {
            return Ok(false);
        }
        self.torn_down.store(true, Ordering::Release);
        Ok(true)
    }

    /// Upstream `disconnectDeadlineReached`: a non-positive timeout never
    /// fires, a connected client clears the stamp, and the first disconnected
    /// observation records `now` without firing.
    pub(crate) fn disconnect_deadline_reached(&self, connected: bool) -> bool {
        let Ok(timeout) = self.disconnect_timeout.lock() else {
            return false;
        };
        let Ok(mut since) = self.disconnected_since.lock() else {
            return false;
        };
        disconnect_deadline_reached(&mut since, Instant::now(), connected, *timeout)
    }

    /// When a disconnected client's timeout fires. Like
    /// [`Self::disconnect_deadline_reached`], the first disconnected
    /// observation starts the clock and a connected client clears it, so a
    /// loop that sleeps until this deadline cannot miss its first stamp.
    #[cfg(unix)]
    pub(crate) fn disconnect_deadline(&self, connected: bool) -> Option<Instant> {
        let timeout = (*self.disconnect_timeout.lock().ok()?).filter(|timeout| !timeout.is_zero());
        let mut since = self.disconnected_since.lock().ok()?;
        let (Some(timeout), false) = (timeout, connected) else {
            *since = None;
            return None;
        };
        since.get_or_insert_with(Instant::now).checked_add(timeout)
    }

    pub(crate) fn set_forward_exit_status(&self, enabled: bool) {
        self.forward_exit_status.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn forwards_exit_status(&self) -> bool {
        self.forward_exit_status.load(Ordering::Relaxed)
    }

    /// Stage terminal-bridge output in the flow queue from now on;
    /// bootstrap and control handshakes before this stay synchronous. The
    /// Unix bridge writes the queue from its own poll loop ([`OutputPump`]).
    #[cfg(unix)]
    pub(crate) fn start_output(&self) {
        self.staged_output();
    }

    /// Stage terminal-bridge output in the flow queue from now on. Windows
    /// cannot poll the client socket together with the bridge's other
    /// sources, so a writer thread owns blocking writes there.
    #[cfg(windows)]
    pub(crate) fn start_output(self: &Arc<Self>) {
        let state = Arc::clone(self.staged_output());
        let session = Arc::downgrade(self);
        let handle = std::thread::spawn(move || session_flow::run_writer(session, state));
        if let Ok(mut writer) = self.flow_writer.lock() {
            *writer = Some(handle);
        }
    }

    fn staged_output(&self) -> &Arc<FlowControl> {
        self.flow_control.as_ref().unwrap_or_else(|| {
            self.default_output
                .get_or_init(|| Arc::new(FlowControl::new_default()))
        })
    }

    fn output_flow(&self) -> Option<&Arc<FlowControl>> {
        self.flow_control
            .as_ref()
            .or_else(|| self.default_output.get())
    }

    #[cfg(test)]
    pub(crate) fn install_flow_enqueue_hook(&self, reached: std::sync::mpsc::SyncSender<()>) {
        self.flow_control
            .as_ref()
            .expect("test session must enable flow control")
            .install_enqueue_hook(reached);
    }

    #[cfg(test)]
    pub(crate) fn install_recover_admission_hook(
        &self,
        reached: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self.recover_admission_hook.lock().unwrap() = Some((reached, release));
    }

    pub(crate) fn send_packet(&self, header: u8, payload: &[u8]) -> Result<(), SessionError> {
        match self.send_packet_owned(header, payload) {
            Ok(()) => Ok(()),
            Err(SessionWriteError::BeforeReplay(SessionError::Connection(ConnError::Io(_)))) => {
                self.connection
                    .lock()
                    .map_err(|_| SessionError::Unavailable)?
                    .disconnect();
                self.send_packet_owned(header, payload)
                    .map_err(SessionWriteError::into_inner)
            }
            Err(error) => Err(error.into_inner()),
        }
    }

    pub(crate) fn send_packet_owned(
        &self,
        header: u8,
        payload: &[u8],
    ) -> Result<(), SessionWriteError> {
        self.send_packet_owned_with(header, payload, |connection, header, payload| {
            connection.write_packet_owned(header, payload)
        })
    }

    /// Terminal-bridge output. The bridge thread is the session's only
    /// transport reader, so once output starts, every packet it emits
    /// (forwarding and control included) is staged in the bounded queue; a
    /// synchronous write here would stall client input behind a peer that is
    /// not draining. Other callers keep `send_packet_owned` semantics:
    /// default sessions write non-terminal packets synchronously, so they
    /// enter the replay catch-up buffer in order while disconnected.
    pub(crate) fn send_bridge_packet_owned(
        &self,
        packet: Packet,
    ) -> Result<(), (Packet, SessionWriteError)> {
        if let Some(state) = self.output_flow() {
            // The Unix bridge writes the queue itself after enqueueing.
            #[cfg(unix)]
            let staged = state.enqueue_owned(packet);
            #[cfg(windows)]
            let staged = state.enqueue_bridge_owned(self, packet);
            return staged
                .map_err(|(packet, error)| (packet, SessionWriteError::BeforeReplay(error)));
        }
        match self.send_packet_owned(packet.header(), packet.payload()) {
            Ok(()) => Ok(()),
            Err(error) => Err((packet, error)),
        }
    }

    #[cfg(windows)]
    pub(crate) fn flush_bridge_outbound(&self) {
        if let Some(state) = self.output_flow() {
            state.flush_bridge_wake();
        }
    }

    fn send_packet_owned_with<W>(
        &self,
        header: u8,
        payload: &[u8],
        mut write: W,
    ) -> Result<(), SessionWriteError>
    where
        W: FnMut(&mut Connection, u8, &[u8]) -> Result<(), et_net::connection::WritePacketError>,
    {
        if let Some(state) = self.output_flow().filter(|_| {
            self.flow_control.is_some()
                || header == et_core::proto::TerminalPacketType::TerminalBuffer as u8
        }) {
            state
                .enqueue(Packet::new(header, payload))
                .map_err(SessionWriteError::BeforeReplay)?;
            // The Unix bridge writes queued output from its poll loop.
            #[cfg(unix)]
            let _ = self.signal();
            return Ok(());
        }
        // While a recover holds the single-flight permit, queue terminal
        // output instead of contending on the connection mutex for the
        // recovery network RTT. Flushed after the new stream is installed.
        if self
            .queue_if_recovering(header, payload)
            .map_err(SessionWriteError::BeforeReplay)?
        {
            return Ok(());
        }
        let _write_serial = self
            .write_serial
            .lock()
            .map_err(|_| SessionWriteError::BeforeReplay(SessionError::Unavailable))?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionWriteError::BeforeReplay(SessionError::Unavailable))?;
        // Recover may have started after the fast path check. Drop the
        // connection lock before taking `recover_hold` (flush takes hold
        // then connection — reverse order deadlocks).
        if self.recovering.load(Ordering::Acquire) {
            drop(connection);
            if self
                .queue_if_recovering(header, payload)
                .map_err(SessionWriteError::BeforeReplay)?
            {
                return Ok(());
            }
            connection = self
                .connection
                .lock()
                .map_err(|_| SessionWriteError::BeforeReplay(SessionError::Unavailable))?;
        }
        if let Some(finish) = connection.finish_pending_live_detached() {
            drop(connection);
            if let Err(error) = finish() {
                if let Ok(mut conn) = self.connection.lock() {
                    conn.disconnect();
                }
                return Err(match error {
                    et_net::connection::WritePacketError::BeforeReplay(err) => {
                        SessionWriteError::BeforeReplay(SessionError::Connection(err))
                    }
                    et_net::connection::WritePacketError::ReplayOwned(err) => {
                        SessionWriteError::ReplayOwned(SessionError::Connection(err))
                    }
                });
            }
            connection = self
                .connection
                .lock()
                .map_err(|_| SessionWriteError::BeforeReplay(SessionError::Unavailable))?;
        }
        write(&mut connection, header, payload).map_err(|error| match error {
            et_net::connection::WritePacketError::BeforeReplay(error) => {
                SessionWriteError::BeforeReplay(SessionError::Connection(error))
            }
            et_net::connection::WritePacketError::ReplayOwned(error) => {
                SessionWriteError::ReplayOwned(SessionError::Connection(error))
            }
        })
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

    pub(crate) fn finish_terminal(&self) -> Result<(), SessionError> {
        self.shutdown.store(true, Ordering::Release);
        let flow_result = self.stop_output(true);
        let _ = self.signal();
        let terminal = self
            .terminal_control
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let _ = terminal.shutdown(Shutdown::Both);
        drop(terminal);
        let control = self.control.lock().map_err(|_| SessionError::Unavailable)?;
        let control_result = if flow_result.is_err() {
            control.shutdown(Shutdown::Both)
        } else {
            control.shutdown(Shutdown::Write)
        };
        match control_result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Err(error) => return Err(SessionError::Io(error)),
        }
        drop(control);
        if let Err(error) = flow_result {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_| SessionError::Unavailable)?;
            let _ = connection.shutdown();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn shutdown(&self) -> Result<(), SessionError> {
        {
            let _admission = self
                .recover_admission
                .lock()
                .map_err(|_| SessionError::Unavailable)?;
            self.torn_down.store(true, Ordering::Release);
        }
        self.shutdown.store(true, Ordering::Release);
        self.stop_output(false)?;
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

    /// Stop output. A graceful stop delivers what is still queued first: on
    /// Unix on this thread, after the terminal bridge loop has exited; on
    /// Windows by joining the writer thread.
    fn stop_output(&self, graceful: bool) -> Result<(), SessionError> {
        if let Some(state) = self.output_flow() {
            if graceful {
                state.stop_gracefully();
                #[cfg(unix)]
                session_flow::write_until_stopped(self, state);
            } else {
                state.stop_hard();
            }
        }
        #[cfg(windows)]
        {
            let handle = self
                .flow_writer
                .lock()
                .map_err(|_| SessionError::Unavailable)?
                .take();
            if handle.is_some_and(|handle| handle.join().is_err()) {
                return Err(SessionError::Unavailable);
            }
        }
        if graceful
            && self
                .output_flow()
                .is_some_and(|state| state.unrecoverable())
        {
            return Err(SessionError::Connection(ConnError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "terminal ended before retained flow output could be delivered",
            ))));
        }
        Ok(())
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        if let Some(state) = self.output_flow() {
            state.stop_hard();
        }
    }
}

fn queue_mode(value: Option<i32>) -> Option<QueueMode> {
    match value.and_then(|value| et_core::proto::FlowControlMode::try_from(value).ok()) {
        None | Some(et_core::proto::FlowControlMode::None) => None,
        Some(et_core::proto::FlowControlMode::Backpressure) => Some(QueueMode::Backpressure),
        Some(et_core::proto::FlowControlMode::Discard) => Some(QueueMode::Discard),
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
            ActiveSession::new(Connection::new_server(stream, &[7; 32]), &terminal, None).unwrap();
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

    #[test]
    fn recover_refuses_to_revive_a_shutting_down_session() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (stream, _) = listener.accept().unwrap();
        let _peer = peer.join().unwrap();
        let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
        let session =
            ActiveSession::new(Connection::new_server(stream, &[7; 32]), &terminal, None).unwrap();

        // Terminal HUP sets `shutdown` so the bridge can drain; recover
        // must still be allowed until full session teardown.
        session.shutdown.store(true, Ordering::Release);
        let hup_permit = session.try_begin_recover().unwrap();
        drop(hup_permit);

        session.torn_down.store(true, Ordering::Release);
        assert!(matches!(
            session.try_begin_recover(),
            Err(SessionError::Unavailable)
        ));

        session.torn_down.store(false, Ordering::Release);
        let permit = session.try_begin_recover().unwrap();
        session.torn_down.store(true, Ordering::Release);
        let extra = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let extra_addr = extra.local_addr().unwrap();
        let extra_peer = std::thread::spawn(move || TcpStream::connect(extra_addr).unwrap());
        let (candidate, _) = extra.accept().unwrap();
        let _extra_peer = extra_peer.join().unwrap();
        assert!(matches!(
            permit.complete(candidate, PeerProof::Required),
            Err(SessionError::Unavailable)
        ));
        assert!(!session.recovering.load(Ordering::Acquire));
    }

    #[test]
    fn teardown_winning_during_recover_admission_rejects_and_releases_claim() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (stream, _) = listener.accept().unwrap();
        let _peer = peer.join().unwrap();
        let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
        let session = Arc::new(
            ActiveSession::new(Connection::new_server(stream, &[7; 32]), &terminal, None).unwrap(),
        );
        let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        session.install_recover_admission_hook(reached_tx, release_rx);

        std::thread::scope(|scope| {
            let recovering = Arc::clone(&session);
            let attempt = scope.spawn(move || {
                assert!(matches!(
                    recovering.try_begin_recover(),
                    Err(SessionError::Unavailable)
                ));
            });
            reached_rx.recv().unwrap();
            session.shutdown().unwrap();
            release_tx.send(()).unwrap();
            attempt.join().unwrap();
        });

        assert!(!session.recovering.load(Ordering::Acquire));
    }
}
