use et_net::local::LocalStream;
use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use et_core::flow_control::FlowControlMode as QueueMode;
use et_core::packet::Packet;
use et_net::connection::{ConnError, Connection};

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
const FLOW_CONTROL_LOCAL_BUFFER_BYTES: usize = 64 * 1024;

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
    flow_control: Option<Arc<FlowControl>>,
    flow_writer: Mutex<Option<std::thread::JoinHandle<()>>>,
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
        mut connection: Connection,
        terminal: &LocalStream,
        flow_control: Option<i32>,
    ) -> Result<Self, SessionError> {
        let queue_mode = queue_mode(flow_control);
        if queue_mode.is_some() {
            connection
                .minimize_output_buffering()
                .map_err(SessionError::Connection)?;
            et_net::local::set_receive_buffer_size(terminal, FLOW_CONTROL_LOCAL_BUFFER_BYTES)
                .map_err(SessionError::Io)?;
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
            flow_control: queue_mode.map(|mode| Arc::new(FlowControl::new(mode))),
            flow_writer: Mutex::new(None),
        })
    }

    pub(crate) fn start_flow_writer(self: &Arc<Self>) {
        let Some(state) = self.flow_control.clone() else {
            return;
        };
        let session = Arc::downgrade(self);
        let handle = std::thread::spawn(move || session_flow::run_writer(session, state));
        if let Ok(mut writer) = self.flow_writer.lock() {
            *writer = Some(handle);
        }
    }

    pub(crate) fn send_packet(&self, header: u8, payload: &[u8]) -> Result<(), SessionError> {
        if let Some(state) = &self.flow_control {
            return state.enqueue(Packet::new(header, payload));
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

    pub(crate) fn finish_terminal(&self) -> Result<(), SessionError> {
        self.shutdown.store(true, Ordering::Release);
        self.join_flow_writer(true)?;
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
        self.join_flow_writer(false)?;
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

    fn join_flow_writer(&self, graceful: bool) -> Result<(), SessionError> {
        if let Some(state) = &self.flow_control {
            if graceful {
                state.stop_gracefully();
            } else {
                state.stop_hard();
            }
        }
        let handle = self
            .flow_writer
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .take();
        if handle.is_some_and(|handle| handle.join().is_err()) {
            return Err(SessionError::Unavailable);
        }
        Ok(())
    }

    fn stop_flow_writer(&self) {
        if let Some(state) = &self.flow_control {
            state.stop_hard();
        }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.stop_flow_writer();
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
