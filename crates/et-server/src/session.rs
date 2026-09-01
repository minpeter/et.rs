use et_net::local::LocalStream;
use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use et_core::backed_writer::{
    MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS, MAX_RECOVERY_BACKUP_BYTES,
};
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
    recover_hold_bytes: AtomicU64,
    shutdown: AtomicBool,
    /// Only one recover may run at a time. Concurrent returning clients used
    /// to queue on the connection mutex for minutes after a blackhole write.
    recovering: AtomicBool,
    connection_generation: AtomicU64,
    flow_control: Option<Arc<FlowControl>>,
    flow_writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    bridge_generation: Mutex<u64>,
    bridge_changed: Condvar,
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
        mut connection: Connection,
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
            recover_hold_bytes: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            connection_generation: AtomicU64::new(0),
            flow_control: queue_mode.map(|mode| Arc::new(FlowControl::new(mode))),
            flow_writer: Mutex::new(None),
            bridge_generation: Mutex::new(0),
            bridge_changed: Condvar::new(),
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

    #[cfg(test)]
    pub(crate) fn install_flow_enqueue_hook(&self, reached: std::sync::mpsc::SyncSender<()>) {
        self.flow_control
            .as_ref()
            .expect("test session must enable flow control")
            .install_enqueue_hook(reached);
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

    fn send_packet_owned_with<W>(
        &self,
        header: u8,
        payload: &[u8],
        mut write: W,
    ) -> Result<(), SessionWriteError>
    where
        W: FnMut(&mut Connection, u8, &[u8]) -> Result<(), et_net::connection::WritePacketError>,
    {
        if let Some(state) = &self.flow_control {
            return state
                .enqueue(Packet::new(header, payload))
                .map_err(SessionWriteError::BeforeReplay);
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
        let flow_result = self.join_flow_writer(true);
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
        if graceful
            && self
                .flow_control
                .as_ref()
                .is_some_and(|state| state.unrecoverable())
        {
            return Err(SessionError::Connection(ConnError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "terminal ended before retained flow output could be delivered",
            ))));
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
}
