use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use et_core::proto::TerminalPacketType;
use et_net::connection::DEFAULT_RECOVERY_TIMEOUT;
use et_net::connection::{ConnError, Connection};

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
    control: Mutex<TcpStream>,
    terminal_control: Mutex<UnixStream>,
    wake_writer: Mutex<UnixStream>,
    wake_reader: Mutex<Option<UnixStream>>,
    shutdown: AtomicBool,
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
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(f, "session connection: {error}"),
            Self::Io(error) => write!(f, "session socket: {error}"),
            Self::Unavailable => write!(f, "session is unavailable"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Unavailable => None,
        }
    }
}

impl ActiveSession {
    pub(crate) fn new(connection: Connection, terminal: &UnixStream) -> Result<Self, SessionError> {
        let control = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        let terminal_control = terminal.try_clone().map_err(SessionError::Io)?;
        let (wake_reader, wake_writer) = UnixStream::pair().map_err(SessionError::Io)?;
        Ok(Self {
            connection: Mutex::new(connection),
            control: Mutex::new(control),
            terminal_control: Mutex::new(terminal_control),
            wake_writer: Mutex::new(wake_writer),
            wake_reader: Mutex::new(Some(wake_reader)),
            shutdown: AtomicBool::new(false),
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

    pub(crate) fn recover(&self, stream: TcpStream) -> Result<(), SessionError> {
        let mut control = self.control.lock().map_err(|_| SessionError::Unavailable)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let mut candidate = connection
            .recovery_candidate(stream, DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        let proof = candidate
            .authenticate_peer(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        if proof.header() != TerminalPacketType::KeepAlive as u8 || !proof.payload().is_empty() {
            return Err(SessionError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "returning client sent an invalid recovery proof",
            )));
        }
        candidate
            .write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .map_err(SessionError::Connection)?;
        let new_control = candidate
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        let old_control = std::mem::replace(&mut *control, new_control);
        let _ = old_control.shutdown(Shutdown::Both);
        *connection = candidate;
        drop(connection);
        drop(control);
        self.signal()
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

    pub(crate) fn take_wake_reader(&self) -> Result<UnixStream, SessionError> {
        self.wake_reader
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .take()
            .ok_or(SessionError::Unavailable)
    }

    pub(crate) fn try_clone_stream(&self) -> Result<TcpStream, SessionError> {
        self.connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .try_clone_stream()
            .map_err(SessionError::Connection)
    }

    pub(crate) fn try_read_packet(&self) -> Result<Option<et_core::packet::Packet>, SessionError> {
        self.connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .try_read_packet()
            .map_err(SessionError::Connection)
    }

    pub(crate) fn connected(&self) -> Result<bool, SessionError> {
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .connected())
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
