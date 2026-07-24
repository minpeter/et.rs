use std::io;
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};

use et_net::connection::{ConnError, Connection};

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
    control: Mutex<TcpStream>,
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
    pub(crate) fn new(connection: Connection) -> Result<Self, SessionError> {
        let control = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            control: Mutex::new(control),
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
        let new_control = stream.try_clone().map_err(SessionError::Io)?;
        {
            let mut control = self.control.lock().map_err(|_| SessionError::Unavailable)?;
            let old_control = std::mem::replace(&mut *control, new_control);
            let _ = old_control.shutdown(Shutdown::Both);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        connection.recover(stream).map_err(SessionError::Connection)
    }

    pub(crate) fn shutdown(&self) -> Result<(), SessionError> {
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
