use std::net::TcpStream;
use std::sync::Mutex;

use et_net::connection::{ConnError, Connection};

pub(crate) struct ActiveSession {
    connection: Mutex<Connection>,
}

#[derive(Debug)]
pub enum SessionError {
    Connection(ConnError),
    Unavailable,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(f, "session connection: {error}"),
            Self::Unavailable => write!(f, "session is unavailable"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Unavailable => None,
        }
    }
}

impl ActiveSession {
    pub(crate) fn new(connection: Connection) -> Self {
        Self {
            connection: Mutex::new(connection),
        }
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
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        connection.recover(stream).map_err(SessionError::Connection)
    }

    pub(crate) fn shutdown(&self) -> Result<(), SessionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        connection.shutdown().map_err(SessionError::Connection)
    }
}
