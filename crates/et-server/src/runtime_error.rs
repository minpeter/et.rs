use std::io;

use et_net::listener::ListenerError;

use crate::registry::RegistrationError;
use crate::router::RouterError;
use crate::session::SessionError;
use crate::session_table::SessionTableError;

#[derive(Debug)]
pub enum RuntimeError {
    Listener(ListenerError),
    Router(RouterError),
    Registration(RegistrationError),
    Session(SessionError),
    SessionTable(SessionTableError),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Spawn(io::Error),
    WorkerPanicked(&'static str),
    WorkerUnavailable,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listener(error) => write!(f, "TCP listener: {error}"),
            Self::Router(error) => write!(f, "terminal router: {error}"),
            Self::Registration(error) => write!(f, "registration: {error}"),
            Self::Session(error) => write!(f, "session: {error}"),
            Self::SessionTable(error) => write!(f, "session table: {error}"),
            Self::Io { operation, source } => write!(f, "{operation}: {source}"),
            Self::Spawn(error) => write!(f, "could not start server worker: {error}"),
            Self::WorkerPanicked(worker) => write!(f, "{worker} worker panicked"),
            Self::WorkerUnavailable => write!(f, "server worker registry is unavailable"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            Self::Router(error) => Some(error),
            Self::Registration(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::SessionTable(error) => Some(error),
            Self::Io { source, .. } | Self::Spawn(source) => Some(source),
            Self::WorkerPanicked(_) | Self::WorkerUnavailable => None,
        }
    }
}

impl From<ListenerError> for RuntimeError {
    fn from(error: ListenerError) -> Self {
        Self::Listener(error)
    }
}

impl From<RouterError> for RuntimeError {
    fn from(error: RouterError) -> Self {
        Self::Router(error)
    }
}

impl From<RegistrationError> for RuntimeError {
    fn from(error: RegistrationError) -> Self {
        Self::Registration(error)
    }
}

impl From<SessionError> for RuntimeError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<SessionTableError> for RuntimeError {
    fn from(error: SessionTableError) -> Self {
        Self::SessionTable(error)
    }
}
