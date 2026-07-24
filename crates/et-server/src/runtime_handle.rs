use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::registry::{Registration, RegistrationError};
use crate::runtime_state::RuntimeCore;
use crate::session::SessionError;
use crate::session_table::{SessionState, SessionTableError};

#[derive(Clone)]
pub struct RuntimeHandle {
    pub(crate) core: Arc<RuntimeCore>,
}

#[derive(Debug)]
pub enum HandleError {
    Registration(RegistrationError),
    Session(SessionError),
    SessionTable(SessionTableError),
    NotActive(String),
    ShuttingDown,
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(error) => write!(f, "registration: {error}"),
            Self::Session(error) => write!(f, "session: {error}"),
            Self::SessionTable(error) => write!(f, "session table: {error}"),
            Self::NotActive(id) => write!(f, "session {id} is not active"),
            Self::ShuttingDown => write!(f, "server runtime is shutting down"),
        }
    }
}

impl std::error::Error for HandleError {}

impl RuntimeHandle {
    pub fn send_packet(&self, id: &str, header: u8, payload: &[u8]) -> Result<(), HandleError> {
        if self.core.shutdown.load(Ordering::Acquire) {
            return Err(HandleError::ShuttingDown);
        }
        let session = self
            .core
            .sessions
            .active(id)
            .map_err(HandleError::SessionTable)?
            .ok_or_else(|| HandleError::NotActive(id.to_owned()))?;
        session
            .send_packet(header, payload)
            .map_err(HandleError::Session)
    }

    pub fn session_state(&self, id: &str) -> Result<Option<SessionState>, HandleError> {
        self.core
            .sessions
            .state(id)
            .map_err(HandleError::SessionTable)
    }

    pub fn wait_for_state(
        &self,
        id: &str,
        state: SessionState,
        timeout: Duration,
    ) -> Result<(), HandleError> {
        self.core
            .sessions
            .wait_for_state(id, state, timeout)
            .map_err(HandleError::SessionTable)
    }

    pub fn wait_registered(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<Registration, HandleError> {
        self.core
            .registry
            .wait_for(id, timeout)
            .map_err(HandleError::Registration)
    }

    pub fn wait_disconnected(&self, id: &str, timeout: Duration) -> Result<(), HandleError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HandleError::Registration(RegistrationError::Timeout))?;
        self.core
            .registry
            .wait_until_absent(id, timeout)
            .map_err(HandleError::Registration)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(HandleError::SessionTable(SessionTableError::Timeout))?;
        self.core
            .sessions
            .wait_until_absent(id, remaining)
            .map_err(HandleError::SessionTable)
    }
}
