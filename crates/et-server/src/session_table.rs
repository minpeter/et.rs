use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex};

use crate::registry::{Registration, RegistrationIdentity, Registry};
use crate::session::{ActiveSession, SessionConnection};
use crate::session_slot::{SessionStart, Slot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Registered,
    Starting,
    Active,
}

#[derive(Debug)]
pub enum SessionTableError {
    Unavailable,
    ShuttingDown,
    ObsoleteRegistration,
    Timeout,
    InvalidTransition,
    Io(io::Error),
}

impl std::fmt::Display for SessionTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "session table is unavailable"),
            Self::ShuttingDown => write!(f, "session table is shutting down"),
            Self::ObsoleteRegistration => write!(f, "terminal registration is obsolete"),
            Self::Timeout => write!(f, "timed out waiting for session state"),
            Self::InvalidTransition => write!(f, "invalid session state transition"),
            Self::Io(error) => write!(f, "session socket: {error}"),
        }
    }
}

impl std::error::Error for SessionTableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(crate) struct TableState {
    pub(crate) slots: HashMap<String, Slot>,
    #[cfg(test)]
    pub(crate) claim_waiters: HashMap<String, usize>,
    pub(crate) shutdown: bool,
}

#[derive(Default)]
pub(crate) struct TableInner {
    pub(crate) state: Mutex<TableState>,
    pub(crate) changed: Condvar,
}

#[derive(Clone, Default)]
pub struct SessionTable {
    pub(crate) inner: Arc<TableInner>,
}

pub(crate) struct RemovedRegistration {
    pub(crate) connection: Option<SessionConnection>,
}

pub(crate) enum SessionClaim {
    New {
        start: SessionStart,
        replaced: Option<SessionConnection>,
    },
    Returning(Arc<ActiveSession>),
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn claim(
        &self,
        registration: Registration,
        stream: &TcpStream,
        registry: &Registry,
    ) -> Result<SessionClaim, SessionTableError> {
        let id = registration.id.clone();
        let identity = registration.identity();
        let mut starting_socket = Some(stream.try_clone().map_err(SessionTableError::Io)?);
        let mut replaced = None;
        let mut state = self.lock()?;
        loop {
            if state.shutdown {
                return Err(SessionTableError::ShuttingDown);
            }
            if !registry
                .contains(&identity)
                .map_err(|_| SessionTableError::Unavailable)?
            {
                return Err(SessionTableError::ObsoleteRegistration);
            }
            if state
                .slots
                .get(&id)
                .is_some_and(|slot| !slot.registration().same_generation(&registration))
            {
                replaced = state.slots.remove(&id).and_then(Slot::into_connection);
                state
                    .slots
                    .insert(id.clone(), Slot::Registered(registration.clone()));
                self.inner.changed.notify_all();
                continue;
            }
            match state.slots.get(&id) {
                None => {
                    state
                        .slots
                        .insert(id.clone(), Slot::Registered(registration.clone()));
                    self.inner.changed.notify_all();
                }
                Some(Slot::Registered(stored)) => {
                    let stored = stored.clone();
                    let socket = starting_socket
                        .take()
                        .ok_or(SessionTableError::InvalidTransition)?;
                    state.slots.insert(
                        id.clone(),
                        Slot::Starting {
                            registration: stored.clone(),
                            socket,
                        },
                    );
                    self.inner.changed.notify_all();
                    return Ok(SessionClaim::New {
                        start: SessionStart {
                            table: self.clone(),
                            registration: stored,
                            committed: false,
                        },
                        replaced,
                    });
                }
                Some(Slot::Starting { .. }) => {
                    #[cfg(test)]
                    {
                        *state.claim_waiters.entry(id.clone()).or_default() += 1;
                        self.inner.changed.notify_all();
                    }
                    state = self
                        .inner
                        .changed
                        .wait(state)
                        .map_err(|_| SessionTableError::Unavailable)?;
                    #[cfg(test)]
                    {
                        let remove = state.claim_waiters.get_mut(&id).is_some_and(|waiters| {
                            *waiters -= 1;
                            *waiters == 0
                        });
                        if remove {
                            state.claim_waiters.remove(&id);
                        }
                        self.inner.changed.notify_all();
                    }
                }
                Some(Slot::Active { session, .. }) => {
                    return Ok(SessionClaim::Returning(session.clone()));
                }
            }
        }
    }

    pub fn state(&self, id: &str) -> Result<Option<SessionState>, SessionTableError> {
        Ok(self.lock()?.slots.get(id).map(Slot::state))
    }

    pub(crate) fn active(&self, id: &str) -> Result<Option<Arc<ActiveSession>>, SessionTableError> {
        Ok(match self.lock()?.slots.get(id) {
            Some(Slot::Active { session, .. }) => Some(session.clone()),
            _ => None,
        })
    }

    pub(crate) fn remove_registration(
        &self,
        identity: &RegistrationIdentity,
    ) -> Result<Option<RemovedRegistration>, SessionTableError> {
        let mut state = self.lock()?;
        let matches = state
            .slots
            .get(identity.id())
            .is_some_and(|slot| identity.matches(slot.registration()));
        if !matches {
            return Ok(None);
        }
        let connection = state
            .slots
            .remove(identity.id())
            .and_then(Slot::into_connection);
        self.inner.changed.notify_all();
        Ok(Some(RemovedRegistration { connection }))
    }

    pub(crate) fn begin_shutdown(&self) -> Result<Vec<SessionConnection>, SessionTableError> {
        let mut state = self.lock()?;
        state.shutdown = true;
        let connections = std::mem::take(&mut state.slots)
            .into_values()
            .filter_map(Slot::into_connection)
            .collect();
        self.inner.changed.notify_all();
        Ok(connections)
    }

    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, TableState>, SessionTableError> {
        self.inner
            .state
            .lock()
            .map_err(|_| SessionTableError::Unavailable)
    }
}
