use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::registry::Registration;
use crate::session::ActiveSession;

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
    Timeout,
    InvalidTransition,
}

impl std::fmt::Display for SessionTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "session table is unavailable"),
            Self::ShuttingDown => write!(f, "session table is shutting down"),
            Self::Timeout => write!(f, "timed out waiting for session state"),
            Self::InvalidTransition => write!(f, "invalid session state transition"),
        }
    }
}

impl std::error::Error for SessionTableError {}

enum Slot {
    Registered(Registration),
    Starting(Registration),
    Active(Arc<ActiveSession>),
}

#[derive(Default)]
struct TableState {
    slots: HashMap<String, Slot>,
    shutdown: bool,
}

#[derive(Default)]
struct TableInner {
    state: Mutex<TableState>,
    changed: Condvar,
}

#[derive(Clone, Default)]
pub struct SessionTable {
    inner: Arc<TableInner>,
}

pub(crate) enum SessionClaim {
    New(SessionStart),
    Returning(Arc<ActiveSession>),
}

pub(crate) struct SessionStart {
    table: SessionTable,
    registration: Registration,
    committed: bool,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn claim(
        &self,
        registration: Registration,
    ) -> Result<SessionClaim, SessionTableError> {
        let id = registration.id.clone();
        let mut state = self.lock()?;
        loop {
            if state.shutdown {
                return Err(SessionTableError::ShuttingDown);
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
                    state
                        .slots
                        .insert(id.clone(), Slot::Starting(stored.clone()));
                    self.inner.changed.notify_all();
                    return Ok(SessionClaim::New(SessionStart {
                        table: self.clone(),
                        registration: stored,
                        committed: false,
                    }));
                }
                Some(Slot::Starting(_)) => {
                    state = self
                        .inner
                        .changed
                        .wait(state)
                        .map_err(|_| SessionTableError::Unavailable)?;
                }
                Some(Slot::Active(session)) => {
                    return Ok(SessionClaim::Returning(session.clone()));
                }
            }
        }
    }

    pub fn state(&self, id: &str) -> Result<Option<SessionState>, SessionTableError> {
        let state = self.lock()?;
        Ok(state.slots.get(id).map(slot_state))
    }

    pub(crate) fn active(&self, id: &str) -> Result<Option<Arc<ActiveSession>>, SessionTableError> {
        let state = self.lock()?;
        Ok(match state.slots.get(id) {
            Some(Slot::Active(session)) => Some(session.clone()),
            _ => None,
        })
    }

    pub fn wait_for_state(
        &self,
        id: &str,
        expected: SessionState,
        timeout: Duration,
    ) -> Result<(), SessionTableError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(SessionTableError::Timeout)?;
        let mut state = self.lock()?;
        loop {
            if state.slots.get(id).map(slot_state) == Some(expected) {
                return Ok(());
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(SessionTableError::Timeout);
            };
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| SessionTableError::Unavailable)?;
            state = next;
            if wait.timed_out() && state.slots.get(id).map(slot_state) != Some(expected) {
                return Err(SessionTableError::Timeout);
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) -> Result<Vec<Arc<ActiveSession>>, SessionTableError> {
        let mut state = self.lock()?;
        state.shutdown = true;
        let sessions = state
            .slots
            .values()
            .filter_map(|slot| match slot {
                Slot::Active(session) => Some(session.clone()),
                _ => None,
            })
            .collect();
        self.inner.changed.notify_all();
        Ok(sessions)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, TableState>, SessionTableError> {
        self.inner
            .state
            .lock()
            .map_err(|_| SessionTableError::Unavailable)
    }
}

impl SessionStart {
    pub(crate) fn registration(&self) -> &Registration {
        &self.registration
    }

    pub(crate) fn activate(mut self, session: ActiveSession) -> Result<(), SessionTableError> {
        let mut state = self.table.lock()?;
        if state.shutdown {
            return Err(SessionTableError::ShuttingDown);
        }
        match state.slots.get(&self.registration.id) {
            Some(Slot::Starting(starting)) if starting.id == self.registration.id => {
                state.slots.insert(
                    self.registration.id.clone(),
                    Slot::Active(Arc::new(session)),
                );
                self.committed = true;
                self.table.inner.changed.notify_all();
                Ok(())
            }
            _ => Err(SessionTableError::InvalidTransition),
        }
    }
}

impl Drop for SessionStart {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(mut state) = self.table.inner.state.lock() {
            if matches!(
                state.slots.get(&self.registration.id),
                Some(Slot::Starting(_))
            ) {
                state.slots.insert(
                    self.registration.id.clone(),
                    Slot::Registered(self.registration.clone()),
                );
                self.table.inner.changed.notify_all();
            }
        }
    }
}

fn slot_state(slot: &Slot) -> SessionState {
    match slot {
        Slot::Registered(_) => SessionState::Registered,
        Slot::Starting(_) => SessionState::Starting,
        Slot::Active(_) => SessionState::Active,
    }
}
