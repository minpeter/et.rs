use std::net::TcpStream;
use std::sync::Arc;

use crate::registry::Registration;
use crate::session::{ActiveSession, SessionConnection};
use crate::session_table::{SessionState, SessionTable, SessionTableError};

pub(crate) enum Slot {
    Registered(Registration),
    Starting {
        registration: Registration,
        socket: TcpStream,
    },
    Active {
        registration: Registration,
        session: Arc<ActiveSession>,
    },
}

pub(crate) struct SessionStart {
    pub(crate) table: SessionTable,
    pub(crate) registration: Registration,
    pub(crate) committed: bool,
}

impl SessionStart {
    pub(crate) fn registration(&self) -> &Registration {
        &self.registration
    }

    pub(crate) fn activate(mut self, session: Arc<ActiveSession>) -> Result<(), SessionTableError> {
        let mut state = self.table.lock()?;
        if state.shutdown {
            return Err(SessionTableError::ShuttingDown);
        }
        let valid = state.slots.get(&self.registration.id).is_some_and(|slot| {
            matches!(slot, Slot::Starting { .. })
                && slot.registration().same_generation(&self.registration)
        });
        if !valid {
            return Err(SessionTableError::InvalidTransition);
        }
        state.slots.insert(
            self.registration.id.clone(),
            Slot::Active {
                registration: self.registration.clone(),
                session,
            },
        );
        self.committed = true;
        self.table.inner.changed.notify_all();
        Ok(())
    }
}

impl Drop for SessionStart {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(mut state) = self.table.inner.state.lock() {
            let valid = state.slots.get(&self.registration.id).is_some_and(|slot| {
                matches!(slot, Slot::Starting { .. })
                    && slot.registration().same_generation(&self.registration)
            });
            if valid {
                state.slots.insert(
                    self.registration.id.clone(),
                    Slot::Registered(self.registration.clone()),
                );
                self.table.inner.changed.notify_all();
            }
        }
    }
}

impl Slot {
    pub(crate) fn registration(&self) -> &Registration {
        match self {
            Self::Registered(registration)
            | Self::Starting { registration, .. }
            | Self::Active { registration, .. } => registration,
        }
    }

    pub(crate) fn into_connection(self) -> Option<SessionConnection> {
        match self {
            Self::Registered(_) => None,
            Self::Starting { socket, .. } => Some(SessionConnection::Starting(socket)),
            Self::Active { session, .. } => Some(SessionConnection::Active(session)),
        }
    }

    pub(crate) fn state(&self) -> SessionState {
        match self {
            Self::Registered(_) => SessionState::Registered,
            Self::Starting { .. } => SessionState::Starting,
            Self::Active { .. } => SessionState::Active,
        }
    }
}
