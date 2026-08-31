use std::time::{Duration, Instant};

use crate::session_slot::Slot;
use crate::session_table::{SessionState, SessionTable, SessionTableError};

impl SessionTable {
    pub fn wait_for_state(
        &self,
        id: &str,
        expected: SessionState,
        timeout: Duration,
    ) -> Result<(), SessionTableError> {
        self.wait_for(id, Some(expected), timeout)
    }

    pub fn wait_until_absent(&self, id: &str, timeout: Duration) -> Result<(), SessionTableError> {
        let deadline = deadline(timeout)?;
        let mut state = self.lock()?;
        loop {
            if !state.slots.contains_key(id) {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(SessionTableError::Timeout)?;
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| SessionTableError::Unavailable)?;
            state = next;
            if wait.timed_out() && state.slots.contains_key(id) {
                return Err(SessionTableError::Timeout);
            }
        }
    }

    fn wait_for(
        &self,
        id: &str,
        expected: Option<SessionState>,
        timeout: Duration,
    ) -> Result<(), SessionTableError> {
        let deadline = deadline(timeout)?;
        let mut state = self.lock()?;
        loop {
            if state.slots.get(id).map(Slot::state) == expected {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(SessionTableError::Timeout)?;
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| SessionTableError::Unavailable)?;
            state = next;
            if wait.timed_out() && state.slots.get(id).map(Slot::state) != expected {
                return Err(SessionTableError::Timeout);
            }
        }
    }
}

fn deadline(timeout: Duration) -> Result<Instant, SessionTableError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(SessionTableError::Timeout)
}
