//! Synchronized terminal registration state.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use et_core::crypto::KEY_LEN;
use et_core::proto::TerminalUserInfo;

use crate::registry_validation::validate;

#[derive(Clone, Debug)]
pub struct Registration {
    pub id: String,
    pub key: [u8; KEY_LEN],
    pub uid: u32,
    pub gid: u32,
    pub(crate) identity: Arc<()>,
}

impl PartialEq for Registration {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.key == other.key
            && self.uid == other.uid
            && self.gid == other.gid
    }
}

impl Eq for Registration {}

#[derive(Clone, Debug)]
pub(crate) struct RegistrationIdentity {
    id: String,
    identity: Arc<()>,
}

pub(crate) struct RegisteredTerminal {
    pub(crate) identity: RegistrationIdentity,
    pub(crate) watcher: UnixStream,
}

struct StoredRegistration {
    info: Registration,
    stream: UnixStream,
}

#[derive(Default)]
struct RegistryState {
    registrations: HashMap<String, StoredRegistration>,
}

#[derive(Default)]
struct RegistryInner {
    state: Mutex<RegistryState>,
    changed: Condvar,
}

#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RegistryInner>,
}

#[derive(Debug)]
pub enum RegistrationError {
    Invalid,
    Duplicate,
    Unavailable,
    Timeout,
    Io(io::Error),
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "terminal registration is invalid"),
            Self::Duplicate => write!(f, "terminal id is already registered"),
            Self::Unavailable => write!(f, "terminal registry is unavailable"),
            Self::Timeout => write!(f, "timed out waiting for terminal registration"),
            Self::Io(error) => write!(f, "terminal registration stream: {error}"),
        }
    }
}

impl std::error::Error for RegistrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(
        &self,
        user_info: TerminalUserInfo,
        stream: UnixStream,
    ) -> Result<RegisteredTerminal, RegistrationError> {
        let registration = validate(user_info)?;
        let watcher = stream.try_clone().map_err(RegistrationError::Io)?;
        let identity = registration.identity();
        let mut state = self.lock()?;
        match state.registrations.entry(registration.id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(StoredRegistration {
                    info: registration,
                    stream,
                });
                self.inner.changed.notify_all();
                Ok(RegisteredTerminal { identity, watcher })
            }
            Entry::Occupied(_) => Err(RegistrationError::Duplicate),
        }
    }

    pub(crate) fn remove_if_current(
        &self,
        identity: &RegistrationIdentity,
    ) -> Result<bool, RegistrationError> {
        let mut state = self.lock()?;
        let matches = state
            .registrations
            .get(identity.id())
            .is_some_and(|stored| identity.matches(&stored.info));
        if matches {
            state.registrations.remove(identity.id());
            self.inner.changed.notify_all();
        }
        Ok(matches)
    }

    pub(crate) fn contains(
        &self,
        identity: &RegistrationIdentity,
    ) -> Result<bool, RegistrationError> {
        let state = self.lock()?;
        Ok(state
            .registrations
            .get(identity.id())
            .is_some_and(|stored| identity.matches(&stored.info)))
    }

    pub(crate) fn clear(&self) -> Result<(), RegistrationError> {
        let mut state = self.lock()?;
        state.registrations.clear();
        self.inner.changed.notify_all();
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<Registration>, RegistrationError> {
        let state = self.lock()?;
        Ok(state
            .registrations
            .get(id)
            .map(|stored| stored.info.clone()))
    }

    pub(crate) fn clone_stream(
        &self,
        registration: &Registration,
    ) -> Result<UnixStream, RegistrationError> {
        let registrations = self
            .inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)?;
        let stored = registrations
            .registrations
            .get(&registration.id)
            .filter(|stored| stored.info.same_generation(registration))
            .ok_or(RegistrationError::Unavailable)?;
        stored.stream.try_clone().map_err(RegistrationError::Io)
    }

    pub fn wait_for(&self, id: &str, timeout: Duration) -> Result<Registration, RegistrationError> {
        self.wait_for_condition(id, timeout, true)?
            .ok_or(RegistrationError::Timeout)
    }

    pub fn wait_until_absent(&self, id: &str, timeout: Duration) -> Result<(), RegistrationError> {
        self.wait_for_condition(id, timeout, false).map(|_| ())
    }

    pub fn len(&self) -> Result<usize, RegistrationError> {
        Ok(self.lock()?.registrations.len())
    }

    pub fn is_empty(&self) -> Result<bool, RegistrationError> {
        self.len().map(|length| length == 0)
    }

    fn wait_for_condition(
        &self,
        id: &str,
        timeout: Duration,
        present: bool,
    ) -> Result<Option<Registration>, RegistrationError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(RegistrationError::Timeout)?;
        let mut state = self.lock()?;
        loop {
            let registration = state
                .registrations
                .get(id)
                .map(|stored| stored.info.clone());
            if registration.is_some() == present {
                return Ok(registration);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(RegistrationError::Timeout)?;
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| RegistrationError::Unavailable)?;
            state = next;
            if wait.timed_out() {
                let exists = state.registrations.contains_key(id);
                if exists != present {
                    return Err(RegistrationError::Timeout);
                }
            }
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RegistryState>, RegistrationError> {
        self.inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)
    }
}

impl Registration {
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.identity, &other.identity)
    }

    pub(crate) fn identity(&self) -> RegistrationIdentity {
        RegistrationIdentity {
            id: self.id.clone(),
            identity: self.identity.clone(),
        }
    }
}

impl RegistrationIdentity {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn matches(&self, registration: &Registration) -> bool {
        self.id == registration.id && Arc::ptr_eq(&self.identity, &registration.identity)
    }

    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.identity, &other.identity)
    }
}
