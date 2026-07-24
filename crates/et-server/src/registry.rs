//! Synchronized terminal registration state.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use et_core::crypto::KEY_LEN;
use et_core::keys::passkey_to_key;
use et_core::proto::TerminalUserInfo;

const ID_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub id: String,
    pub key: [u8; KEY_LEN],
    pub uid: u32,
    pub gid: u32,
}

struct StoredRegistration {
    info: Registration,
    _stream: UnixStream,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    Invalid,
    Duplicate,
    Unavailable,
    Timeout,
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "terminal registration is invalid"),
            Self::Duplicate => write!(f, "terminal id is already registered"),
            Self::Unavailable => write!(f, "terminal registry is unavailable"),
            Self::Timeout => write!(f, "timed out waiting for terminal registration"),
        }
    }
}

impl std::error::Error for RegistrationError {}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        user_info: TerminalUserInfo,
        stream: UnixStream,
    ) -> Result<String, RegistrationError> {
        let registration = validate(user_info)?;
        let id = registration.id.clone();
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)?;
        match state.registrations.entry(id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(StoredRegistration {
                    info: registration,
                    _stream: stream,
                });
                self.inner.changed.notify_all();
                Ok(id)
            }
            Entry::Occupied(_) => Err(RegistrationError::Duplicate),
        }
    }

    pub fn get(&self, id: &str) -> Result<Option<Registration>, RegistrationError> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)?;
        Ok(state
            .registrations
            .get(id)
            .map(|stored| stored.info.clone()))
    }

    pub fn wait_for(&self, id: &str, timeout: Duration) -> Result<Registration, RegistrationError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(RegistrationError::Timeout)?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)?;
        loop {
            if let Some(stored) = state.registrations.get(id) {
                return Ok(stored.info.clone());
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(RegistrationError::Timeout);
            };
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| RegistrationError::Unavailable)?;
            state = next;
            if wait.timed_out() && !state.registrations.contains_key(id) {
                return Err(RegistrationError::Timeout);
            }
        }
    }

    pub fn len(&self) -> Result<usize, RegistrationError> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| RegistrationError::Unavailable)?;
        Ok(state.registrations.len())
    }

    pub fn is_empty(&self) -> Result<bool, RegistrationError> {
        self.len().map(|length| length == 0)
    }
}

fn validate(user_info: TerminalUserInfo) -> Result<Registration, RegistrationError> {
    let id = user_info.id.ok_or(RegistrationError::Invalid)?;
    if id.len() != ID_LEN || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(RegistrationError::Invalid);
    }
    let passkey = user_info.passkey.ok_or(RegistrationError::Invalid)?;
    let key = passkey_to_key(&passkey).ok_or(RegistrationError::Invalid)?;
    let uid = user_info
        .uid
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RegistrationError::Invalid)?;
    let gid = user_info
        .gid
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RegistrationError::Invalid)?;
    Ok(Registration { id, key, uid, gid })
}
