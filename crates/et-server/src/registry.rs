//! Synchronized terminal registration state.

use et_net::local::LocalStream;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use et_core::crypto::KEY_LEN;
use et_core::proto::TerminalUserInfo;

use crate::registry_validation::{validate, PeerIdentity};

#[derive(Clone, Debug)]
pub struct Registration {
    pub id: String,
    pub key: [u8; KEY_LEN],
    pub uid: u32,
    pub gid: u32,
    pub(crate) startup_ack: bool,
    /// The terminal re-registered with a live pty after its router socket died.
    pub(crate) pty_active: bool,
    pub(crate) had_reverse_tunnels: bool,
    pub(crate) disconnect_timeout_seconds: Option<i32>,
    pub(crate) identity: Arc<()>,
}

impl PartialEq for Registration {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.key == other.key
            && self.uid == other.uid
            && self.gid == other.gid
            && self.startup_ack == other.startup_ack
            && self.pty_active == other.pty_active
            && self.had_reverse_tunnels == other.had_reverse_tunnels
            && self.disconnect_timeout_seconds == other.disconnect_timeout_seconds
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
    pub(crate) watcher: LocalStream,
    pub(crate) startup_ack: bool,
}

struct StoredRegistration {
    info: Registration,
    stream: LocalStream,
    startup: StartupState,
    registered_at: Instant,
}

#[derive(Clone)]
enum StartupState {
    Legacy,
    Pending,
    Complete(Result<(), String>),
}

#[derive(Default)]
struct RegistryState {
    registrations: HashMap<String, StoredRegistration>,
    /// Ids removed in this process. A challenge client that returns during
    /// the post-start grace window must not be told to retry a session that
    /// already ended.
    removed: HashMap<String, Instant>,
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
        stream: LocalStream,
        peer: PeerIdentity,
    ) -> Result<RegisteredTerminal, RegistrationError> {
        let registration = validate(user_info, peer)?;
        let watcher = stream.try_clone().map_err(RegistrationError::Io)?;
        // The Windows router peeks this handle for EOF, which requires
        // non-blocking mode so a live session never stalls the loop.
        #[cfg(windows)]
        watcher
            .set_nonblocking(true)
            .map_err(RegistrationError::Io)?;
        let identity = registration.identity();
        let mut state = self.lock()?;
        match state.registrations.entry(registration.id.clone()) {
            Entry::Vacant(entry) => {
                let startup_ack = registration.startup_ack;
                let startup = if startup_ack {
                    StartupState::Pending
                } else {
                    StartupState::Legacy
                };
                entry.insert(StoredRegistration {
                    info: registration,
                    stream,
                    startup,
                    registered_at: Instant::now(),
                });
                self.inner.changed.notify_all();
                Ok(RegisteredTerminal {
                    identity,
                    watcher,
                    startup_ack,
                })
            }
            Entry::Occupied(mut entry) => {
                // A terminal that lost its router socket re-registers the same
                // id. Replace only a peer that has already closed; a live
                // duplicate stays rejected.
                if !peer_closed(&entry.get().stream) {
                    return Err(RegistrationError::Duplicate);
                }
                let startup_ack = registration.startup_ack;
                let startup = if startup_ack {
                    StartupState::Pending
                } else {
                    StartupState::Legacy
                };
                entry.insert(StoredRegistration {
                    info: registration,
                    stream,
                    startup,
                    registered_at: Instant::now(),
                });
                self.inner.changed.notify_all();
                Ok(RegisteredTerminal {
                    identity,
                    watcher,
                    startup_ack,
                })
            }
        }
    }

    pub(crate) fn report_startup(
        &self,
        identity: &RegistrationIdentity,
        result: Result<(), String>,
    ) -> Result<(), RegistrationError> {
        let mut state = self.lock()?;
        let stored = state
            .registrations
            .get_mut(identity.id())
            .filter(|stored| identity.matches(&stored.info))
            .ok_or(RegistrationError::Unavailable)?;
        if !matches!(stored.startup, StartupState::Pending) {
            return Err(RegistrationError::Invalid);
        }
        stored.startup = StartupState::Complete(result);
        self.inner.changed.notify_all();
        Ok(())
    }

    pub(crate) fn wait_for_startup(
        &self,
        registration: &Registration,
        deadline: Instant,
    ) -> Result<(), RegistrationError> {
        let mut state = self.lock()?;
        loop {
            let stored = state
                .registrations
                .get(&registration.id)
                .filter(|stored| stored.info.same_generation(registration))
                .ok_or(RegistrationError::Unavailable)?;
            match &stored.startup {
                StartupState::Legacy | StartupState::Complete(Ok(())) => return Ok(()),
                StartupState::Complete(Err(message)) => {
                    return Err(RegistrationError::Io(io::Error::other(message.clone())))
                }
                StartupState::Pending => {}
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
                return Err(RegistrationError::Timeout);
            }
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
            let id = identity.id().to_owned();
            state.registrations.remove(&id);
            let now = Instant::now();
            prune_removed(&mut state.removed, now);
            state.removed.insert(id, now);
            self.inner.changed.notify_all();
        }
        Ok(matches)
    }

    /// True when this process removed `id` inside the recovery grace window.
    pub(crate) fn was_removed(&self, id: &str) -> Result<bool, RegistrationError> {
        let mut state = self.lock()?;
        let now = Instant::now();
        prune_removed(&mut state.removed, now);
        Ok(state.removed.contains_key(id))
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

    pub(crate) fn resumed(&self) -> Result<Vec<(Registration, Instant)>, RegistrationError> {
        Ok(self
            .lock()?
            .registrations
            .values()
            .filter(|stored| stored.info.pty_active)
            .map(|stored| (stored.info.clone(), stored.registered_at))
            .collect())
    }

    pub(crate) fn clone_stream(
        &self,
        registration: &Registration,
    ) -> Result<LocalStream, RegistrationError> {
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

fn prune_removed(removed: &mut HashMap<String, Instant>, now: Instant) {
    removed.retain(|_, removed_at| {
        now.saturating_duration_since(*removed_at) <= et_core::RECOVERY_GRACE
    });
}

/// True when the registered terminal socket is already closed.
///
/// A blocking peek is only attempted after `poll` reports readability, so a
/// live idle session is not stalled.
#[cfg(unix)]
fn peer_closed(stream: &LocalStream) -> bool {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{recv, MsgFlags};
    use rustix::event::{poll, PollFd, PollFlags};

    let mut descriptors = [PollFd::new(
        stream,
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
    )];
    let Ok(timeout) = rustix::time::Timespec::try_from(Duration::ZERO) else {
        return false;
    };
    if poll(&mut descriptors, Some(&timeout)).is_err() {
        return false;
    }
    let events = descriptors[0].revents();
    if events.intersects(PollFlags::ERR) {
        return true;
    }
    if !events.intersects(PollFlags::IN | PollFlags::HUP) {
        return false;
    }
    let mut byte = [0u8; 1];
    match recv(stream.as_raw_fd(), &mut byte, MsgFlags::MSG_PEEK) {
        Ok(0) => true,
        Ok(_) => false,
        Err(_) => events.intersects(PollFlags::HUP),
    }
}

#[cfg(windows)]
fn peer_closed(stream: &LocalStream) -> bool {
    let previous = stream.set_nonblocking(true);
    if previous.is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let closed = match stream.peek(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted =>
        {
            false
        }
        Err(_) => true,
    };
    let _ = stream.set_nonblocking(false);
    closed
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
