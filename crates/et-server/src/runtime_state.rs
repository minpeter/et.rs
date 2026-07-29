use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::registry::{RegistrationIdentity, Registry};
use crate::runtime_error::RuntimeError;
use crate::session_table::SessionTable;

pub(crate) struct RuntimeCore {
    pub(crate) registry: Registry,
    pub(crate) sessions: SessionTable,
    pub(crate) raw_sockets: Arc<RawSockets>,
    pub(crate) handlers: HandlerThreads,
    pub(crate) pre_auth_slots: Arc<PreAuthSlots>,
    pub(crate) shutdown: AtomicBool,
}

pub(crate) const MAX_PRE_AUTH_CONNECTIONS: usize = 128;

pub(crate) struct PreAuthSlots {
    active: AtomicUsize,
    limit: usize,
}

pub(crate) struct PreAuthGuard {
    slots: Arc<PreAuthSlots>,
}

impl PreAuthSlots {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    pub(crate) fn try_acquire(self: Arc<Self>) -> Option<PreAuthGuard> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()?;
        Some(PreAuthGuard { slots: self })
    }
}

impl Drop for PreAuthGuard {
    fn drop(&mut self) {
        self.slots.active.fetch_sub(1, Ordering::Release);
    }
}

struct TrackedSocket {
    stream: TcpStream,
    registration: Option<RegistrationIdentity>,
}

pub(crate) struct RawSockets {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, TrackedSocket>>,
}

pub(crate) struct RawSocketGuard {
    id: u64,
    sockets: Arc<RawSockets>,
}

impl RawSockets {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            streams: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn track(
        self: &Arc<Self>,
        stream: &TcpStream,
    ) -> Result<RawSocketGuard, RuntimeError> {
        let clone = stream.try_clone().map_err(|source| RuntimeError::Io {
            operation: "clone accepted TCP stream",
            source,
        })?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        streams.insert(
            id,
            TrackedSocket {
                stream: clone,
                registration: None,
            },
        );
        Ok(RawSocketGuard {
            id,
            sockets: self.clone(),
        })
    }

    pub(crate) fn shutdown_all(&self) -> Result<(), RuntimeError> {
        let streams = self
            .streams
            .lock()
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        for tracked in streams.values() {
            let _ = tracked.stream.shutdown(Shutdown::Both);
        }
        Ok(())
    }

    pub(crate) fn shutdown_registration(
        &self,
        identity: &RegistrationIdentity,
    ) -> Result<(), RuntimeError> {
        let streams = self
            .streams
            .lock()
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        for tracked in streams.values() {
            if tracked
                .registration
                .as_ref()
                .is_some_and(|current| current.same_generation(identity))
            {
                let _ = tracked.stream.shutdown(Shutdown::Both);
            }
        }
        Ok(())
    }
}

impl RawSocketGuard {
    pub(crate) fn assign(
        &mut self,
        registration: RegistrationIdentity,
    ) -> Result<(), RuntimeError> {
        let mut streams = self
            .sockets
            .streams
            .lock()
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        let tracked = streams
            .get_mut(&self.id)
            .ok_or(RuntimeError::WorkerUnavailable)?;
        tracked.registration = Some(registration);
        Ok(())
    }
}

impl Drop for RawSocketGuard {
    fn drop(&mut self) {
        if let Ok(mut streams) = self.sockets.streams.lock() {
            streams.remove(&self.id);
        }
    }
}

pub(crate) struct HandlerThreads {
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl HandlerThreads {
    pub(crate) fn new() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn push(&self, handle: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        match self.handles.lock() {
            Ok(mut handles) => {
                handles.push(handle);
                Ok(())
            }
            Err(_) => Err(handle),
        }
    }

    pub(crate) fn take(&self) -> Result<Vec<JoinHandle<()>>, RuntimeError> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        Ok(std::mem::take(&mut *handles))
    }
}

#[cfg(test)]
mod pre_auth_tests {
    use super::*;

    #[test]
    fn pre_auth_slots_reject_excess_and_release_on_drop() {
        let slots = Arc::new(PreAuthSlots::new(1));
        let first = slots.clone().try_acquire().unwrap();
        assert!(slots.clone().try_acquire().is_none());
        drop(first);
        assert!(slots.try_acquire().is_some());
    }
}
