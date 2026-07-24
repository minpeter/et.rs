use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::registry::Registry;
use crate::runtime_error::RuntimeError;
use crate::session_table::SessionTable;

pub(crate) struct RuntimeCore {
    pub(crate) registry: Registry,
    pub(crate) sessions: SessionTable,
    pub(crate) raw_sockets: Arc<RawSockets>,
    pub(crate) handlers: HandlerThreads,
    pub(crate) shutdown: AtomicBool,
}

pub(crate) struct RawSockets {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, TcpStream>>,
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
        streams.insert(id, clone);
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
        for stream in streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
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
