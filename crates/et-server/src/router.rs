use et_net::local::LocalStream;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::path::{PathError, RouterPath};
use crate::registry::Registry;
use crate::router_loop;
use crate::runtime_lifecycle::LifecycleEvent;
#[cfg(unix)]
use crate::socket_path::OwnedRouterListener;
#[cfg(windows)]
use crate::socket_path_windows::OwnedRouterListener;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouterEvent {
    Registered { id: String },
    Disconnected { id: String },
    Rejected(RouterReject),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterReject {
    MalformedFrame,
    Encrypted,
    WrongPacketType,
    MalformedUserInfo,
    InvalidRegistration,
    Duplicate,
    RegistryUnavailable,
}

#[derive(Debug)]
pub enum RouterError {
    Path(PathError),
    Io(io::Error),
    Spawn(io::Error),
    WorkerPanicked,
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(error) => write!(f, "router path: {error}"),
            Self::Io(error) => write!(f, "router I/O: {error}"),
            Self::Spawn(error) => write!(f, "could not start router worker: {error}"),
            Self::WorkerPanicked => write!(f, "router worker panicked"),
        }
    }
}

impl std::error::Error for RouterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::Io(error) | Self::Spawn(error) => Some(error),
            Self::WorkerPanicked => None,
        }
    }
}

impl From<PathError> for RouterError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

pub struct Router {
    wake_writer: LocalStream,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), RouterError>>>,
    events: Receiver<RouterEvent>,
}

impl Router {
    pub fn start(path: RouterPath, registry: Registry) -> Result<Self, RouterError> {
        Self::start_with_lifecycle(path, registry, None)
    }

    pub(crate) fn start_with_lifecycle(
        path: RouterPath,
        registry: Registry,
        lifecycle: Option<Sender<LifecycleEvent>>,
    ) -> Result<Self, RouterError> {
        let listener = OwnedRouterListener::bind(&path)?;
        let (wake_reader, wake_writer) = et_net::local::wake_pair().map_err(RouterError::Io)?;
        wake_reader.set_nonblocking(true).map_err(RouterError::Io)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let (event_sender, events) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("et-router".to_owned())
            .spawn(move || {
                router_loop::run(
                    listener,
                    wake_reader,
                    registry,
                    event_sender,
                    lifecycle,
                    worker_shutdown,
                )
            })
            .map_err(RouterError::Spawn)?;
        Ok(Self {
            wake_writer,
            shutdown,
            worker: Some(worker),
            events,
        })
    }

    pub fn recv_event_timeout(&self, timeout: Duration) -> Result<RouterEvent, RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }

    pub fn shutdown(&mut self) -> Result<(), RouterError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        self.shutdown.store(true, Ordering::Release);
        if self.wake_writer.write_all(&[1]).is_err() {
            let _ = self.wake_writer.shutdown(std::net::Shutdown::Both);
        }
        worker.join().map_err(|_| RouterError::WorkerPanicked)??;
        Ok(())
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
