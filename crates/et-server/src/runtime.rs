use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use et_net::listener::bind_tcp;

use crate::path::RouterPath;
use crate::registry::Registry;
use crate::router::Router;
use crate::runtime_accept;
use crate::runtime_error::RuntimeError;
use crate::runtime_handle::RuntimeHandle;
use crate::runtime_lifecycle::{self, LifecycleEvent};
use crate::runtime_state::{HandlerThreads, RawSockets, RuntimeCore};
use crate::session_table::SessionTable;

pub struct Runtime {
    core: Arc<RuntimeCore>,
    router: Option<Router>,
    lifecycle_sender: Option<Sender<LifecycleEvent>>,
    lifecycle_worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    accept_wakers: Vec<UnixStream>,
    accept_workers: Vec<JoinHandle<Result<(), RuntimeError>>>,
    tcp_addresses: Vec<SocketAddr>,
    router_path: PathBuf,
}

impl Runtime {
    pub fn start(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
    ) -> Result<Self, RuntimeError> {
        let bound = bind_tcp(bind_ip, port)?;
        let mut tcp_addresses = Vec::new();
        for listener in bound.iter() {
            tcp_addresses.push(listener.local_addr().map_err(|source| RuntimeError::Io {
                operation: "inspect TCP listener address",
                source,
            })?);
        }
        let registry = Registry::new();
        let core = Arc::new(RuntimeCore {
            registry: registry.clone(),
            sessions: SessionTable::new(),
            raw_sockets: Arc::new(RawSockets::new()),
            handlers: HandlerThreads::new(),
            shutdown: AtomicBool::new(false),
        });
        let router_name = router_path.path().to_path_buf();
        let (lifecycle_sender, lifecycle_events) = mpsc::channel();
        let mut router =
            Router::start_with_lifecycle(router_path, registry, Some(lifecycle_sender.clone()))?;
        let lifecycle_core = core.clone();
        let lifecycle_worker = match thread::Builder::new()
            .name("et-terminal-lifecycle".to_owned())
            .spawn(move || runtime_lifecycle::run(lifecycle_events, lifecycle_core))
        {
            Ok(worker) => worker,
            Err(source) => {
                let _ = router.shutdown();
                return Err(RuntimeError::Spawn(source));
            }
        };
        let mut runtime = Self {
            core,
            router: Some(router),
            lifecycle_sender: Some(lifecycle_sender),
            lifecycle_worker: Some(lifecycle_worker),
            accept_wakers: Vec::new(),
            accept_workers: Vec::new(),
            tcp_addresses,
            router_path: router_name,
        };
        for listener in bound.into_listeners() {
            let (wake_reader, wake_writer) = match UnixStream::pair() {
                Ok(pair) => pair,
                Err(source) => {
                    let _ = runtime.shutdown();
                    return Err(RuntimeError::Io {
                        operation: "create accept wakeup",
                        source,
                    });
                }
            };
            let worker_core = runtime.core.clone();
            let worker = match thread::Builder::new()
                .name("et-tcp-accept".to_owned())
                .spawn(move || runtime_accept::run(listener, wake_reader, worker_core))
            {
                Ok(worker) => worker,
                Err(source) => {
                    let _ = runtime.shutdown();
                    return Err(RuntimeError::Spawn(source));
                }
            };
            runtime.accept_wakers.push(wake_writer);
            runtime.accept_workers.push(worker);
        }
        Ok(runtime)
    }

    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle {
            core: self.core.clone(),
        }
    }

    pub fn tcp_addresses(&self) -> &[SocketAddr] {
        &self.tcp_addresses
    }

    pub fn router_path(&self) -> &Path {
        &self.router_path
    }

    pub fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.core.shutdown.store(true, Ordering::Release);
        let mut first_error = None;
        let connections = match self.core.sessions.begin_shutdown() {
            Ok(connections) => connections,
            Err(error) => {
                remember(&mut first_error, RuntimeError::SessionTable(error));
                Vec::new()
            }
        };
        for waker in &mut self.accept_wakers {
            if let Err(source) = waker.write_all(&[1]) {
                remember(
                    &mut first_error,
                    RuntimeError::Io {
                        operation: "wake TCP accept worker",
                        source,
                    },
                );
            }
        }
        if let Err(error) = self.core.raw_sockets.shutdown_all() {
            remember(&mut first_error, error);
        }
        for connection in connections {
            if let Err(error) = connection.shutdown() {
                remember(&mut first_error, RuntimeError::Session(error));
            }
        }
        if let Some(mut router) = self.router.take() {
            if let Err(error) = router.shutdown() {
                remember(&mut first_error, RuntimeError::Router(error));
            }
        }
        if let Err(error) = self.core.registry.clear() {
            remember(&mut first_error, RuntimeError::Registration(error));
        }
        if let Some(sender) = self.lifecycle_sender.take() {
            let _ = sender.send(LifecycleEvent::Shutdown);
        }
        if let Some(worker) = self.lifecycle_worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => remember(&mut first_error, error),
                Err(_) => remember(
                    &mut first_error,
                    RuntimeError::WorkerPanicked("terminal lifecycle"),
                ),
            }
        }
        for worker in self.accept_workers.drain(..) {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => remember(&mut first_error, error),
                Err(_) => remember(&mut first_error, RuntimeError::WorkerPanicked("TCP accept")),
            }
        }
        if let Err(error) = self.core.raw_sockets.shutdown_all() {
            remember(&mut first_error, error);
        }
        match self.core.handlers.take() {
            Ok(workers) => join_handlers(workers, &mut first_error),
            Err(error) => remember(&mut first_error, error),
        }
        self.accept_wakers.clear();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn join_handlers(workers: Vec<JoinHandle<()>>, first_error: &mut Option<RuntimeError>) {
    for worker in workers {
        if worker.join().is_err() {
            remember(
                first_error,
                RuntimeError::WorkerPanicked("TCP session handler"),
            );
        }
    }
}

fn remember(first: &mut Option<RuntimeError>, error: RuntimeError) {
    if first.is_none() {
        *first = Some(error);
    }
}
