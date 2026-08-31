use et_net::local::LocalStream;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
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
use crate::runtime_state::{
    HandlerThreads, PreAuthSlots, RawSockets, RuntimeCore, MAX_PRE_AUTH_CONNECTIONS,
};
use crate::session_table::SessionTable;

pub struct Runtime {
    core: Arc<RuntimeCore>,
    router: Option<Router>,
    lifecycle_sender: Option<Sender<LifecycleEvent>>,
    lifecycle_worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    accept_wakers: Vec<LocalStream>,
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
        Self::start_with_forward_resolver(
            bind_ip,
            port,
            router_path,
            Arc::new(et_net::forward::SystemForwardResolver),
        )
    }

    #[doc(hidden)]
    pub fn start_with_forward_resolver(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
        forward_resolver: Arc<dyn et_net::forward::ForwardResolver>,
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
            pre_auth_slots: Arc::new(PreAuthSlots::new(MAX_PRE_AUTH_CONNECTIONS)),
            shutdown: AtomicBool::new(false),
            forward_resolver,
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
            let (wake_reader, wake_writer) = match et_net::local::wake_pair() {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use et_core::packet::Packet;
    use et_core::proto::{ConnectResponse, ConnectStatus, TerminalPacketType, TerminalUserInfo};
    use et_net::framing_io::{read_proto_limited, write_proto};
    use et_net::handshake::client_request;
    use et_net::local_packet::write_local_packet;
    use prost::Message;

    use super::Runtime;
    use crate::path::select_router_path_for;

    const ID: &str = "aaaaaaaaaaaaaaaa";
    const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    const TIMEOUT: Duration = Duration::from_secs(3);
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "et-rs-stale-waiter-test-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("router.sock")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support networking")]
    fn terminal_eof_does_not_resurrect_a_starting_session_from_a_stale_waiter() {
        let directory = TestDirectory::new();
        let router_path =
            select_router_path_for(1000, Some(&directory.socket()), None, None).unwrap();
        let mut runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path).unwrap();
        let handle = runtime.handle();
        let address = runtime.tcp_addresses()[0];
        let terminal = register(&directory.socket(), &handle);

        let (mut client_a, response) = handshake(address);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        assert_eq!(handle.session_state(ID).unwrap(), None);

        // A newer unauthenticated connection displaces the old one without
        // creating a Starting slot or a waiter.
        let (mut client_b, response) = handshake(address);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        assert_closed(&mut client_a);

        drop(terminal);
        handle.wait_disconnected(ID, TIMEOUT).unwrap();
        assert_closed(&mut client_a);
        assert_closed(&mut client_b);
        assert_eq!(handle.session_state(ID).unwrap(), None);

        let (_unregistered, response) = handshake(address);
        assert_eq!(response.status, Some(ConnectStatus::InvalidKey as i32));

        let _fresh_terminal = register(&directory.socket(), &handle);
        let (_fresh_client, response) = handshake(address);
        assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
        runtime.shutdown().unwrap();
    }

    fn register(
        path: &Path,
        handle: &crate::runtime_handle::RuntimeHandle,
    ) -> et_net::local::LocalStream {
        let mut stream = et_net::local::connect(path).unwrap();
        let uid = i64::from(rustix::process::getuid().as_raw());
        let gid = i64::from(rustix::process::getgid().as_raw());
        let packet = Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            TerminalUserInfo {
                id: Some(ID.to_owned()),
                passkey: Some(KEY.to_owned()),
                uid: Some(uid),
                gid: Some(gid),
                fd: None,
            }
            .encode_to_vec(),
        );
        write_local_packet(&mut stream, &packet).unwrap();
        handle.wait_registered(ID, TIMEOUT).unwrap();
        stream
    }

    fn handshake(address: SocketAddr) -> (TcpStream, ConnectResponse) {
        let mut stream = connect_request(address);
        let response = read_proto_limited(&mut stream, 64 * 1024).unwrap();
        (stream, response)
    }

    fn connect_request(address: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        write_proto(&mut stream, &client_request(ID)).unwrap();
        stream
    }

    fn assert_closed(stream: &mut TcpStream) {
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).unwrap_or(0), 0);
    }
}
