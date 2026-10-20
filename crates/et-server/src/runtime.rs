use et_net::local::LocalStream;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use et_net::listener::{bind_tcp_with_backlog, DEFAULT_LISTEN_BACKLOG};

use crate::path::RouterPath;
use crate::registry::Registry;
#[cfg(windows)]
use crate::router::Router;
#[cfg(unix)]
use crate::router::RouterError;
use crate::runtime_accept;
use crate::runtime_error::RuntimeError;
use crate::runtime_handle::RuntimeHandle;
use crate::runtime_lifecycle::{self, LifecycleEvent, LifecycleSender};
use crate::runtime_state::{
    HandlerThreads, PreAuthSlots, RawSockets, RuntimeCore, MAX_PRE_AUTH_CONNECTIONS,
};
use crate::session_table::SessionTable;

#[cfg(all(test, unix))]
#[path = "runtime_recovery_test.rs"]
mod recovery_tests;

pub struct Runtime {
    core: Arc<RuntimeCore>,
    #[cfg(windows)]
    router: Option<Router>,
    /// Reports when the control thread closed the router it drives (Unix).
    #[cfg(unix)]
    router_stopped: Option<std::sync::mpsc::Receiver<Result<(), RouterError>>>,
    lifecycle: Option<LifecycleSender>,
    control_wake: Option<LocalStream>,
    control_worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    tcp_addresses: Vec<SocketAddr>,
    router_path: PathBuf,
    listen_backlog: i32,
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

    pub fn start_with_listen_backlog(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
        listen_backlog: i32,
    ) -> Result<Self, RuntimeError> {
        Self::start_configured(
            bind_ip,
            port,
            router_path,
            Arc::new(et_net::forward::SystemForwardResolver),
            listen_backlog,
            0,
        )
    }

    /// Start with a server-wide disconnect timeout in seconds. Explicit
    /// per-session values (including zero) override this default.
    pub fn start_with_settings(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
        listen_backlog: i32,
        disconnect_timeout_seconds: i32,
    ) -> Result<Self, RuntimeError> {
        Self::start_configured(
            bind_ip,
            port,
            router_path,
            Arc::new(et_net::forward::SystemForwardResolver),
            listen_backlog,
            disconnect_timeout_seconds,
        )
    }

    #[doc(hidden)]
    pub fn start_with_forward_resolver(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
        forward_resolver: Arc<dyn et_net::forward::ForwardResolver>,
    ) -> Result<Self, RuntimeError> {
        Self::start_configured(
            bind_ip,
            port,
            router_path,
            forward_resolver,
            DEFAULT_LISTEN_BACKLOG,
            0,
        )
    }

    fn start_configured(
        bind_ip: IpAddr,
        port: u16,
        router_path: RouterPath,
        forward_resolver: Arc<dyn et_net::forward::ForwardResolver>,
        listen_backlog: i32,
        disconnect_timeout_seconds: i32,
    ) -> Result<Self, RuntimeError> {
        let bound = bind_tcp_with_backlog(bind_ip, port, listen_backlog)?;
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
            started: Instant::now(),
            disconnect_timeout_seconds,
        });
        let router_name = router_path.path().to_path_buf();
        let (lifecycle, lifecycle_events) =
            runtime_lifecycle::channel().map_err(|source| RuntimeError::Io {
                operation: "create lifecycle wakeup",
                source,
            })?;
        #[cfg(windows)]
        let mut router =
            Router::start_with_lifecycle(router_path, registry, Some(lifecycle.clone()))?;
        // Unix runs the router on the control thread, next to the TCP
        // listeners: one thread for the whole control plane.
        #[cfg(unix)]
        let (control_router, router_stopped) = {
            let listener = crate::socket_path::OwnedRouterListener::bind(&router_path)
                .map_err(RouterError::from)?;
            // The runtime consumes no diagnostic router events.
            let (events, _) = std::sync::mpsc::sync_channel(1);
            let (stopped, router_stopped) = std::sync::mpsc::sync_channel(1);
            let poll = crate::router_loop::RouterPoll::new(
                listener,
                registry,
                events,
                Some(lifecycle.clone()),
            );
            (
                runtime_accept::ControlRouter { poll, stopped },
                router_stopped,
            )
        };
        let (wake_reader, wake_writer) = match et_net::local::wake_pair() {
            Ok(pair) => pair,
            Err(source) => {
                #[cfg(windows)]
                let _ = router.shutdown();
                return Err(RuntimeError::Io {
                    operation: "create accept wakeup",
                    source,
                });
            }
        };
        // One control thread accepts on every listener (IPv4 and IPv6) and
        // services terminal lifecycle events (and, on Unix, the router)
        // between accepts.
        let control_core = core.clone();
        let listen_backlog = bound.listen_backlog();
        let listeners = bound.into_listeners();
        let control_worker =
            match thread::Builder::new()
                .name("et-runtime".to_owned())
                .spawn(move || {
                    runtime_accept::run(
                        listeners,
                        wake_reader,
                        lifecycle_events,
                        control_core,
                        #[cfg(unix)]
                        Some(control_router),
                    )
                }) {
                Ok(worker) => worker,
                Err(source) => {
                    #[cfg(windows)]
                    let _ = router.shutdown();
                    return Err(RuntimeError::Spawn(source));
                }
            };
        Ok(Self {
            core,
            #[cfg(windows)]
            router: Some(router),
            #[cfg(unix)]
            router_stopped: Some(router_stopped),
            lifecycle: Some(lifecycle),
            control_wake: Some(wake_writer),
            control_worker: Some(control_worker),
            tcp_addresses,
            router_path: router_name,
            listen_backlog,
        })
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

    pub fn listen_backlog(&self) -> i32 {
        self.listen_backlog
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
        if let Some(waker) = self.control_wake.as_mut() {
            if let Err(source) = waker.write_all(&[1]) {
                remember(
                    &mut first_error,
                    RuntimeError::Io {
                        operation: "wake runtime control thread",
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
        #[cfg(windows)]
        if let Some(mut router) = self.router.take() {
            if let Err(error) = router.shutdown() {
                remember(&mut first_error, RuntimeError::Router(error));
            }
        }
        // The control thread closes the router at its next turn. A router that
        // already failed has reported its error and closed.
        #[cfg(unix)]
        if let Some(stopped) = self.router_stopped.take() {
            if let Some(lifecycle) = self.lifecycle.as_ref() {
                lifecycle.send(LifecycleEvent::StopRouter);
            }
            if let Ok(Err(error)) = stopped.recv() {
                remember(&mut first_error, RuntimeError::Router(error));
            }
        }
        if let Err(error) = self.core.registry.clear() {
            remember(&mut first_error, RuntimeError::Registration(error));
        }
        // The control thread keeps applying lifecycle events until this one.
        if let Some(lifecycle) = self.lifecycle.take() {
            lifecycle.send(LifecycleEvent::Shutdown);
        }
        if let Some(worker) = self.control_worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => remember(&mut first_error, error),
                Err(_) => remember(
                    &mut first_error,
                    RuntimeError::WorkerPanicked("runtime control"),
                ),
            }
        }
        if let Err(error) = self.core.raw_sockets.shutdown_all() {
            remember(&mut first_error, error);
        }
        match self.core.handlers.take() {
            Ok(workers) => join_handlers(workers, &mut first_error),
            Err(error) => remember(&mut first_error, error),
        }
        self.control_wake = None;
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

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io::{self, Read};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
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
    fn disconnect_between_registration_lookup_and_raw_assignment_closes_handler() {
        let directory = TestDirectory::new();
        let router_path =
            select_router_path_for(1000, Some(&directory.socket()), None, None).unwrap();
        let mut runtime = Runtime::start(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, router_path).unwrap();
        let handle = runtime.handle();
        let address = runtime.tcp_addresses()[0];
        let terminal = register(&directory.socket(), &handle);
        let (assignment_tx, assignment_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (scan_tx, scan_rx) = mpsc::sync_channel(1);
        let identity = runtime.core.registry.get(ID).unwrap().unwrap().identity();
        crate::runtime_handler::install_raw_assignment_hook(identity, assignment_tx, release_rx);
        crate::runtime_lifecycle::install_raw_scan_hook(ID, scan_tx);

        let mut client = connect_request(address);
        assignment_rx
            .recv_timeout(TIMEOUT)
            .expect("handler did not reach the post-lookup assignment barrier");
        drop(terminal);
        scan_rx
            .recv_timeout(TIMEOUT)
            .expect("terminal lifecycle did not complete its raw-socket scan");
        release_tx.send(()).unwrap();
        assert_prompt_closed(&mut client);

        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = shutdown_tx.send(runtime.shutdown());
        });
        shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("raced handler and pre-auth permit were not released promptly")
            .unwrap();
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
                ptyactive: None,
                hadreversetunnels: None,
                disconnect_timeout_seconds: None,
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

    fn assert_prompt_closed(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                panic!("raced initialization socket remained open: {error}")
            }
            Ok(read) => panic!("raced initialization socket produced {read} bytes before close"),
            Err(error) => panic!("raced initialization socket close failed: {error}"),
        }
    }
}
