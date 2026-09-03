use std::collections::VecDeque;
#[cfg(unix)]
use std::io::Read;
use std::io::{self};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;

use crossbeam_channel as channel;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{PortForwardSourceRequest, TerminalPacketType};

use crate::forward_endpoint::{Endpoint, ResolvedEndpoint};
use crate::forward_io::BoundSource;
use crate::forward_worker::{
    command_channel, run, Command, CommandSender, TryCommandError, WorkerChannels,
};

const CHANNEL_CAPACITY: usize = 256;
/// Maximum reverse listeners owned by one terminal session, after DNS fanout
/// and address deduplication.
pub const MAX_SESSION_LISTENERS: usize = 32;
pub(crate) const RESOLVER_WORKERS: usize = 4;
pub(crate) const RESOLVER_QUEUE_CAPACITY: usize = 16;
pub const FORWARD_TIMEOUT_SENTINEL: &str = "\nET_ERR:FORWARD_TIMEOUT";

pub fn encode_forward_timeout(message: &str) -> String {
    format!("{message}{FORWARD_TIMEOUT_SENTINEL}")
}

pub fn decode_forward_timeout(message: &str) -> Option<&str> {
    message.strip_suffix(FORWARD_TIMEOUT_SENTINEL)
}

pub trait ForwardResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>>;

    #[cfg(unix)]
    fn listen_tcp_as_user(
        &self,
        address: std::net::SocketAddr,
        uid: u32,
        gid: u32,
        deadline: Instant,
    ) -> io::Result<std::net::TcpListener> {
        crate::user_socket_ops::listen_tcp_as_user_deadline(address, uid, gid, deadline)
    }
}

struct ResolverRequest {
    resolver: Arc<dyn ForwardResolver>,
    host: String,
    port: u16,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    result: mpsc::SyncSender<io::Result<Vec<std::net::SocketAddr>>>,
}

struct ResolverQueue {
    requests: Mutex<VecDeque<ResolverRequest>>,
    changed: Condvar,
}

pub(crate) struct ResolverExecutor {
    queue: Arc<ResolverQueue>,
    _workers: Vec<JoinHandle<()>>,
}

impl ResolverExecutor {
    pub(crate) fn global() -> &'static Self {
        static EXECUTOR: OnceLock<ResolverExecutor> = OnceLock::new();
        EXECUTOR.get_or_init(Self::new)
    }

    fn new() -> Self {
        let queue = Arc::new(ResolverQueue {
            requests: Mutex::new(VecDeque::with_capacity(RESOLVER_QUEUE_CAPACITY)),
            changed: Condvar::new(),
        });
        let mut workers = Vec::with_capacity(RESOLVER_WORKERS);
        for index in 0..RESOLVER_WORKERS {
            let queue = queue.clone();
            if let Ok(worker) = std::thread::Builder::new()
                .name(format!("et-forward-resolver-{index}"))
                .spawn(move || loop {
                    let request = {
                        let mut requests = match queue.requests.lock() {
                            Ok(requests) => requests,
                            Err(_) => return,
                        };
                        while requests.is_empty() {
                            requests = match queue.changed.wait(requests) {
                                Ok(requests) => requests,
                                Err(_) => return,
                            };
                        }
                        let request = requests.pop_front().expect("queue is non-empty");
                        queue.changed.notify_all();
                        request
                    };
                    if request.cancelled.load(Ordering::Acquire)
                        || Instant::now() >= request.deadline
                    {
                        continue;
                    }
                    let result = request.resolver.resolve(&request.host, request.port);
                    if !request.cancelled.load(Ordering::Acquire)
                        && Instant::now() < request.deadline
                    {
                        let _ = request.result.send(result);
                    }
                })
            {
                workers.push(worker);
            }
        }
        ResolverExecutor {
            queue,
            _workers: workers,
        }
    }

    pub(crate) fn resolve(
        &self,
        resolver: Arc<dyn ForwardResolver>,
        host: String,
        port: u16,
        deadline: Instant,
    ) -> io::Result<Vec<std::net::SocketAddr>> {
        self.resolve_with_observers(resolver, host, port, deadline, |_| {}, |_| {})
    }

    fn resolve_with_observers<F, G>(
        &self,
        resolver: Arc<dyn ForwardResolver>,
        host: String,
        port: u16,
        deadline: Instant,
        observe_wait: F,
        observe_result: G,
    ) -> io::Result<Vec<std::net::SocketAddr>>
    where
        F: FnOnce(Duration),
        G: FnOnce(&io::Result<Vec<std::net::SocketAddr>>),
    {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "forwarding setup deadline elapsed")
            })?;
        let (result, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut request = Some(ResolverRequest {
            resolver,
            host,
            port,
            deadline,
            cancelled: cancelled.clone(),
            result,
        });
        let mut requests = self
            .queue
            .requests
            .lock()
            .map_err(|_| io::Error::other("forwarding resolver is unavailable"))?;
        loop {
            let now = Instant::now();
            requests.retain(|queued| {
                !queued.cancelled.load(Ordering::Acquire) && now < queued.deadline
            });
            if requests.len() < RESOLVER_QUEUE_CAPACITY {
                requests.push_back(request.take().expect("request is admitted once"));
                self.queue.changed.notify_one();
                break;
            }
            let wait = deadline.checked_duration_since(now).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "forwarding resolution deadline elapsed",
                )
            })?;
            let (next, timed) = self
                .queue
                .changed
                .wait_timeout(requests, wait)
                .map_err(|_| io::Error::other("forwarding resolver is unavailable"))?;
            requests = next;
            if timed.timed_out() && Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "forwarding resolution deadline elapsed",
                ));
            }
        }
        drop(requests);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "forwarding resolution deadline elapsed",
                )
            })?;
        observe_wait(remaining);
        let result = match receiver.recv_timeout(remaining) {
            Ok(_) if Instant::now() >= deadline => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "forwarding resolution deadline elapsed",
            )),
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "forwarding resolution deadline elapsed",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "forwarding resolver terminated unexpectedly",
            )),
        };
        observe_result(&result);
        cancelled.store(true, Ordering::Release);
        self.queue.changed.notify_all();
        result
    }
}

#[derive(Default)]
pub struct SystemForwardResolver;

impl ForwardResolver for SystemForwardResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}

#[derive(Debug)]
pub enum ForwardError {
    Unsupported,
    Io(std::io::Error),
    Protocol(&'static str),
    Unavailable,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(formatter, "port forwarding is not implemented"),
            Self::Io(error) => write!(formatter, "port forwarding I/O: {error}"),
            Self::Protocol(message) => write!(formatter, "port forwarding protocol: {message}"),
            Self::Unavailable => write!(formatter, "port forwarding worker is unavailable"),
        }
    }
}

impl std::error::Error for ForwardError {}

impl ForwardError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::TimedOut)
    }
}

impl From<io::Error> for ForwardError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) type Outbound = Result<Packet, ForwardError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardOrigin {
    Explicit,
    SshConfig { strict: bool },
}

pub struct ForwardSource {
    pub request: PortForwardSourceRequest,
    pub origin: ForwardOrigin,
}

impl ForwardSource {
    pub const fn explicit(request: PortForwardSourceRequest) -> Self {
        Self {
            request,
            origin: ForwardOrigin::Explicit,
        }
    }

    pub const fn ssh_config(request: PortForwardSourceRequest, strict: bool) -> Self {
        Self {
            request,
            origin: ForwardOrigin::SshConfig { strict },
        }
    }
}

pub struct SkippedForward {
    pub request: PortForwardSourceRequest,
    pub error: io::Error,
}

pub struct Forwarder {
    commands: CommandSender,
    outbound: channel::Receiver<Outbound>,
    priority: channel::Receiver<Outbound>,
    cancel: Option<channel::Sender<()>>,
    /// Readiness channel for outbound packets. Unix callers poll it exactly
    /// like upstream's `select()`; Windows callers drain [`Forwarder::try_outbound`]
    /// on the client loop's 10ms cadence instead, because a socket pair created
    /// this way is not selectable there.
    #[cfg(unix)]
    wake: UnixStream,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    abandoned: Arc<AtomicBool>,
}

impl Forwarder {
    pub fn start(sources: Vec<PortForwardSourceRequest>) -> Result<Self, ForwardError> {
        let sources = sources.into_iter().map(ForwardSource::explicit).collect();
        start_forwarder(
            sources,
            None,
            Instant::now() + Duration::from_secs(30),
            Arc::new(SystemForwardResolver),
        )
        .map(|(forwarder, _, _)| forwarder)
    }

    pub fn start_with_origins(
        sources: Vec<ForwardSource>,
    ) -> Result<(Self, Vec<SkippedForward>), ForwardError> {
        Self::start_with_origins_deadline(
            sources,
            Instant::now() + Duration::from_secs(30),
            Arc::new(SystemForwardResolver),
        )
    }

    pub fn start_with_origins_deadline(
        sources: Vec<ForwardSource>,
        deadline: Instant,
        resolver: Arc<dyn ForwardResolver>,
    ) -> Result<(Self, Vec<SkippedForward>), ForwardError> {
        start_forwarder(sources, None, deadline, resolver)
            .map(|(forwarder, _, skipped)| (forwarder, skipped))
    }

    /// Bind all forwarding sources and return the forwarder together with the
    /// environment variables created for named-pipe requests, mirroring the
    /// upstream server (`PortForwardHandler::createSource` +
    /// `TerminalServer::runTerminal`). `owner` is the session user: UNIX
    /// listen/connect drop to that user (ET #784).
    pub fn start_with_user(
        sources: Vec<PortForwardSourceRequest>,
        owner: Option<(u32, u32)>,
    ) -> Result<(Self, ForwardEnvironment), ForwardError> {
        Self::start_with_user_deadline(
            sources,
            owner,
            Instant::now() + Duration::from_secs(30),
            Arc::new(SystemForwardResolver),
        )
    }

    pub fn start_with_user_deadline(
        sources: Vec<PortForwardSourceRequest>,
        owner: Option<(u32, u32)>,
        deadline: Instant,
        resolver: Arc<dyn ForwardResolver>,
    ) -> Result<(Self, ForwardEnvironment), ForwardError> {
        Self::start_with_user_deadline_hook(sources, owner, deadline, resolver, || {})
    }

    fn start_with_user_deadline_hook(
        sources: Vec<PortForwardSourceRequest>,
        owner: Option<(u32, u32)>,
        deadline: Instant,
        resolver: Arc<dyn ForwardResolver>,
        before_publish: impl FnOnce(),
    ) -> Result<(Self, ForwardEnvironment), ForwardError> {
        let sources = sources.into_iter().map(ForwardSource::explicit).collect();
        start_forwarder_hook(sources, owner, deadline, resolver, before_publish, || {})
            .map(|(forwarder, environment, _)| (forwarder, environment))
    }
}

fn start_forwarder(
    sources: Vec<ForwardSource>,
    owner: Option<(u32, u32)>,
    deadline: Instant,
    resolver: Arc<dyn ForwardResolver>,
) -> Result<(Forwarder, ForwardEnvironment, Vec<SkippedForward>), ForwardError> {
    start_forwarder_hook(sources, owner, deadline, resolver, || {}, || {})
}

fn start_forwarder_hook(
    sources: Vec<ForwardSource>,
    owner: Option<(u32, u32)>,
    deadline: Instant,
    resolver: Arc<dyn ForwardResolver>,
    before_publish: impl FnOnce(),
    worker_start: impl FnOnce() + Send + 'static,
) -> Result<(Forwarder, ForwardEnvironment, Vec<SkippedForward>), ForwardError> {
    let (sources, environment, skipped) = bind_sources(sources, owner, deadline, resolver)?;
    ensure_setup_deadline(deadline)?;
    let session_user = owner;
    let (commands_tx, commands_rx) = command_channel(CHANNEL_CAPACITY);
    let (outbound_tx, outbound_rx) = channel::bounded(CHANNEL_CAPACITY);
    // Credit returns are CONTROL messages for a flow they regulate, so they
    // must not queue behind the very data they are meant to release. On a
    // small transport window the data backlog is exactly what delays them,
    // which parks both senders. Draining this lane first keeps credit moving.
    let (priority_tx, priority_rx) = channel::bounded(CHANNEL_CAPACITY);
    let (cancel_tx, cancel_rx) = channel::bounded(1);
    let abandoned = Arc::new(AtomicBool::new(false));
    let worker_abandoned = abandoned.clone();
    #[cfg(unix)]
    let (wake, wake_writer) = {
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        (reader, writer)
    };
    #[cfg(unix)]
    let (listener_stop, listener_stop_reader) = UnixStream::pair()?;
    #[cfg(windows)]
    let listener_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(windows)]
    let listener_stop_reader = listener_stop.clone();
    let worker_commands = commands_tx.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = shutdown.clone();
    let worker = std::thread::Builder::new()
        .name("et-forwarding".to_owned())
        .spawn(move || {
            worker_start();
            run(
                sources,
                WorkerChannels {
                    receiver: commands_rx,
                    sender: worker_commands,
                    outbound: outbound_tx,
                    priority: priority_tx,
                    cancel: cancel_rx,
                    abandoned: worker_abandoned,
                },
                #[cfg(unix)]
                wake_writer,
                (listener_stop_reader, session_user, worker_shutdown),
            );
            #[cfg(unix)]
            drop(listener_stop);
            #[cfg(windows)]
            listener_stop.store(true, std::sync::atomic::Ordering::Release);
        })
        .map_err(ForwardError::Io)?;
    let forwarder = Forwarder {
        commands: commands_tx,
        outbound: outbound_rx,
        priority: priority_rx,
        cancel: Some(cancel_tx),
        #[cfg(unix)]
        wake,
        shutdown,
        worker: Some(worker),
        abandoned,
    };
    before_publish();
    ensure_setup_deadline(deadline)?;
    Ok((forwarder, environment, skipped))
}

impl Forwarder {
    /// Pollable readiness handle for outbound forwarding packets (Unix only).
    #[cfg(unix)]
    pub fn wake(&self) -> Result<&UnixStream, ForwardError> {
        Ok(&self.wake)
    }

    /// Hand a forwarding packet to the worker, blocking when its command
    /// queue is full.
    ///
    /// Only safe for callers that never also drain [`Forwarder::try_outbound`]
    /// on the same thread (e.g. tests). Session loops must use
    /// [`Forwarder::try_receive`] instead: the worker can itself be blocked
    /// emitting outbound packets, which only the session loop drains, so a
    /// blocking send from the session loop closes a cycle and deadlocks the
    /// session permanently.
    pub fn receive(&self, packet: Packet) -> Result<(), ForwardError> {
        self.commands
            .send(Command::Packet(packet))
            .map_err(|_| ForwardError::Unavailable)
    }

    /// Hand a forwarding packet to the worker without blocking.
    ///
    /// Returns the packet back when the worker's command queue is full so the
    /// caller can drain outbound packets (which is what unblocks the worker)
    /// and retry later. Callers must not read further session packets while
    /// holding a returned packet, or forwarding data would be reordered.
    pub fn try_receive(&self, packet: Packet) -> Result<Option<Packet>, ForwardError> {
        match self.commands.try_send(Command::Packet(packet)) {
            Ok(()) => Ok(None),
            Err(TryCommandError::Full(Command::Packet(packet))) => Ok(Some(packet)),
            Err(TryCommandError::Full(_)) | Err(TryCommandError::Closed) => {
                Err(ForwardError::Unavailable)
            }
        }
    }

    pub fn try_outbound(&self) -> Result<Option<Packet>, ForwardError> {
        #[cfg(unix)]
        drain_wake(&self.wake)?;
        if let Ok(result) = self.priority.try_recv() {
            return result.map(Some);
        }
        match self.outbound.try_recv() {
            Ok(result) => result.map(Some),
            Err(channel::TryRecvError::Empty) => Ok(None),
            Err(channel::TryRecvError::Disconnected) => Err(ForwardError::Unavailable),
        }
    }

    pub fn wait_outbound(&self, timeout: Duration) -> Result<Packet, ForwardError> {
        wait_outbound_from(&self.priority, &self.outbound, timeout)
    }

    pub fn shutdown(mut self) -> Result<(), ForwardError> {
        self.stop()
    }

    /// Cancel independently of bounded command/output capacity and join the
    /// worker. Returns true when queued commands or outbound packets could not
    /// be completed and were explicitly abandoned.
    pub fn shutdown_hard(&mut self) -> Result<bool, ForwardError> {
        self.shutdown.store(true, Ordering::Release);
        self.cancel.take();
        let mut abandoned =
            !self.commands.is_empty() || !self.priority.is_empty() || !self.outbound.is_empty();
        self.commands.shutdown();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ForwardError::Unavailable)?;
        }
        while self.outbound.try_recv().is_ok() {
            abandoned = true;
        }
        while self.priority.try_recv().is_ok() {
            abandoned = true;
        }
        if !self.commands.is_empty() {
            abandoned = true;
        }
        abandoned |= self.abandoned.load(Ordering::Acquire);
        Ok(abandoned)
    }

    fn stop(&mut self) -> Result<(), ForwardError> {
        if let Some(worker) = self.worker.take() {
            self.shutdown.store(true, Ordering::Release);
            self.commands.shutdown();
            worker.join().map_err(|_| ForwardError::Unavailable)?;
        }
        Ok(())
    }
}

fn wait_outbound_from(
    priority: &channel::Receiver<Outbound>,
    outbound: &channel::Receiver<Outbound>,
    timeout: Duration,
) -> Result<Packet, ForwardError> {
    let deadline = Instant::now() + timeout;
    let mut priority_open = true;
    let mut outbound_open = true;
    loop {
        if priority_open {
            match priority.try_recv() {
                Ok(result) => return result,
                Err(channel::TryRecvError::Empty) => {}
                Err(channel::TryRecvError::Disconnected) => priority_open = false,
            }
        }
        if outbound_open {
            match outbound.try_recv() {
                Ok(result) => return result,
                Err(channel::TryRecvError::Empty) => {}
                Err(channel::TryRecvError::Disconnected) => outbound_open = false,
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(ForwardError::Unavailable);
        };
        match (priority_open, outbound_open) {
            (true, true) => {
                let timeout = channel::after(remaining);
                channel::select_biased! {
                    recv(priority) -> result => match result {
                        Ok(result) => return result,
                        Err(_) => priority_open = false,
                    },
                    recv(outbound) -> result => match result {
                        Ok(result) => return result,
                        Err(_) => outbound_open = false,
                    },
                    recv(timeout) -> _ => return Err(ForwardError::Unavailable),
                }
            }
            (true, false) => {
                return priority
                    .recv_timeout(remaining)
                    .map_err(|_| ForwardError::Unavailable)?;
            }
            (false, true) => {
                return outbound
                    .recv_timeout(remaining)
                    .map_err(|_| ForwardError::Unavailable)?;
            }
            (false, false) => return Err(ForwardError::Unavailable),
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        // Drop is an abort path and must not block behind bounded forwarding
        // queues. Callers that require graceful completion use `shutdown`.
        let _ = self.shutdown_hard();
    }
}

/// Environment variables created for named-pipe forwards.
pub type ForwardEnvironment = Vec<(String, String)>;

enum PlannedSource {
    Endpoint {
        source: ResolvedEndpoint,
        destination: et_core::proto::SocketEndpoint,
        original: PortForwardSourceRequest,
        origin: ForwardOrigin,
    },
    #[cfg(unix)]
    Environment {
        variable: String,
        destination: et_core::proto::SocketEndpoint,
    },
}

fn bind_sources(
    sources: Vec<ForwardSource>,
    owner: Option<(u32, u32)>,
    deadline: Instant,
    resolver: Arc<dyn ForwardResolver>,
) -> Result<(Vec<BoundSource>, ForwardEnvironment, Vec<SkippedForward>), ForwardError> {
    let mut plans = Vec::with_capacity(sources.len());
    let mut skipped = Vec::new();
    let mut listener_count = 0usize;
    for source in sources {
        ensure_setup_deadline(deadline)?;
        let origin = source.origin;
        let original = source.request.clone();
        let request = source.request;
        // The destination is passed through verbatim in the
        // PORT_FORWARD_DESTINATION_REQUEST and parsed by the remote side.
        let destination = request.destination.unwrap_or_default();
        let (plan, additional_listeners) = if let Some(variable) = request.environmentvariable {
            if request.source.is_some() {
                return Err(ForwardError::Protocol(
                    "Do not set a source when forwarding named pipes with environment variables",
                ));
            }
            #[cfg(unix)]
            {
                (
                    PlannedSource::Environment {
                        variable,
                        destination,
                    },
                    1,
                )
            }
            #[cfg(windows)]
            {
                let _ = (variable, destination, owner);
                return Err(ForwardError::Protocol(
                    "named-pipe forwarding is not supported on Windows",
                ));
            }
        } else {
            let endpoint = Endpoint::parse(request.source).map_err(ForwardError::Io)?;
            let resolved = endpoint.resolve_for_bind_deadline(deadline, resolver.clone());
            let source = match (resolved, origin) {
                (Ok(source), _) => source,
                (Err(error), ForwardOrigin::SshConfig { strict: false }) => {
                    skipped.push(SkippedForward {
                        request: original,
                        error,
                    });
                    continue;
                }
                (
                    Err(error),
                    ForwardOrigin::Explicit | ForwardOrigin::SshConfig { strict: true },
                ) => return Err(ForwardError::Io(error)),
            };
            if owner.is_some()
                && matches!(
                    &source,
                    ResolvedEndpoint::Tcp(addresses)
                        if addresses.iter().any(|address| address.ip().is_unspecified())
                )
            {
                return Err(ForwardError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "authenticated reverse TCP wildcard bind is not permitted",
                )));
            }
            let listener_count = source.listener_count();
            (
                PlannedSource::Endpoint {
                    source,
                    destination,
                    original,
                    origin,
                },
                listener_count,
            )
        };
        listener_count = listener_count
            .checked_add(additional_listeners)
            .ok_or(ForwardError::Protocol("reverse listener limit exceeded"))?;
        if owner.is_some() && listener_count > MAX_SESSION_LISTENERS {
            return Err(ForwardError::Protocol("reverse listener limit exceeded"));
        }
        plans.push(plan);
    }

    let mut bound = Vec::with_capacity(listener_count);
    #[cfg_attr(windows, allow(unused_mut))]
    let mut environment = Vec::new();
    for plan in plans {
        match plan {
            PlannedSource::Endpoint {
                source,
                destination,
                original,
                origin,
            } => match (
                source.bind_with_user_deadline_resolver(owner, deadline, resolver.clone()),
                origin,
            ) {
                (Ok(listeners), _) => {
                    for listener in listeners {
                        bound.push(BoundSource {
                            listener,
                            destination: destination.clone(),
                        });
                    }
                }
                (Err(error), ForwardOrigin::SshConfig { strict: false }) => {
                    skipped.push(SkippedForward {
                        request: original,
                        error,
                    });
                }
                (
                    Err(error),
                    ForwardOrigin::Explicit | ForwardOrigin::SshConfig { strict: true },
                ) => return Err(ForwardError::Io(error)),
            },
            #[cfg(unix)]
            PlannedSource::Environment {
                variable,
                destination,
            } => {
                let mut pipe = create_forward_pipe(owner)?;
                let source = Endpoint::Unix(pipe.path.clone())
                    .resolve_for_bind_deadline(deadline, resolver.clone())?;
                let mut listeners =
                    source.bind_with_user_deadline_resolver(owner, deadline, resolver.clone())?;
                environment.push((variable, pipe.path.to_string_lossy().into_owned()));
                let directory = pipe.disarm()?;
                for mut listener in listeners.drain(..) {
                    listener.also_remove_dir(directory.clone());
                    bound.push(BoundSource {
                        listener,
                        destination: destination.clone(),
                    });
                }
            }
        }
    }
    ensure_setup_deadline(deadline)?;
    Ok((bound, environment, skipped))
}

fn ensure_setup_deadline(deadline: Instant) -> Result<(), ForwardError> {
    if Instant::now() >= deadline {
        Err(ForwardError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "forwarding setup deadline elapsed",
        )))
    } else {
        Ok(())
    }
}

/// Create the private directory for a named-pipe forward and return the
/// socket path inside it (upstream `et_forward_sock_XXXXXX/sock`).
#[cfg(unix)]
fn create_forward_pipe(owner: Option<(u32, u32)>) -> Result<ForwardPipe, ForwardError> {
    create_forward_pipe_with(owner, |_| Ok(()))
}

#[cfg(unix)]
fn create_forward_pipe_with(
    owner: Option<(u32, u32)>,
    after_create: impl FnOnce(&std::path::Path) -> io::Result<()>,
) -> Result<ForwardPipe, ForwardError> {
    use std::os::unix::fs::DirBuilderExt;
    let (suffix, _) = et_core::keys::gen_id_passkey();
    let directory = std::env::temp_dir().join(format!("et_forward_sock_{suffix}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(ForwardError::Io)?;
    let pipe = ForwardPipe {
        path: directory.join("sock"),
        directory: Some(directory),
    };
    after_create(
        pipe.directory
            .as_deref()
            .ok_or(ForwardError::Protocol("forward pipe directory missing"))?,
    )
    .map_err(ForwardError::Io)?;
    if let (Some((uid, gid)), Some(directory)) = (owner, pipe.directory.as_deref()) {
        std::os::unix::fs::chown(directory, Some(uid), Some(gid)).map_err(ForwardError::Io)?;
    }
    Ok(pipe)
}

#[cfg(unix)]
struct ForwardPipe {
    path: std::path::PathBuf,
    directory: Option<std::path::PathBuf>,
}

#[cfg(unix)]
impl ForwardPipe {
    fn disarm(&mut self) -> Result<std::path::PathBuf, ForwardError> {
        self.directory
            .take()
            .ok_or(ForwardError::Protocol("forward pipe directory missing"))
    }
}

#[cfg(unix)]
impl Drop for ForwardPipe {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.as_ref() {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(directory);
        }
    }
}

#[cfg(unix)]
fn drain_wake(mut wake: &UnixStream) -> Result<(), ForwardError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ForwardError::Io(error)),
        }
    }
}

pub fn is_forward_packet(header: u8) -> bool {
    header == TerminalPacketType::PortForwardDestinationRequest as u8
        || header == TerminalPacketType::PortForwardDestinationResponse as u8
        || header == TerminalPacketType::PortForwardData as u8
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use et_core::proto::{PortForwardData, PortForwardDestinationRequest, SocketEndpoint};
    use prost::Message;
    use std::cell::RefCell;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::unix::net::UnixListener;
    use std::sync::{Barrier, Condvar};

    #[test]
    fn disconnected_priority_does_not_mask_buffered_outbound_packet() {
        let (priority_tx, priority_rx) = channel::bounded::<Outbound>(1);
        let (outbound_tx, outbound_rx) = channel::bounded::<Outbound>(1);
        outbound_tx
            .send(Ok(Packet::new(
                TerminalPacketType::PortForwardData as u8,
                vec![1, 2, 3],
            )))
            .unwrap();
        drop(priority_tx);

        let packet =
            wait_outbound_from(&priority_rx, &outbound_rx, Duration::from_secs(1)).unwrap();

        assert_eq!(packet.payload(), &[1, 2, 3]);
    }

    struct GatedResolver {
        started: mpsc::SyncSender<()>,
        completed: Option<mpsc::SyncSender<()>>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ForwardResolver for GatedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            self.started.send(()).unwrap();
            let (released, changed) = &*self.gate;
            let mut released = released.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            if let Some(completed) = self.completed.as_ref() {
                completed.send(()).unwrap();
            }
            Ok(Vec::new())
        }
    }

    #[test]
    fn queue_admission_time_does_not_extend_resolution_deadline() {
        let executor = Arc::new(ResolverExecutor::new());
        let active_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (active_started_tx, active_started_rx) = mpsc::sync_channel(RESOLVER_WORKERS);
        let start_barrier = Arc::new(Barrier::new(RESOLVER_WORKERS + 1));
        let mut active = Vec::new();
        for index in 0..RESOLVER_WORKERS {
            let executor = executor.clone();
            let gate = active_gate.clone();
            let started = active_started_tx.clone();
            let barrier = start_barrier.clone();
            active.push(std::thread::spawn(move || {
                barrier.wait();
                executor.resolve(
                    Arc::new(GatedResolver {
                        started,
                        completed: None,
                        gate,
                    }),
                    format!("active-{index}"),
                    1,
                    Instant::now() + Duration::from_secs(10),
                )
            }));
        }
        start_barrier.wait();
        for _ in 0..RESOLVER_WORKERS {
            active_started_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
        }

        let admission_delay = Duration::from_millis(1500);
        let queued_deadline = Instant::now() + admission_delay;
        let mut queued_receivers = Vec::new();
        {
            let mut requests = executor.queue.requests.lock().unwrap();
            for index in 0..RESOLVER_QUEUE_CAPACITY {
                let (result, receiver) = mpsc::sync_channel(1);
                queued_receivers.push(receiver);
                requests.push_back(ResolverRequest {
                    resolver: Arc::new(SystemForwardResolver),
                    host: format!("expired-{index}"),
                    port: 1,
                    deadline: queued_deadline,
                    cancelled: Arc::new(AtomicBool::new(false)),
                    result,
                });
            }
            assert_eq!(requests.len(), RESOLVER_QUEUE_CAPACITY);
        }

        let target_start = Instant::now();
        let target_deadline = target_start + Duration::from_secs(3);
        let target_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (target_started_tx, target_started_rx) = mpsc::sync_channel(1);
        let (target_completed_tx, target_completed_rx) = mpsc::sync_channel(1);
        let (target_wait_tx, target_wait_rx) = mpsc::sync_channel(1);
        let (target_decision_tx, target_decision_rx) = mpsc::sync_channel(1);
        let (target_done_tx, target_done_rx) = mpsc::sync_channel(1);
        let target_executor = executor.clone();
        let target_gate_for_resolver = target_gate.clone();
        let target = std::thread::spawn(move || {
            let result = target_executor.resolve_with_observers(
                Arc::new(GatedResolver {
                    started: target_started_tx,
                    completed: Some(target_completed_tx),
                    gate: target_gate_for_resolver,
                }),
                "target".to_owned(),
                1,
                target_deadline,
                |remaining| target_wait_tx.send(remaining).unwrap(),
                |result| {
                    target_decision_tx
                        .send(result.as_ref().map(|_| ()).map_err(io::Error::kind))
                        .unwrap()
                },
            );
            target_done_tx.send(result).unwrap();
        });

        assert!(matches!(
            target_done_rx.recv_timeout(admission_delay),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        executor.queue.changed.notify_all();
        {
            let (released, changed) = &*active_gate;
            *released.lock().unwrap() = true;
            changed.notify_all();
        }
        let target_wait = target_wait_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("target caller did not begin its result wait after admission");
        target_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("target resolver did not start after delayed admission");
        let decision = target_decision_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("target caller did not make a bounded timeout decision");

        {
            let (released, changed) = &*target_gate;
            *released.lock().unwrap() = true;
            changed.notify_all();
        }
        target_completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("late target callback did not complete after release");
        let result = target_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("target caller did not return its timeout decision");
        target.join().unwrap();
        for worker in active {
            worker.join().unwrap().unwrap();
        }
        drop(queued_receivers);

        assert!(
            target_wait <= target_deadline.duration_since(target_start) - admission_delay,
            "queue admission extended the caller's result-wait budget"
        );
        assert_eq!(decision, Err(io::ErrorKind::TimedOut));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn later_unix_source_failure_rolls_back_prior_tcp_listener() {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let directory =
            std::env::temp_dir().join(format!("et-forward-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let occupied = directory.join("occupied.sock");
        std::fs::write(&occupied, b"occupied").unwrap();
        let requests = vec![
            PortForwardSourceRequest {
                source: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(address.port())),
                }),
                destination: None,
                environmentvariable: None,
            },
            PortForwardSourceRequest {
                source: Some(SocketEndpoint {
                    name: Some(occupied.to_string_lossy().into_owned()),
                    port: None,
                }),
                destination: None,
                environmentvariable: None,
            },
        ];
        assert!(Forwarder::start_with_user_deadline(
            requests,
            None,
            Instant::now() + Duration::from_secs(1),
            Arc::new(SystemForwardResolver),
        )
        .is_err());
        TcpListener::bind(address).expect("later source failure retained prior listener");
        std::fs::remove_file(occupied).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_completes_with_command_and_outbound_queues_saturated() {
        let directory = std::env::temp_dir().join(format!(
            "et-forward-saturated-shutdown-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("listener.sock");
        let request = PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(path.to_string_lossy().into_owned()),
                port: None,
            }),
            destination: Some(SocketEndpoint {
                name: Some("localhost".to_owned()),
                port: Some(1),
            }),
            environmentvariable: None,
        };
        let forwarder = Forwarder::start(vec![request]).unwrap();
        let mut fd = 1;
        loop {
            let packet = Packet::new(
                TerminalPacketType::PortForwardDestinationRequest as u8,
                PortForwardDestinationRequest {
                    destination: None,
                    fd: Some(fd),
                    window: None,
                }
                .encode_to_vec(),
            );
            match forwarder.commands.try_send(Command::Packet(packet)) {
                Ok(()) => fd += 1,
                Err(TryCommandError::Full(_)) => break,
                Err(TryCommandError::Closed) => {
                    panic!("forwarding worker stopped before saturation")
                }
            }
        }
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = forwarder.shutdown();
            let _ = done_tx.send(result);
        });
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("forwarder shutdown hung with both queues saturated")
            .unwrap();
        assert!(!path.exists(), "owned Unix listener was not retired");
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn shutdown_and_drop_ignore_a_full_non_emitting_command_queue() {
        for drop_only in [false, true] {
            let directory = std::env::temp_dir().join(format!(
                "ef{}{}",
                std::process::id(),
                u8::from(drop_only)
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let path = directory.join("s");
            let request = PortForwardSourceRequest {
                source: Some(SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                destination: Some(SocketEndpoint {
                    name: Some("localhost".to_owned()),
                    port: Some(1),
                }),
                environmentvariable: None,
            };
            let (worker_entered_tx, worker_entered_rx) = mpsc::sync_channel(1);
            let (worker_release_tx, worker_release_rx) = mpsc::sync_channel(1);
            let (forwarder, _, _) = start_forwarder_hook(
                vec![ForwardSource::explicit(request)],
                None,
                Instant::now() + Duration::from_secs(3),
                Arc::new(SystemForwardResolver),
                || {},
                move || {
                    worker_entered_tx.send(()).unwrap();
                    worker_release_rx.recv().unwrap();
                },
            )
            .unwrap();
            worker_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("forwarding worker did not reach its deterministic gate");

            for socket_id in 1..=CHANNEL_CAPACITY {
                let packet = Packet::new(
                    TerminalPacketType::PortForwardData as u8,
                    PortForwardData {
                        sourcetodestination: Some(false),
                        socketid: Some(i32::try_from(socket_id).unwrap()),
                        buffer: None,
                        error: None,
                        closed: Some(true),
                        window: None,
                    }
                    .encode_to_vec(),
                );
                forwarder
                    .commands
                    .try_send(Command::Packet(packet))
                    .unwrap_or_else(|_| panic!("command queue filled before capacity"));
            }
            let overflow = Packet::new(
                TerminalPacketType::PortForwardData as u8,
                PortForwardData {
                    sourcetodestination: Some(false),
                    socketid: Some(i32::MAX),
                    buffer: None,
                    error: None,
                    closed: Some(true),
                    window: None,
                }
                .encode_to_vec(),
            );
            assert!(matches!(
                forwarder.commands.try_send(Command::Packet(overflow)),
                Err(TryCommandError::Full(_))
            ));

            let shutdown_observer = forwarder.commands.clone();
            let (done_tx, done_rx) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let result = if drop_only {
                    drop(forwarder);
                    Ok(())
                } else {
                    forwarder.shutdown()
                };
                let _ = done_tx.send(result);
            });
            let shutdown_observed = shutdown_observer.wait_shutdown_timeout(Duration::from_secs(2));
            if !shutdown_observed {
                // Failure-only cleanup: release the worker through the queue's
                // independent cancellation path before reporting the defect.
                shutdown_observer.shutdown();
            }
            worker_release_tx.send(()).unwrap();
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("queue-independent shutdown did not join the worker")
                .unwrap();
            assert!(
                shutdown_observed,
                "Forwarder shutdown did not signal queue-independent cancellation"
            );
            assert!(!path.exists(), "shutdown retained the owned Unix listener");
            std::fs::remove_dir(directory).unwrap();
        }
    }

    #[test]
    fn named_pipe_failure_after_directory_creation_cleans_and_retries() {
        // Given
        let created = RefCell::new(None);

        // When
        let error = match create_forward_pipe_with(None, |directory| {
            *created.borrow_mut() = Some(directory.to_path_buf());
            Err(io::Error::other("injected before chown"))
        }) {
            Ok(_) => panic!("injected directory failure succeeded"),
            Err(error) => error,
        };
        let directory = created.into_inner().unwrap();

        // Then
        assert!(matches!(error, ForwardError::Io(_)));
        assert!(!directory.exists());
        std::fs::create_dir(&directory).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn named_pipe_post_bind_failure_cleans_socket_and_directory_then_retries() {
        // Given
        let pipe = create_forward_pipe(None).unwrap();
        let directory = pipe.directory.as_ref().unwrap().clone();
        let path = pipe.path.clone();
        let listener = UnixListener::bind(&path).unwrap();

        // When: a later bind/configuration step fails and ownership never transfers.
        drop(pipe);

        // Then
        assert!(!path.exists());
        assert!(!directory.exists());
        drop(listener);
        std::fs::create_dir(&directory).unwrap();
        let retry = UnixListener::bind(&path).unwrap();
        drop(retry);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
