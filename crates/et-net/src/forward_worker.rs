use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(unix)]
use std::io::Write;
use std::io::{self};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
#[cfg(all(test, unix))]
use std::sync::mpsc;
#[cfg(windows)]
use std::sync::{atomic::AtomicI64, RwLock};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel as channel;

use crate::forward::{ForwardError, Outbound};
use crate::forward_endpoint::ForwardStream;
#[cfg(windows)]
use crate::forward_io::{abort_io, commit_reservation, stop_io, ActiveIo};
use crate::forward_io::{
    spawn_connector, spawn_listener, spawn_socks_listener, BoundSource, FlowWindow, ListenerStop,
};
use et_core::packet::Packet;
use et_core::proto::SocketEndpoint;

const MAX_ACTIVE_SOCKETS: usize = 256;
pub(crate) const MAX_DATA_PACKET: usize = 64 * 1024;
/// Accepted forwards parked until a destination response. A withholding peer
/// must not exhaust the process by leaving this set unbounded.
pub(crate) const MAX_UNASSIGNED_FDS: usize = 128;
pub(crate) const UNASSIGNED_FD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Role {
    Source,
    Destination,
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct FastRoute {
    pub(crate) writer: Option<channel::Sender<Vec<u8>>>,
    pub(crate) pending_bytes: Arc<AtomicUsize>,
    pub(crate) in_flight: Arc<AtomicI64>,
    pub(crate) packets_in_flight: Arc<AtomicI64>,
    pub(crate) window: Arc<AtomicI64>,
    pub(crate) packet_window: Arc<AtomicI64>,
    pub(crate) in_flight_wake: channel::Sender<()>,
}

#[cfg(windows)]
pub(crate) type FastRoutes = Arc<RwLock<HashMap<(Role, i32), FastRoute>>>;

pub(crate) enum Command {
    Packet(Packet),
    Accepted {
        client_fd: i32,
        destination: SocketEndpoint,
        stream: ForwardStream,
        early: Vec<u8>,
        socks_version: Option<u8>,
        half_close_on_eof: bool,
        stdio: bool,
    },
    Connected {
        client_fd: i32,
        socket_id: i32,
        result: io::Result<ForwardStream>,
    },
    // The next four variants exist only for the Windows threaded model: on
    // Unix the poll worker reads, writes, and detects socket EOF/errors
    // inline and never round-trips them through the command queue.
    #[cfg(windows)]
    Read {
        role: Role,
        socket_id: i32,
        buffer: Vec<u8>,
        committed: channel::Sender<()>,
    },
    /// A chunk was written to the local socket. Credit returns on DELIVERY,
    /// not on receipt: returning on receipt makes each side's credit depend
    /// on the peer still being able to send, which deadlocks two saturated
    /// endpoints. Delivery is independent of the peer's credit, so it always
    /// makes progress.
    #[cfg(windows)]
    Drained {
        role: Role,
        socket_id: i32,
        bytes: usize,
    },
    #[cfg(windows)]
    Closed {
        role: Role,
        socket_id: i32,
    },
    #[cfg(windows)]
    IoFailed {
        role: Role,
        socket_id: i32,
        error: io::Error,
    },
    /// Replace the recorded OpenSSH session binds replayed on new connections
    /// to `agent_socket_path`. An empty list leaves forwarding unchanged.
    SetSshAgentSessionBinds {
        agent_socket_path: String,
        binds: Vec<Vec<u8>>,
    },
}

struct CommandQueueState {
    commands: VecDeque<Command>,
    senders: usize,
    receiver_alive: bool,
    shutdown: bool,
}

struct CommandQueue {
    capacity: usize,
    in_flight: AtomicUsize,
    state: Mutex<CommandQueueState>,
    changed: Condvar,
    /// Unix poll-loop wake pipe: the first push onto an empty queue (or a
    /// shutdown) writes one byte so the worker's `poll(2)` wakes.
    #[cfg(unix)]
    wake_writer: Option<std::os::unix::net::UnixStream>,
    #[cfg(unix)]
    wake_signalled: AtomicBool,
}

pub(crate) struct CommandSender {
    queue: Arc<CommandQueue>,
}

pub(crate) struct CommandReceiver {
    queue: Arc<CommandQueue>,
    #[cfg(unix)]
    wake_reader: Option<std::os::unix::net::UnixStream>,
}

pub(crate) enum TryCommandError {
    Full(Command),
    Closed,
}

/// Non-blocking pop result for the Unix poll loop.
#[allow(dead_code)]
pub(crate) enum CommandPop {
    Command(Command),
    Empty,
    Disconnected,
}

pub(crate) fn command_channel(capacity: usize) -> (CommandSender, CommandReceiver) {
    #[cfg(unix)]
    let (wake_reader, wake_writer) = std::os::unix::net::UnixStream::pair()
        .ok()
        .and_then(|(reader, writer)| {
            reader.set_nonblocking(true).ok()?;
            writer.set_nonblocking(true).ok()?;
            Some((reader, writer))
        })
        .map(|(reader, writer)| (Some(reader), Some(writer)))
        .unwrap_or((None, None));
    let queue = Arc::new(CommandQueue {
        capacity,
        in_flight: AtomicUsize::new(0),
        state: Mutex::new(CommandQueueState {
            commands: VecDeque::with_capacity(capacity),
            senders: 1,
            receiver_alive: true,
            shutdown: false,
        }),
        changed: Condvar::new(),
        #[cfg(unix)]
        wake_writer,
        #[cfg(unix)]
        wake_signalled: AtomicBool::new(false),
    });
    (
        CommandSender {
            queue: queue.clone(),
        },
        CommandReceiver {
            queue,
            #[cfg(unix)]
            wake_reader,
        },
    )
}

impl Clone for CommandSender {
    fn clone(&self) -> Self {
        let mut state = self.queue.state.lock().unwrap();
        state.senders += 1;
        drop(state);
        Self {
            queue: self.queue.clone(),
        }
    }
}

impl Drop for CommandSender {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap();
        state.senders -= 1;
        self.queue.changed.notify_all();
    }
}

impl CommandQueue {
    /// Wake the Unix poll loop when a push transitions the queue from empty.
    /// Must be called with the state lock held; the byte write itself is
    /// non-blocking and idempotent because of the signalled flag.
    #[cfg(unix)]
    fn signal_wake(&self, was_empty: bool) {
        if !was_empty {
            return;
        }
        if self.wake_signalled.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(writer) = &self.wake_writer {
            use std::io::Write;
            let _ = (&mut &*writer).write(&[1]);
        }
    }

    /// Clear the signalled flag once the queue drains to empty. Must be
    /// called with the state lock held so a concurrent push cannot lose its
    /// wake byte. Returns whether the queue was empty.
    #[cfg(unix)]
    fn clear_wake_if_empty(&self, state: &CommandQueueState) -> bool {
        if state.commands.is_empty() {
            self.wake_signalled.store(false, Ordering::Release);
            true
        } else {
            false
        }
    }
}

impl CommandSender {
    pub(crate) fn send(&self, command: Command) -> Result<(), Command> {
        let mut state = self.queue.state.lock().unwrap();
        while state.commands.len() >= self.queue.capacity && !state.shutdown && state.receiver_alive
        {
            state = self.queue.changed.wait(state).unwrap();
        }
        if state.shutdown || !state.receiver_alive {
            return Err(command);
        }
        let was_empty = state.commands.is_empty();
        self.queue.in_flight.fetch_add(1, Ordering::AcqRel);
        state.commands.push_back(command);
        if was_empty {
            self.queue.changed.notify_all();
        }
        #[cfg(unix)]
        self.queue.signal_wake(was_empty);
        Ok(())
    }

    pub(crate) fn try_send(&self, command: Command) -> Result<(), TryCommandError> {
        let mut state = self.queue.state.lock().unwrap();
        if state.shutdown || !state.receiver_alive {
            return Err(TryCommandError::Closed);
        }
        if state.commands.len() >= self.queue.capacity {
            return Err(TryCommandError::Full(command));
        }
        let was_empty = state.commands.is_empty();
        self.queue.in_flight.fetch_add(1, Ordering::AcqRel);
        state.commands.push_back(command);
        if was_empty {
            self.queue.changed.notify_all();
        }
        #[cfg(unix)]
        self.queue.signal_wake(was_empty);
        Ok(())
    }

    pub(crate) fn try_send_batched(&self, command: Command) -> Result<(), TryCommandError> {
        let mut state = self.queue.state.lock().unwrap();
        if state.shutdown || !state.receiver_alive {
            return Err(TryCommandError::Closed);
        }
        if state.commands.len() >= self.queue.capacity {
            #[cfg(unix)]
            self.queue.signal_wake(true);
            return Err(TryCommandError::Full(command));
        }
        let was_empty = state.commands.is_empty();
        self.queue.in_flight.fetch_add(1, Ordering::AcqRel);
        state.commands.push_back(command);
        if was_empty {
            self.queue.changed.notify_all();
        }
        #[cfg(unix)]
        if state.commands.len() >= 16 {
            self.queue.signal_wake(true);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn try_send_queue(&self, queue: &mut VecDeque<Packet>) -> Result<(), ForwardError> {
        if queue.is_empty() {
            return Ok(());
        }
        let mut state = self.queue.state.lock().unwrap();
        if state.shutdown || !state.receiver_alive {
            return Err(ForwardError::Unavailable);
        }
        let was_empty = state.commands.is_empty();
        let avail = self.queue.capacity.saturating_sub(state.commands.len());
        let count = queue.len().min(avail);
        for _ in 0..count {
            if let Some(packet) = queue.pop_front() {
                state.commands.push_back(Command::Packet(packet));
            }
        }
        if count > 0 {
            self.queue.in_flight.fetch_add(count, Ordering::AcqRel);
            if was_empty {
                self.queue.changed.notify_all();
            }
            #[cfg(unix)]
            self.queue.signal_wake(true);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn flush_wake(&self) {
        if self.queue.in_flight.load(Ordering::Acquire) == 0
            || self.queue.wake_signalled.load(Ordering::Acquire)
        {
            return;
        }
        let state = self.queue.state.lock().unwrap();
        if !state.commands.is_empty() {
            self.queue.signal_wake(true);
        }
    }

    pub(crate) fn shutdown(&self) {
        let mut state = self.queue.state.lock().unwrap();
        state.shutdown = true;
        self.queue.changed.notify_all();
        #[cfg(unix)]
        {
            if !self.queue.wake_signalled.swap(true, Ordering::AcqRel) {
                if let Some(writer) = &self.queue.wake_writer {
                    use std::io::Write;
                    let _ = (&mut &*writer).write(&[1]);
                }
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue
            .state
            .lock()
            .map_or(true, |state| state.commands.is_empty())
    }

    #[cfg(windows)]
    pub(crate) fn is_idle(&self) -> bool {
        self.queue.in_flight.load(Ordering::Acquire) == 0
    }
    #[cfg(all(test, unix))]
    pub(crate) fn wait_shutdown_timeout(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.queue.state.lock().unwrap();
        while !state.shutdown {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return false;
            };
            let (next, wait) = self.queue.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && !state.shutdown {
                return false;
            }
        }
        true
    }
}

#[cfg(windows)]
enum RecvStatus {
    Command(Command),
    Timeout,
    Disconnected,
}

impl CommandReceiver {
    /// Read end of the wake pipe, polled by the Unix worker loop.
    #[cfg(unix)]
    pub(crate) fn wake_reader(&self) -> &std::os::unix::net::UnixStream {
        self.wake_reader
            .as_ref()
            .expect("command wake pipe unavailable")
    }

    #[cfg(unix)]
    pub(crate) fn has_pending(&self) -> bool {
        self.queue.in_flight.load(Ordering::Acquire) > 0
    }

    /// Drain pending wake bytes after the pipe reports readable.
    #[cfg(unix)]
    pub(crate) fn drain_wake(&self) {
        use std::io::Read;
        let Some(reader) = &self.wake_reader else {
            return;
        };
        let mut buffer = [0u8; 64];
        loop {
            match (&mut &*reader).read(&mut buffer) {
                Ok(0) => return,
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }

    /// Re-arm the wake after a drain cycle emptied the queue. If a push
    /// landed after the last pop, the flag stays set and a wake byte is
    /// written: that push skipped its own byte because the flag was still
    /// set, so the pipe would otherwise stay quiet.
    #[cfg(unix)]
    pub(crate) fn arm_wake(&self) {
        let state = self.queue.state.lock().unwrap();
        if !self.queue.clear_wake_if_empty(&state) {
            if let Some(writer) = &self.queue.wake_writer {
                use std::io::Write;
                let _ = (&mut &*writer).write(&[1]);
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn drain_batch(&self, batch: &mut Vec<Command>) -> bool {
        let mut state = self.queue.state.lock().unwrap();
        if state.shutdown || state.senders == 0 {
            return false;
        }
        let was_full = state.commands.len() >= self.queue.capacity;
        batch.extend(state.commands.drain(..));
        if was_full && state.commands.len() < self.queue.capacity {
            self.queue.changed.notify_all();
        }
        // If the queue was drained to empty, the wake pipe must be drained so
        // the next poll does not spin on a stale byte.
        if state.commands.is_empty() {
            self.queue.wake_signalled.store(false, Ordering::Release);
            if let Some(reader) = &self.wake_reader {
                use std::io::Read;
                let mut buffer = [0u8; 64];
                loop {
                    match (&mut &*reader).read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            }
        } else if !self.queue.wake_signalled.swap(true, Ordering::AcqRel) {
            // If the queue still has packets but the flag was cleared by a
            // racing session pop, re-write the wake byte so the next poll
            // returns immediately.
            if let Some(writer) = &self.queue.wake_writer {
                use std::io::Write;
                let _ = (&mut &*writer).write(&[1]);
            }
        }
        true
    }

    #[cfg(unix)]
    pub(crate) fn complete_count(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.queue.in_flight.fetch_sub(count, Ordering::AcqRel);
        // If the worker had to queue commands because the queue was empty,
        // we must re-arm the wake flag so `has_pending()` is false and the
        // worker sleeps until new work arrives.
        if self.queue.in_flight.load(Ordering::Acquire) == 0 {
            self.queue.wake_signalled.store(false, Ordering::Release);
        }
    }
    /// Non-blocking pop for the Unix poll loop. Like `recv_until`, shutdown
    /// (or all senders leaving) short-circuits even a full queue: graceful
    /// stop discards pending commands rather than draining them behind a
    /// congested outbound channel.
    #[cfg(unix)]
    #[allow(dead_code)]
    pub(crate) fn pop(&self) -> CommandPop {
        let mut state = self.queue.state.lock().unwrap();
        if state.shutdown || state.senders == 0 {
            return CommandPop::Disconnected;
        }
        if let Some(command) = state.commands.pop_front() {
            if state.commands.len() + 1 >= self.queue.capacity {
                self.queue.changed.notify_all();
            }
            // The wake flag stays set until the poll cycle finishes draining
            // the queue. Clearing it per pop would make every packet pushed
            // during the drain write its own wake byte.
            return CommandPop::Command(command);
        }
        CommandPop::Empty
    }

    #[cfg(windows)]
    fn recv_until(&self, deadline: Option<Instant>) -> RecvStatus {
        let mut state = self.queue.state.lock().unwrap();
        loop {
            if state.shutdown || state.senders == 0 {
                return RecvStatus::Disconnected;
            }
            if let Some(command) = state.commands.pop_front() {
                if state.commands.len() + 1 >= self.queue.capacity {
                    self.queue.changed.notify_all();
                }
                #[cfg(unix)]
                self.queue.clear_wake_if_empty(&state);
                return RecvStatus::Command(command);
            }
            let Some(deadline) = deadline else {
                state = self.queue.changed.wait(state).unwrap();
                continue;
            };
            let now = Instant::now();
            if now >= deadline {
                return RecvStatus::Timeout;
            }
            let (next, wait) = self
                .queue
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap();
            state = next;
            if wait.timed_out()
                && state.commands.is_empty()
                && !state.shutdown
                && state.senders != 0
            {
                return RecvStatus::Timeout;
            }
        }
    }

    #[allow(dead_code)]
    fn complete_one(&self) {
        self.queue.in_flight.fetch_sub(1, Ordering::AcqRel);
    }

    #[cfg(all(test, unix))]
    pub(crate) fn recv_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Command, mpsc::RecvTimeoutError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.queue.state.lock().unwrap();
        loop {
            if state.shutdown || state.senders == 0 {
                return Err(mpsc::RecvTimeoutError::Disconnected);
            }
            if let Some(command) = state.commands.pop_front() {
                self.queue.changed.notify_all();
                #[cfg(unix)]
                self.queue.clear_wake_if_empty(&state);
                return Ok(command);
            }
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return Err(mpsc::RecvTimeoutError::Timeout);
            };
            let (next, wait) = self.queue.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && state.commands.is_empty() {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
        }
    }
}

impl Drop for CommandReceiver {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap();
        state.receiver_alive = false;
        self.queue.changed.notify_all();
    }
}

pub(crate) struct WorkerChannels {
    pub(crate) receiver: CommandReceiver,
    pub(crate) sender: CommandSender,
    pub(crate) outbound: channel::Sender<Outbound>,
    pub(crate) priority: channel::Sender<Outbound>,
    pub(crate) cancel: channel::Receiver<()>,
    pub(crate) abandoned: Arc<AtomicBool>,
    pub(crate) stdio_open: Option<Arc<AtomicBool>>,
    pub(crate) next_client_fd: Arc<AtomicI32>,
    #[cfg(windows)]
    pub(crate) routes: FastRoutes,
    #[cfg(unix)]
    pub(crate) wake_signalled: Arc<AtomicBool>,
}

pub(crate) fn run(
    sources: Vec<BoundSource>,
    channels: WorkerChannels,
    #[cfg(unix)] outbound_wake: UnixStream,
    control: (ListenerStop, Option<(u32, u32)>, Arc<AtomicBool>),
) {
    let WorkerChannels {
        receiver: commands,
        sender: command_sender,
        outbound,
        priority,
        cancel,
        abandoned,
        stdio_open,
        next_client_fd,
        #[cfg(windows)]
        routes,
        #[cfg(unix)]
        wake_signalled,
    } = channels;
    let (listener_stop, session_user, shutdown) = control;
    #[cfg(unix)]
    let result = Worker::new(
        command_sender,
        outbound.clone(),
        priority.clone(),
        outbound_wake.try_clone().ok(),
        cancel.clone(),
        abandoned,
    )
    .and_then(|mut worker| {
        worker.wake_signalled = wake_signalled.clone();
        worker.run(
            sources,
            commands,
            listener_stop,
            session_user,
            stdio_open,
            next_client_fd,
        )
    });
    #[cfg(windows)]
    let result = Worker::new(
        command_sender,
        outbound.clone(),
        priority.clone(),
        cancel.clone(),
        abandoned,
    )
    .and_then(|mut worker| {
        worker.routes = routes;
        worker.direct_enabled = true;
        worker.run(
            sources,
            commands,
            listener_stop,
            session_user,
            stdio_open,
            next_client_fd,
        )
    });
    // Stop externally owned listeners even if publishing the failure is
    // blocked by a full outbound queue.
    let was_shutdown = shutdown.swap(true, Ordering::AcqRel);
    if let Err(error) = result {
        if !was_shutdown {
            channel::select! {
                send(outbound, Err(error)) -> _ => {}
                recv(cancel) -> _ => {}
            }
        }
        #[cfg(unix)]
        {
            wake_signalled.store(true, Ordering::Release);
            let _ = (&outbound_wake).write(&[1]);
        }
    }
}

struct Worker {
    commands: CommandSender,
    outbound: channel::Sender<Outbound>,
    priority: channel::Sender<Outbound>,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
    #[cfg(windows)]
    routes: FastRoutes,
    #[cfg(windows)]
    direct_enabled: bool,
    #[cfg(unix)]
    outbound_wake: Arc<UnixStream>,
    /// Outbound packets the poll loop could not hand to the session because
    /// the channel was full. Drained before new socket reads so ordering holds.
    #[cfg(unix)]
    outbound_spill: std::collections::VecDeque<crate::forward::Outbound>,
    #[cfg(unix)]
    wake_signalled: Arc<AtomicBool>,
    #[cfg(unix)]
    pub(super) defer_outbound_wake: bool,
    pending: HashMap<i32, PendingAccept>,
    connecting: HashSet<i32>,
    #[cfg(unix)]
    sources: HashMap<i32, poll::SocketIo>,
    #[cfg(unix)]
    destinations: HashMap<i32, poll::SocketIo>,
    #[cfg(windows)]
    sources: HashMap<i32, ActiveIo>,
    #[cfg(windows)]
    destinations: HashMap<i32, ActiveIo>,
    /// Network data held because the target socket's queue was full. Unix
    /// only: the poll worker retries these before popping new commands.
    #[cfg(unix)]
    held: std::collections::VecDeque<(Role, i32, Vec<u8>)>,
    #[cfg(unix)]
    read_scratch: Box<[u8; crate::forward_io::READ_CHUNK]>,
    /// Window the peer advertised for a socket still being connected, held
    /// until the socket becomes active and credit can be attached to it.
    pending_windows: HashMap<i32, Option<FlowWindow>>,
    threads: Vec<JoinHandle<()>>,
    next_socket_id: i32,
    session_user: Option<(u32, u32)>,
    stdio_open: Option<Arc<AtomicBool>>,
    stdio_socket: Option<i32>,
    /// Forwarded ssh-agent socket that receives session bindings.
    ssh_agent_socket_path: String,
    /// Session-bind request bodies replayed on new agent connections.
    ssh_agent_session_binds: Vec<Vec<u8>>,
    /// Binds snapshotted for a destination connect that has not finished.
    pending_agent_binds: HashMap<i32, crate::ssh_agent_session_bind::PendingSessionBinds>,
}

struct PendingAccept {
    stream: ForwardStream,
    early: Vec<u8>,
    socks_version: Option<u8>,
    half_close_on_eof: bool,
    stdio: bool,
    /// When the destination response must have arrived. After this the parked
    /// socket is closed so a late reply cannot attach to a recycled token.
    deadline: Instant,
}

impl PendingAccept {
    fn park(
        stream: ForwardStream,
        early: Vec<u8>,
        socks_version: Option<u8>,
        half_close_on_eof: bool,
        stdio: bool,
    ) -> Self {
        Self {
            stream,
            early,
            socks_version,
            half_close_on_eof,
            stdio,
            deadline: Instant::now() + UNASSIGNED_FD_TIMEOUT,
        }
    }
}

impl Worker {
    fn new(
        commands: CommandSender,
        outbound: channel::Sender<Outbound>,
        priority: channel::Sender<Outbound>,
        #[cfg(unix)] outbound_wake: Option<UnixStream>,
        cancel: channel::Receiver<()>,
        abandoned: Arc<AtomicBool>,
    ) -> Result<Self, ForwardError> {
        #[cfg(unix)]
        let outbound_wake = {
            let wake = outbound_wake.ok_or(ForwardError::Unavailable)?;
            wake.set_nonblocking(true).map_err(ForwardError::Io)?;
            Arc::new(wake)
        };
        Ok(Self {
            commands,
            outbound,
            priority,
            cancel,
            abandoned,
            #[cfg(windows)]
            routes: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(windows)]
            direct_enabled: false,
            #[cfg(unix)]
            outbound_wake,
            #[cfg(unix)]
            outbound_spill: std::collections::VecDeque::new(),
            #[cfg(unix)]
            wake_signalled: Arc::new(AtomicBool::new(false)),
            #[cfg(unix)]
            defer_outbound_wake: false,
            pending: HashMap::new(),
            connecting: HashSet::new(),
            sources: HashMap::new(),
            destinations: HashMap::new(),
            #[cfg(unix)]
            held: std::collections::VecDeque::new(),
            #[cfg(unix)]
            read_scratch: Box::new([0u8; crate::forward_io::READ_CHUNK]),
            pending_windows: HashMap::new(),
            threads: Vec::new(),
            next_socket_id: 1,
            session_user: None,
            stdio_open: None,
            stdio_socket: None,
            ssh_agent_socket_path: String::new(),
            ssh_agent_session_binds: Vec::new(),
            pending_agent_binds: HashMap::new(),
        })
    }

    fn run(
        &mut self,
        sources: Vec<BoundSource>,
        commands: CommandReceiver,
        listener_stop: ListenerStop,
        session_user: Option<(u32, u32)>,
        stdio_open: Option<Arc<AtomicBool>>,
        next_client_fd: Arc<AtomicI32>,
    ) -> Result<(), ForwardError> {
        self.session_user = session_user;
        self.stdio_open = stdio_open;
        for source in sources {
            if source.stdio {
                #[cfg(unix)]
                {
                    let destination = source.destination;
                    self.threads.push(
                        crate::forward_io::spawn_stdio(
                            destination,
                            self.commands.clone(),
                            self.cancel.clone(),
                            next_client_fd.clone(),
                            (self.stdio_open.clone(), self.outbound_wake.try_clone().ok()),
                        )
                        .map_err(ForwardError::Io)?,
                    );
                    continue;
                }
                #[cfg(windows)]
                {
                    let _ = source;
                    return Err(ForwardError::Protocol(
                        "-W/--stdio-forward is not supported on Windows",
                    ));
                }
            }
            #[cfg(unix)]
            let stop = listener_stop.try_clone().map_err(ForwardError::Io)?;
            #[cfg(windows)]
            let stop = listener_stop.clone();
            let thread = if source.socks {
                spawn_socks_listener(
                    source,
                    self.commands.clone(),
                    self.cancel.clone(),
                    stop,
                    next_client_fd.clone(),
                )
            } else {
                spawn_listener(
                    source,
                    self.commands.clone(),
                    self.cancel.clone(),
                    stop,
                    Arc::new(AtomicBool::new(false)),
                    next_client_fd.clone(),
                )
            };
            self.threads.push(thread);
        }
        let result = self.run_loop(commands);
        #[cfg(windows)]
        self.routes.write().unwrap().clear();
        #[cfg(unix)]
        let _ = listener_stop.shutdown(std::net::Shutdown::Both);
        #[cfg(windows)]
        listener_stop.store(true, std::sync::atomic::Ordering::Release);
        for (_, pending) in self.pending.drain() {
            pending.stream.shutdown();
        }
        let hard_cancelled = !matches!(self.cancel.try_recv(), Err(channel::TryRecvError::Empty));
        #[cfg(unix)]
        self.stop_sockets(hard_cancelled);
        #[cfg(windows)]
        for (_, io) in self.sources.drain().chain(self.destinations.drain()) {
            if hard_cancelled {
                abort_io(io);
            } else {
                stop_io(io);
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        result
    }

    #[cfg(windows)]
    fn run_loop(&mut self, commands: CommandReceiver) -> Result<(), ForwardError> {
        loop {
            self.expire_parked();
            let command = match commands.recv_until(self.next_park_deadline()) {
                RecvStatus::Command(command) => command,
                RecvStatus::Timeout => continue,
                RecvStatus::Disconnected => break Ok(()),
            };
            let step = self.handle_command(command);
            commands.complete_one();
            if let Err(error) = step {
                break Err(error);
            }
        }
    }

    #[cfg(unix)]
    fn run_loop(&mut self, commands: CommandReceiver) -> Result<(), ForwardError> {
        self.run_poll(&commands)
    }

    fn handle_command(&mut self, command: Command) -> Result<(), ForwardError> {
        match command {
            Command::Packet(packet) => self.handle_packet(packet),
            Command::Accepted {
                client_fd,
                destination,
                stream,
                early,
                socks_version,
                half_close_on_eof,
                stdio,
            } => self.accepted(
                client_fd,
                destination,
                PendingAccept::park(stream, early, socks_version, half_close_on_eof, stdio),
            ),
            Command::Connected {
                client_fd,
                socket_id,
                result,
            } => {
                let advertised = self.pending_windows.remove(&socket_id).flatten();
                self.connected(client_fd, socket_id, result, advertised)
            }
            #[cfg(windows)]
            Command::Read {
                role,
                socket_id,
                buffer,
                committed,
            } => {
                if let Some(active) = self.map_ref(role).get(&socket_id) {
                    commit_reservation(active, i64::try_from(buffer.len()).unwrap_or(i64::MAX));
                    let _ = committed.try_send(());
                    self.send_data(role, socket_id, buffer, false, None)
                } else {
                    let _ = committed.try_send(());
                    Ok(())
                }
            }
            #[cfg(windows)]
            Command::Drained {
                role,
                socket_id,
                bytes,
            } => self.return_credit(role, socket_id, bytes),
            #[cfg(windows)]
            Command::Closed { role, socket_id } => self.read_closed(role, socket_id),
            #[cfg(windows)]
            Command::IoFailed {
                role,
                socket_id,
                error,
            } => {
                self.remove(role, socket_id);
                self.send_data(role, socket_id, Vec::new(), true, Some(error.to_string()))
            }
            Command::SetSshAgentSessionBinds {
                agent_socket_path,
                binds,
            } => {
                self.ssh_agent_socket_path = agent_socket_path;
                self.ssh_agent_session_binds = binds;
                Ok(())
            }
        }
    }
}
#[path = "forward_worker_state.rs"]
pub(crate) mod state;

#[cfg(unix)]
#[path = "forward_poll.rs"]
pub(crate) mod poll;

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crossbeam_channel as channel;
    use et_core::packet::Packet;
    use et_core::proto::{
        PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
        SocketEndpoint, TerminalPacketType,
    };
    use prost::Message;

    use super::{
        command_channel, Command, CommandReceiver, PendingAccept, Role, Worker, MAX_ACTIVE_SOCKETS,
    };
    use crate::forward_endpoint::ForwardStream;

    const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

    fn worker() -> (
        Worker,
        CommandReceiver,
        channel::Receiver<crate::forward::Outbound>,
        channel::Sender<()>,
    ) {
        let (commands, command_receiver) = command_channel(MAX_ACTIVE_SOCKETS + 1);
        let (outbound, outbound_receiver) = channel::bounded(MAX_ACTIVE_SOCKETS + 1);
        // Tests observe a single stream, so credit shares the same receiver.
        let priority = outbound.clone();
        let (cancel, cancel_receiver) = channel::bounded(1);
        let (_wake_reader, wake_writer) = UnixStream::pair().unwrap();
        (
            Worker::new(
                commands,
                outbound,
                priority,
                Some(wake_writer),
                cancel_receiver,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap(),
            command_receiver,
            outbound_receiver,
            cancel,
        )
    }

    struct RemoveDirectory(std::path::PathBuf);

    impl Drop for RemoveDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_directory(name: &str) -> (std::path::PathBuf, RemoveDirectory) {
        let path =
            std::path::PathBuf::from(format!("/tmp/et-forward-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        (path.clone(), RemoveDirectory(path))
    }

    fn destination_request(fd: i32, path: &std::path::Path) -> Packet {
        Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                fd: Some(fd),
                window: None,
            }
            .encode_to_vec(),
        )
    }

    fn response(packet: Packet) -> PortForwardDestinationResponse {
        assert_eq!(
            packet.header(),
            TerminalPacketType::PortForwardDestinationResponse as u8
        );
        PortForwardDestinationResponse::decode(packet.payload()).unwrap()
    }

    fn forward_data(to_destination: bool, socket_id: i32, data: PortForwardData) -> Packet {
        Packet::new(
            TerminalPacketType::PortForwardData as u8,
            PortForwardData {
                sourcetodestination: Some(to_destination),
                socketid: Some(socket_id),
                ..data
            }
            .encode_to_vec(),
        )
    }

    fn closed() -> PortForwardData {
        PortForwardData {
            closed: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn peer_close_fully_closes_the_stdio_source_and_leaves_the_bridge_to_stdout() {
        // Given: an active `et -W` source whose stdin is still open.
        let (mut worker, _commands, outbound, _cancel) = worker();
        let open = Arc::new(AtomicBool::new(true));
        worker.stdio_open = Some(open.clone());
        let (worker_end, mut application) = UnixStream::pair().unwrap();
        application.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
        worker
            .accepted(
                1,
                SocketEndpoint::default(),
                PendingAccept::park(
                    ForwardStream::Unix(worker_end),
                    Vec::new(),
                    None,
                    true,
                    true,
                ),
            )
            .unwrap();
        let _request = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();
        worker
            .handle_packet(Packet::new(
                TerminalPacketType::PortForwardDestinationResponse as u8,
                PortForwardDestinationResponse {
                    clientfd: Some(1),
                    socketid: Some(5),
                    error: None,
                    window: None,
                }
                .encode_to_vec(),
            ))
            .unwrap();
        assert_eq!(worker.sources.len(), 1);

        // When: the remote destination closes before stdin reaches EOF.
        worker
            .handle_packet(forward_data(false, 5, closed()))
            .unwrap();

        // Then: like upstream `closeSourceSocketId`, the source closes in full
        // and its reply side ends. The stdout copier, not the worker, reports
        // the bridge closed once that reply is flushed.
        assert!(worker.sources.is_empty());
        let mut rest = Vec::new();
        application.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        assert!(open.load(Ordering::Acquire));
        drop(application);
        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    #[test]
    fn destination_half_close_keeps_the_reply_and_drops_later_writes() {
        // Given: an active destination socket.
        let (mut worker, _commands, outbound, _cancel) = worker();
        let (stream, mut application) = UnixStream::pair().unwrap();
        application.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
        worker
            .connected(1, 7, Ok(ForwardStream::Unix(stream)), None)
            .unwrap();
        let _response = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();

        // When: the source half-closes (`et -W` stdin EOF), then a stray
        // write for the same socket follows.
        let half_close = PortForwardData {
            half_close: Some(true),
            ..closed()
        };
        worker
            .handle_packet(forward_data(true, 7, half_close))
            .unwrap();
        let mut received = Vec::new();
        application.read_to_end(&mut received).unwrap();
        assert!(received.is_empty());
        let late = PortForwardData {
            buffer: Some(b"late".to_vec()),
            ..Default::default()
        };
        worker.handle_packet(forward_data(true, 7, late)).unwrap();

        // Then: like upstream `shutdownWrite`, the late write is dropped
        // without failing the forwarder and the reply direction still reads.
        assert_eq!(worker.destinations.len(), 1);
        application.write_all(b"reply").unwrap();
        worker.poll_once(EVENT_TIMEOUT).unwrap();
        let reply = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();
        let data = PortForwardData::decode(reply.payload()).unwrap();
        assert_eq!(data.buffer.as_deref(), Some(b"reply".as_slice()));
        worker
            .handle_packet(forward_data(true, 7, closed()))
            .unwrap();
        assert!(worker.destinations.is_empty());
        drop(application);
        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    #[test]
    fn eof_for_a_socket_the_peer_already_closed_emits_nothing() {
        // Given: a socket id the peer's close already removed.
        let (mut worker, _commands, outbound, _cancel) = worker();

        // When: its reader reports EOF afterwards.
        worker.read_closed(Role::Source, 42).unwrap();

        // Then: no second close reaches the peer, as upstream only reports
        // EOF for a socket it still owns.
        assert!(outbound.try_recv().is_err());
    }

    #[test]
    fn local_eof_reports_close_immediately_and_graceful_stop_flushes_the_queue() {
        let (mut worker, outbound, mut peer, _cancel) = queued_destination();
        let abandoned = worker.abandoned.clone();
        assert_eq!(worker.held.len(), 1);

        // Local EOF reports the close immediately, independent of the queued
        // backlog, and keeps the socket until its queue drains — upstream
        // flushes pending writes before closing the socket in full.
        worker.read_closed(Role::Destination, 7).unwrap();
        let close = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();
        assert_eq!(
            PortForwardData::decode(close.payload()).unwrap().closed,
            Some(true)
        );
        assert!(worker.destinations.contains_key(&7));

        // Graceful stop delivers the admitted queue in order. The packet
        // still held worker-side is dropped, as the threaded model dropped
        // commands admitted after a close.
        let draining = std::thread::spawn(move || {
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            received
        });
        worker.stop_sockets(false);
        let received = draining.join().unwrap();
        let expected: Vec<u8> = (1..=64).collect();
        assert_eq!(received, expected);
        assert!(!abandoned.load(Ordering::Acquire));
        assert!(worker.destinations.is_empty());
    }

    #[test]
    fn peer_close_flushes_queued_writes_before_full_close() {
        let (mut worker, outbound, mut peer, _cancel) = queued_destination();

        // When: the peer closes behind a full queue, the close is echoed at
        // once but the socket stays until the backlog is written out.
        worker
            .handle_packet(forward_data(true, 7, closed()))
            .unwrap();
        let echo = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();
        assert_eq!(
            PortForwardData::decode(echo.payload()).unwrap().closed,
            Some(true)
        );
        assert!(worker.destinations.contains_key(&7));

        let draining = std::thread::spawn(move || {
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            received
        });
        while worker.destinations.contains_key(&7) {
            worker.poll_once(EVENT_TIMEOUT).unwrap();
        }
        let received = draining.join().unwrap();
        let expected: Vec<u8> = (1..=64).collect();
        assert_eq!(received, expected);
    }

    #[test]
    fn peer_half_close_flushes_then_shuts_only_the_write_side() {
        let (mut worker, _outbound, mut peer, _cancel) = queued_destination();
        worker
            .handle_packet(forward_data(
                true,
                7,
                PortForwardData {
                    half_close: Some(true),
                    ..closed()
                },
            ))
            .unwrap();
        assert!(worker.destinations.contains_key(&7));

        // Then: queued bytes drain in order and the app sees EOF afterwards,
        // while the socket stays open for the reply direction.
        let mut received = Vec::new();
        while received.len() < 64 {
            worker.poll_once(EVENT_TIMEOUT).unwrap();
            let mut chunk = [0u8; 64];
            let count = peer.read(&mut chunk).unwrap();
            received.extend_from_slice(&chunk[..count]);
        }
        let expected: Vec<u8> = (1..=64).collect();
        assert_eq!(received, expected);
        let mut eof = [0u8; 1];
        assert_eq!(peer.read(&mut eof).unwrap(), 0);
        assert!(worker.destinations.contains_key(&7));
    }

    #[test]
    fn graceful_stop_flushes_held_data_for_healthy_sockets() {
        let (mut worker, _outbound, mut peer, _cancel) = queued_destination();
        let abandoned = worker.abandoned.clone();

        // Then: with no close in play, graceful stop delivers the full queue
        // AND the packet held behind it, in order.
        let draining = std::thread::spawn(move || {
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            received
        });
        worker.stop_sockets(false);
        let received = draining.join().unwrap();
        let expected: Vec<u8> = (1..=65).collect();
        assert_eq!(received, expected);
        assert!(!abandoned.load(Ordering::Acquire));
    }

    #[test]
    fn hard_cancel_abandons_queued_and_held_socket_writes() {
        let (mut worker, _outbound, _peer, _cancel) = queued_destination();
        let abandoned = worker.abandoned.clone();
        assert_eq!(worker.held.len(), 1);

        // Then: hard cancellation reports the queued and held bytes as
        // abandoned and closes everything without waiting for the peer.
        worker.stop_sockets(true);
        assert!(abandoned.load(Ordering::Acquire));
        assert!(worker.destinations.is_empty());
        assert!(worker.held.is_empty());
    }

    fn queued_destination() -> (
        Worker,
        channel::Receiver<crate::forward::Outbound>,
        UnixStream,
        channel::Sender<()>,
    ) {
        let (mut worker, _commands, outbound, cancel) = worker();
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
        worker
            .connected(1, 7, Ok(ForwardStream::Unix(stream)), None)
            .unwrap();
        let _ = outbound.recv_timeout(EVENT_TIMEOUT).unwrap();
        // 64 buffers fill the per-socket queue; the 65th is held worker-side.
        for byte in 1..=65u8 {
            worker
                .handle_packet(forward_data(
                    true,
                    7,
                    PortForwardData {
                        buffer: Some(vec![byte]),
                        ..Default::default()
                    },
                ))
                .unwrap();
        }
        (worker, outbound, peer, cancel)
    }

    #[test]
    fn in_flight_connectors_count_toward_socket_limit_and_failure_releases_slot() {
        let (directory, _cleanup) = test_directory("connector-failure-test");
        let missing_socket = directory.join("missing.sock");
        let (mut worker, commands, outbound, _cancel) = worker();

        for fd in 1..=MAX_ACTIVE_SOCKETS as i32 {
            worker
                .handle_packet(destination_request(fd, &missing_socket))
                .unwrap();
        }
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS);
        assert_eq!(worker.total_sockets(), MAX_ACTIVE_SOCKETS);

        let rejected_fd = MAX_ACTIVE_SOCKETS as i32 + 1;
        worker
            .handle_packet(destination_request(rejected_fd, &missing_socket))
            .unwrap();
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS);
        let rejected = response(outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap());
        assert_eq!(rejected.clientfd, Some(rejected_fd));
        assert!(rejected.error.unwrap().contains("socket limit"));

        let completion = commands.recv_timeout(EVENT_TIMEOUT).unwrap();
        let Command::Connected {
            client_fd,
            socket_id,
            result,
        } = completion
        else {
            panic!("connector emitted an unexpected command");
        };
        assert!(result.is_err());
        worker
            .connected(client_fd, socket_id, result, None)
            .unwrap();
        assert_eq!(worker.total_sockets(), MAX_ACTIVE_SOCKETS - 1);
        let _ = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();

        worker
            .handle_packet(destination_request(rejected_fd + 1, &missing_socket))
            .unwrap();
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS + 1);

        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    #[test]
    fn successful_connector_transfers_slot_to_active_destination() {
        let (directory, _cleanup) = test_directory("connector-success-test");
        let path = directory.join("destination.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (mut worker, commands, _outbound, _cancel) = worker();
        let request = Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                fd: Some(1),
                window: None,
            }
            .encode_to_vec(),
        );

        worker.handle_packet(request).unwrap();
        assert_eq!(worker.total_sockets(), 1);
        let Command::Connected {
            client_fd,
            socket_id,
            result,
        } = commands.recv_timeout(EVENT_TIMEOUT).unwrap()
        else {
            panic!("connector emitted an unexpected command");
        };
        assert!(
            result.is_ok(),
            "connector failed: {:?}",
            result.as_ref().err()
        );
        let (peer, _) = listener.accept().unwrap();
        worker
            .connected(client_fd, socket_id, result, None)
            .unwrap();

        assert_eq!(worker.total_sockets(), 1);
        assert_eq!(worker.destinations.len(), 1);

        drop(peer);
        worker.remove(super::Role::Destination, socket_id);
        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    #[test]
    fn a_failed_session_bind_write_fails_the_forwarded_connection() {
        let (mut worker, _commands, outbound, _cancel) = worker();
        let bind = crate::ssh_agent_session_bind::encode_session_bind(
            b"dest-key",
            b"session-id",
            b"signature",
            true,
        )
        .unwrap();
        worker.pending_agent_binds.insert(
            7,
            crate::ssh_agent_session_bind::PendingSessionBinds {
                path: "/tmp/agent.sock".to_owned(),
                binds: vec![bind],
            },
        );
        // A connected pair with its own write side shut down. The bind send
        // then fails with EPIPE. macOS returns EINVAL from SO_SNDTIMEO once a
        // unix socket's peer is already gone, so this does not use a timeout.
        let (stream, _peer) = UnixStream::pair().unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        worker
            .connected(3, 7, Ok(ForwardStream::Unix(stream)), None)
            .unwrap();

        let packet = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();
        let response = response(packet);
        assert_eq!(
            response.error.as_deref(),
            Some("could not send ssh agent session binding")
        );
        assert!(response.socketid.is_none());
        assert_eq!(response.clientfd, Some(3));
        assert!(worker.destinations.is_empty());
        assert!(!worker.pending_agent_binds.contains_key(&7));
    }
}

#[cfg(test)]
mod parked_forward_limits {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use crossbeam_channel as channel;
    use et_core::packet::Packet;
    use et_core::proto::{
        PortForwardData, PortForwardDestinationResponse, SocketEndpoint, TerminalPacketType,
    };
    use prost::Message;

    use super::{command_channel, PendingAccept, Worker, MAX_UNASSIGNED_FDS};
    use crate::forward_endpoint::ForwardStream;

    struct Harness {
        worker: Worker,
        outbound: channel::Receiver<crate::forward::Outbound>,
        _cancel: channel::Sender<()>,
    }

    fn harness() -> Harness {
        let (commands, _receiver) = command_channel(MAX_UNASSIGNED_FDS + 8);
        let (outbound, outbound_receiver) = channel::bounded(MAX_UNASSIGNED_FDS + 8);
        let (cancel, cancel_receiver) = channel::bounded(1);
        #[cfg(unix)]
        let worker = {
            let (_read, write) = std::os::unix::net::UnixStream::pair().unwrap();
            Worker::new(
                commands,
                outbound.clone(),
                outbound,
                Some(write),
                cancel_receiver,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap()
        };
        #[cfg(windows)]
        let worker = Worker::new(
            commands,
            outbound.clone(),
            outbound,
            cancel_receiver,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        Harness {
            worker,
            outbound: outbound_receiver,
            _cancel: cancel,
        }
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
        (client, accepted)
    }

    fn park(worker: &mut Worker, client_fd: i32, accepted: TcpStream) {
        worker
            .accepted(
                client_fd,
                SocketEndpoint::default(),
                PendingAccept::park(ForwardStream::Tcp(accepted), Vec::new(), None, false, false),
            )
            .unwrap();
    }

    #[test]
    fn parked_forwards_are_capped_and_expired() {
        let mut harness = harness();
        let mut peers = Vec::new();
        for client_fd in 1..=MAX_UNASSIGNED_FDS as i32 {
            let (peer, accepted) = pair();
            park(&mut harness.worker, client_fd, accepted);
            peers.push(peer);
            assert!(harness
                .outbound
                .recv_timeout(Duration::from_secs(2))
                .is_ok());
        }
        assert_eq!(harness.worker.pending.len(), MAX_UNASSIGNED_FDS);
        let (mut overflow_peer, overflow) = pair();
        park(&mut harness.worker, MAX_UNASSIGNED_FDS as i32 + 1, overflow);
        assert_eq!(harness.worker.pending.len(), MAX_UNASSIGNED_FDS);
        let mut byte = [0u8; 1];
        assert_eq!(overflow_peer.read(&mut byte).unwrap(), 0);

        harness.worker.expire_parked();
        assert_eq!(harness.worker.pending.len(), MAX_UNASSIGNED_FDS);
        harness.worker.expire_for_test(1);
        harness.worker.expire_parked();
        assert!(!harness.worker.pending.contains_key(&1));
        assert_eq!(peers[0].read(&mut byte).unwrap(), 0);
        assert!(harness.worker.pending.contains_key(&2));
    }

    #[test]
    fn a_late_destination_response_closes_the_peer_socket() {
        let mut harness = harness();
        let (_peer, accepted) = pair();
        park(&mut harness.worker, 1, accepted);
        let _request = harness
            .outbound
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        harness.worker.expire_for_test(1);
        harness.worker.expire_parked();
        let (next_peer, next) = pair();
        park(&mut harness.worker, 2, next);
        let _next_request = harness
            .outbound
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        harness
            .worker
            .handle_packet(Packet::new(
                TerminalPacketType::PortForwardDestinationResponse as u8,
                PortForwardDestinationResponse {
                    clientfd: Some(1),
                    socketid: Some(44),
                    error: None,
                    window: None,
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let stale = harness
            .outbound
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(stale.header(), TerminalPacketType::PortForwardData as u8);
        let closed = PortForwardData::decode(stale.payload()).unwrap();
        assert_eq!(closed.socketid, Some(44));
        assert_eq!(closed.sourcetodestination, Some(true));
        assert_eq!(closed.closed, Some(true));
        assert!(harness.worker.pending.contains_key(&2));
        assert!(!harness.worker.sources.contains_key(&44));

        harness
            .worker
            .handle_packet(Packet::new(
                TerminalPacketType::PortForwardDestinationResponse as u8,
                PortForwardDestinationResponse {
                    clientfd: Some(2),
                    socketid: Some(45),
                    error: None,
                    window: None,
                }
                .encode_to_vec(),
            ))
            .unwrap();
        assert!(harness.worker.sources.contains_key(&45));
        assert!(!harness.worker.pending.contains_key(&2));
        drop(next_peer);
        harness.worker.remove(super::Role::Source, 45);
        for thread in harness.worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}
