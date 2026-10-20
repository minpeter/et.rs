//! Bounded, interruptible local console output, including default sessions.
//!
//! On Linux a FIFO or terminal stdout is written by the session loop itself
//! (the direct console), as upstream `TerminalClient::run` drains its
//! `WriteBuffer` from its select loop. Other outputs keep the
//! `et-console-output` worker thread.

#[path = "client_output_interrupt.rs"]
mod output_interrupt;

use std::collections::VecDeque;
#[cfg(unix)]
use std::fs::File;
use std::io::Read;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use et_cli::client::FlowControlMode;
#[cfg(unix)]
use et_net::local::LocalStream;
#[cfg(unix)]
use rustix::event::{PollFd, PollFlags};

const OUTPUT_BYTES: usize = 64 * 1024;
const OUTPUT_PACKETS: usize = 4096;
pub(crate) const GRACEFUL_DRAIN_STALL_TIMEOUT: Duration = Duration::from_secs(1);
/// Queued packets one vectored write to the direct console covers.
#[cfg(target_os = "linux")]
const WRITE_SLICES: usize = 64;
/// Delivered packet buffers the direct console keeps for reuse, so a
/// saturated terminal does not allocate one per queued packet.
#[cfg(target_os = "linux")]
const SPARE_BUFFERS: usize = 4;

// Delivery is distinct from progress: a buffered sink must flush before a
// completed packet can affect terminal cleanup or cursor-report accounting.
trait ConsoleWriter: Send {
    fn write_with_delivery(
        &mut self,
        bytes: &[u8],
        shared: &Shared,
        delivered: &mut dyn FnMut(usize),
    ) -> io::Result<usize>;
}

impl<T: Write + Send> ConsoleWriter for T {
    fn write_with_delivery(
        &mut self,
        bytes: &[u8],
        shared: &Shared,
        delivered: &mut dyn FnMut(usize),
    ) -> io::Result<usize> {
        let count = self.write(bytes)?;
        if count != 0 {
            report_worker_progress(shared)?;
            loop {
                match self.flush() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => break result?,
                }
            }
            delivered(count);
        }
        Ok(count)
    }
}

struct OutputEntry {
    bytes: Vec<u8>,
    /// Prefix of `bytes` the direct console already wrote. The worker takes
    /// whole entries out of the queue, so for it this stays 0.
    sent: usize,
    terminal_modes: crate::client_terminal::TerminalModeState,
}

impl OutputEntry {
    fn unsent(&self) -> &[u8] {
        &self.bytes[self.sent..]
    }
}

struct State {
    queue: VecDeque<OutputEntry>,
    /// Unsent queued bytes.
    bytes: usize,
    stopping: bool,
    error: Option<io::Error>,
    cursor_reports: usize,
    worker_done: bool,
    worker_progress: usize,
    stream: et_core::output_interrupt::TerminalStream,
    skip_until_newline: bool,
    /// A packet was refused for lack of room and is held by the caller.
    waiting_for_capacity: bool,
    #[cfg(target_os = "linux")]
    spare: Vec<Vec<u8>>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    worker_progress: std::sync::atomic::AtomicUsize,
    stopping_fast: std::sync::atomic::AtomicBool,
}

impl Shared {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                bytes: 0,
                stopping: false,
                error: None,
                cursor_reports: 0,
                worker_done: false,
                worker_progress: 0,
                stream: et_core::output_interrupt::TerminalStream::default(),
                skip_until_newline: false,
                waiting_for_capacity: false,
                #[cfg(target_os = "linux")]
                spare: Vec::new(),
            }),
            wake: Condvar::new(),
            worker_progress: std::sync::atomic::AtomicUsize::new(0),
            stopping_fast: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))
    }
}

/// The worker's wake descriptors polled by the session loop.
#[cfg(unix)]
struct WorkerWakes {
    /// Queue capacity freed or cursor reports confirmed.
    capacity: LocalStream,
    /// The worker stopped on a write error.
    status: LocalStream,
}

#[derive(Clone, Copy)]
pub(crate) enum ConsoleCompletion {
    RemoteSessionEnded,
    #[cfg(any(unix, test))]
    LocalInputClosed,
}

pub(crate) struct ConsoleOutput {
    mode: FlowControlMode,
    shared: Option<Arc<Shared>>,
    /// `None` for the direct console, which has no worker to wake the loop.
    #[cfg(unix)]
    wakes: Option<WorkerWakes>,
    cancel: Option<Box<dyn FnOnce() + Send>>,
    graceful_finish: Option<Box<dyn FnOnce() -> io::Result<()> + Send>>,
    worker: Option<thread::JoinHandle<()>>,
    /// Non-blocking stdout the session loop writes itself; no worker runs.
    #[cfg(target_os = "linux")]
    direct: Option<File>,
}

impl ConsoleOutput {
    pub(crate) fn stdout(mode: FlowControlMode) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = File::from(rustix::io::dup(io::stdout().lock().as_fd())?);
            #[cfg(target_os = "linux")]
            if let Some(direct) = reopen_nonblocking(&file) {
                return Ok(Self::direct(mode, direct));
            }
            let (cancel_reader, mut cancel_writer) = et_net::local::wake_pair()?;
            let cancel = Box::new(move || {
                let _ = cancel_writer.write_all(&[1]);
            });
            Self::new_with_lifecycle(
                mode,
                Box::new(CancellableStdout {
                    file,
                    cancel: cancel_reader,
                    discard_device: None,
                    #[cfg(target_os = "linux")]
                    stdout_kind: None,
                }),
                cancel,
                Box::new(|| Ok(())),
            )
        }
        #[cfg(windows)]
        {
            let mut child = Command::new(std::env::current_exe()?)
                .arg("__et-console-writer")
                .stdin(Stdio::piped())
                .stdout(Stdio::inherit())
                .stderr(Stdio::piped())
                .spawn()?;
            let input = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("console helper stdin unavailable"))?;
            let ack = child
                .stderr
                .take()
                .ok_or_else(|| io::Error::other("console helper acknowledgement unavailable"))?;
            let child = Arc::new(Mutex::new(child));
            let cancel_child = Arc::clone(&child);
            let graceful_child = Arc::clone(&child);
            Self::new_with_lifecycle_factory(
                mode,
                move |_| Box::new(WindowsHelperWriter { input, ack }),
                Box::new(move || cancel_windows_helper(&cancel_child)),
                Box::new(move || wait_windows_helper(&graceful_child)),
            )
        }
    }

    /// Console output the session loop writes to the non-blocking `file`
    /// itself: no worker thread, no wake descriptors.
    #[cfg(target_os = "linux")]
    fn direct(mode: FlowControlMode, file: File) -> Self {
        Self {
            mode,
            shared: Some(Arc::new(Shared::new())),
            wakes: None,
            cancel: None,
            graceful_finish: None,
            worker: None,
            direct: Some(file),
        }
    }

    pub(crate) fn new(mode: FlowControlMode, writer: Box<dyn Write + Send>) -> io::Result<Self> {
        Self::new_with_lifecycle(mode, writer, Box::new(|| {}), Box::new(|| Ok(())))
    }

    #[cfg(test)]
    pub(crate) fn new_with_cancel(
        mode: FlowControlMode,
        writer: Box<dyn Write + Send>,
        cancel: Box<dyn FnOnce() + Send>,
    ) -> io::Result<Self> {
        Self::new_with_lifecycle(mode, writer, cancel, Box::new(|| Ok(())))
    }

    pub(crate) fn new_with_lifecycle(
        mode: FlowControlMode,
        writer: Box<dyn Write + Send>,
        cancel: Box<dyn FnOnce() + Send>,
        graceful_finish: Box<dyn FnOnce() -> io::Result<()> + Send>,
    ) -> io::Result<Self> {
        Self::new_with_lifecycle_factory(mode, move |_| Box::new(writer), cancel, graceful_finish)
    }

    fn new_with_lifecycle_factory<F>(
        mode: FlowControlMode,
        writer: F,
        cancel: Box<dyn FnOnce() + Send>,
        graceful_finish: Box<dyn FnOnce() -> io::Result<()> + Send>,
    ) -> io::Result<Self>
    where
        F: FnOnce(&Arc<Shared>) -> Box<dyn ConsoleWriter>,
    {
        #[cfg(unix)]
        let (capacity_wake, mut capacity_signal) = {
            let (wake, signal) = et_net::local::wake_pair()?;
            wake.set_nonblocking(true)?;
            signal.set_nonblocking(true)?;
            (wake, signal)
        };
        #[cfg(unix)]
        let (status_wake, mut status_signal) = {
            let (wake, signal) = et_net::local::wake_pair()?;
            wake.set_nonblocking(true)?;
            signal.set_nonblocking(true)?;
            (wake, signal)
        };
        let shared = Arc::new(Shared::new());
        let mut writer = writer(&shared);
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("et-console-output".to_owned())
            .spawn(move || {
                run_writer(
                    &worker_shared,
                    &mut *writer,
                    #[cfg(unix)]
                    &mut capacity_signal,
                    #[cfg(unix)]
                    &mut status_signal,
                );
            })?;
        Ok(Self {
            mode,
            shared: Some(shared),
            #[cfg(unix)]
            wakes: Some(WorkerWakes {
                capacity: capacity_wake,
                status: status_wake,
            }),
            cancel: Some(cancel),
            graceful_finish: Some(graceful_finish),
            worker: Some(worker),
            #[cfg(target_os = "linux")]
            direct: None,
        })
    }

    /// Attempt to admit one complete terminal-output packet without waiting.
    ///
    /// `Ok(false)` leaves ownership with the caller, which must retry the same
    /// packet before reading another server packet.
    pub(crate) fn try_write(
        &self,
        bytes: &[u8],
        terminal_modes: &crate::client_terminal::TerminalModeState,
    ) -> io::Result<bool> {
        let Some(shared) = &self.shared else {
            io::stdout()
                .lock()
                .write_all(bytes)
                .and_then(|()| io::stdout().lock().flush())?;
            terminal_modes.observe(bytes);
            return Ok(true);
        };
        if self.mode != FlowControlMode::Discard && bytes.len() > OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal output packet exceeds console queue capacity",
            ));
        }
        let mut retained = if bytes.len() > OUTPUT_BYTES {
            &bytes[bytes.len() - OUTPUT_BYTES..]
        } else {
            bytes
        };
        let mut state = shared.lock()?;
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        if state.stopping {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "console output stopped",
            ));
        }
        if state.skip_until_newline {
            let Some(newline) = memchr::memchr(b'\n', retained) else {
                return Ok(true);
            };
            retained = &retained[newline + 1..];
        }
        match self.mode {
            FlowControlMode::None | FlowControlMode::Backpressure
                if state.bytes.saturating_add(retained.len()) > OUTPUT_BYTES
                    || state.queue.len() >= OUTPUT_PACKETS =>
            {
                state.waiting_for_capacity = true;
                return Ok(false);
            }
            FlowControlMode::None | FlowControlMode::Backpressure => {}
            FlowControlMode::Discard => {
                while state.bytes.saturating_add(retained.len()) > OUTPUT_BYTES
                    || state.queue.len() >= OUTPUT_PACKETS
                {
                    // A partly written entry is already on the console.
                    let oldest = usize::from(state.queue.front().is_some_and(|e| e.sent != 0));
                    let Some(removed) = state.queue.remove(oldest) else {
                        break;
                    };
                    state.bytes -= removed.unsent().len();
                }
            }
        }
        // Only commit the terminator after admission; a held packet must
        // retry with the same skip state when the queue is still full.
        state.skip_until_newline = false;
        #[cfg(target_os = "linux")]
        if let Some(direct) = &self.direct {
            state.waiting_for_capacity = false;
            state.write_packet(shared, direct, retained, terminal_modes);
            return Ok(true);
        }
        let was_empty = state.queue.is_empty();
        state.bytes += retained.len();
        state.queue.push_back(OutputEntry {
            bytes: retained.to_vec(),
            sent: 0,
            terminal_modes: terminal_modes.clone(),
        });
        drop(state);
        if was_empty {
            shared.wake.notify_one();
        }
        Ok(true)
    }

    pub(crate) fn is_async(&self) -> bool {
        self.shared.is_some()
    }

    /// The session loop writes this console itself (see `poll_descriptors`).
    pub(crate) fn is_direct(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.direct.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Bytes still queued for the console. Synchronous writers have none.
    pub(crate) fn has_pending_data(&self) -> io::Result<bool> {
        let Some(shared) = &self.shared else {
            return Ok(false);
        };
        let state = shared.lock()?;
        Ok(state.bytes > 0 || !state.queue.is_empty())
    }

    pub(crate) fn take_cursor_reports(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        let mut state = shared.lock()?;
        Ok(std::mem::take(&mut state.cursor_reports))
    }

    #[cfg(test)]
    pub(crate) fn wait_worker_done(&self) {
        let Some(shared) = &self.shared else {
            return;
        };
        let state = shared.state.lock().unwrap();
        drop(
            shared
                .wake
                .wait_while(state, |state| !state.worker_done)
                .unwrap(),
        );
    }

    pub(crate) fn complete(mut self, completion: ConsoleCompletion) -> io::Result<()> {
        match completion {
            ConsoleCompletion::RemoteSessionEnded => self.finish_gracefully(),
            #[cfg(any(unix, test))]
            ConsoleCompletion::LocalInputClosed => Ok(()),
        }
    }

    pub(crate) fn finish_gracefully(&mut self) -> io::Result<()> {
        self.finish_gracefully_with_stall(false)
    }

    pub(crate) fn finish_gracefully_after_stall(&mut self) -> io::Result<()> {
        self.finish_gracefully_with_stall(true)
    }

    fn finish_gracefully_with_stall(&mut self, already_stalled: bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(direct) = self.direct.take() {
            return match self.shared.take() {
                Some(shared) => finish_direct(&shared, &direct, already_stalled),
                None => Ok(()),
            };
        }
        let Some(shared) = self.shared.clone() else {
            return Ok(());
        };
        {
            let mut state = shared.lock()?;
            state.stopping = true;
            shared
                .stopping_fast
                .store(true, std::sync::atomic::Ordering::Release);
            shared.wake.notify_all();
        }
        let stalled = already_stalled || wait_for_graceful_drain(&shared)?;
        if stalled {
            if let Some(cancel) = self.cancel.take() {
                cancel();
            }
        }
        // Cancellation normally wakes the writer immediately. A blocking
        // descriptor can still race between poll readiness and its write,
        // though, so never turn the bounded drain into an unbounded join.
        let worker_done = !stalled || !wait_for_graceful_drain(&shared)?;
        if worker_done {
            if let Some(worker) = self.worker.take() {
                worker
                    .join()
                    .map_err(|_| io::Error::other("console output worker panicked"))?;
            }
            self.check_error()?;
            if let Some(finish) = self.graceful_finish.take() {
                finish()?;
            }
        } else {
            // Dropping a JoinHandle detaches the irrecoverably blocked writer.
            // The client is already terminating and the worker retains its Arc.
            self.worker = None;
            self.graceful_finish = None;
        }
        self.cancel = None;
        self.shared = None;
        Ok(())
    }

    pub(crate) fn check_error(&self) -> io::Result<()> {
        let Some(shared) = &self.shared else {
            return Ok(());
        };
        match shared.lock()?.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Count of writes that moved console bytes, by the worker or the
    /// session loop; completion uses it to detect a stalled console.
    pub(crate) fn worker_progress(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        Ok(shared
            .worker_progress
            .load(std::sync::atomic::Ordering::Acquire))
    }

    /// Appends the descriptors whose readiness lets console output progress:
    /// the worker's capacity and status wakes, in that order, or the direct
    /// console's stdout for `POLLOUT` while output is queued for it.
    #[cfg(unix)]
    pub(crate) fn poll_descriptors<'a>(
        &'a self,
        descriptors: &mut Vec<PollFd<'a>>,
    ) -> io::Result<()> {
        if let Some(wakes) = &self.wakes {
            descriptors.push(PollFd::new(&wakes.capacity, PollFlags::IN | PollFlags::HUP));
            descriptors.push(PollFd::new(&wakes.status, PollFlags::IN | PollFlags::HUP));
        }
        #[cfg(target_os = "linux")]
        if let Some(direct) = &self.direct {
            if self.has_pending_data()? {
                descriptors.push(PollFd::new(direct, PollFlags::OUT));
            }
        }
        Ok(())
    }

    /// Handles readiness of the first descriptor from `poll_descriptors`:
    /// drains the worker's capacity wake, or writes queued output to the
    /// direct console. A write error is kept for `check_error`, as the
    /// worker keeps it.
    #[cfg(unix)]
    pub(crate) fn service_ready(&mut self) -> io::Result<()> {
        if let Some(wakes) = &mut self.wakes {
            return drain_stream(&mut wakes.capacity);
        }
        #[cfg(target_os = "linux")]
        if let (Some(direct), Some(shared)) = (&self.direct, &self.shared) {
            shared.lock()?.write_queued(shared, direct);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn drain_status_wake(&mut self) -> io::Result<()> {
        match &mut self.wakes {
            Some(wakes) => drain_stream(&mut wakes.status),
            None => Ok(()),
        }
    }
}

impl Drop for ConsoleOutput {
    fn drop(&mut self) {
        // Without a worker there is nothing to stop: the direct console's
        // queue is discarded with it, as cancelling the worker discards it.
        if self.worker.is_none() {
            return;
        }
        let shared = self.shared.clone();
        if let Some(shared) = &shared {
            if let Ok(mut state) = shared.state.lock() {
                state.stopping = true;
                shared
                    .stopping_fast
                    .store(true, std::sync::atomic::Ordering::Release);
                shared.wake.notify_all();
            }
        }
        self.graceful_finish = None;
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
        let worker_done = shared
            .as_deref()
            .is_none_or(|shared| matches!(wait_for_graceful_drain(shared), Ok(false)));
        if worker_done {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        } else {
            self.worker = None;
        }
    }
}

struct WorkerDone<'a>(&'a Shared);

impl Drop for WorkerDone<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.worker_done = true;
            self.0.wake.notify_all();
        }
    }
}

fn run_writer(
    shared: &Shared,
    writer: &mut dyn ConsoleWriter,
    #[cfg(unix)] capacity_signal: &mut LocalStream,
    #[cfg(unix)] status_signal: &mut LocalStream,
) {
    let _done = WorkerDone(shared);
    // Reused across batches: a fresh multi-packet join per batch is a large
    // allocation whose pages the kernel zero-fills again after decay.
    let mut joined: Vec<u8> = Vec::new();
    loop {
        let (entries, notify_capacity) = {
            let Ok(state) = shared.state.lock() else {
                return;
            };
            let Ok(mut state) = shared
                .wake
                .wait_while(state, |state| state.queue.is_empty() && !state.stopping)
            else {
                return;
            };
            if state.queue.is_empty() {
                return;
            }
            // Snapshot only admitted output: no delay or unbounded network drain.
            // Like a single packet, this bounded batch is writer-owned and must
            // be observed before interrupt filtering can inspect the next queue.
            let entries: Vec<_> = state.queue.drain(..).collect();
            state.bytes = 0;
            let notify_capacity = std::mem::replace(&mut state.waiting_for_capacity, false);
            for entry in &entries {
                state.stream.observe(&entry.bytes);
            }
            (entries, notify_capacity)
        };
        #[cfg(unix)]
        if notify_capacity {
            signal_capacity(capacity_signal);
        }
        #[cfg(not(unix))]
        let _ = notify_capacity;
        let bytes: &[u8] = match entries.as_slice() {
            [entry] => &entry.bytes,
            _ => {
                joined.clear();
                for entry in &entries {
                    joined.extend_from_slice(&entry.bytes);
                }
                &joined
            }
        };
        let mut pending = entries.iter().peekable();
        let mut confirmed = 0;
        let result = write_all_with_progress(shared, writer, bytes, &mut |count| {
            confirmed += count;
            let mut cursor_reports = 0;
            while pending
                .peek()
                .is_some_and(|entry| entry.bytes.len() <= confirmed)
            {
                let entry = pending.next().unwrap();
                confirmed -= entry.bytes.len();
                entry.terminal_modes.observe(&entry.bytes);
                cursor_reports += usize::from(
                    crate::client_terminal::contains_cursor_report_request(&entry.bytes),
                );
            }
            if cursor_reports != 0 {
                if let Ok(mut state) = shared.state.lock() {
                    state.cursor_reports += cursor_reports;
                }
                #[cfg(unix)]
                signal_capacity(capacity_signal);
            }
        });
        let notify_capacity = shared
            .state
            .lock()
            .is_ok_and(|mut state| std::mem::replace(&mut state.waiting_for_capacity, false));
        #[cfg(unix)]
        if notify_capacity {
            signal_capacity(capacity_signal);
        }
        #[cfg(not(unix))]
        let _ = notify_capacity;
        if let Err(error) = result {
            if let Ok(mut state) = shared.state.lock() {
                state.error = Some(error);
                state.stopping = true;
                state.worker_done = true;
                shared.wake.notify_all();
            }
            #[cfg(unix)]
            signal_capacity(status_signal);
            return;
        }
    }
}

fn write_all_with_progress(
    shared: &Shared,
    writer: &mut dyn ConsoleWriter,
    mut bytes: &[u8],
    delivered: &mut dyn FnMut(usize),
) -> io::Result<()> {
    while !bytes.is_empty() {
        match writer.write_with_delivery(bytes, shared, delivered) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn report_worker_progress(shared: &Shared) -> io::Result<()> {
    let next = shared
        .worker_progress
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        .wrapping_add(1);
    if shared
        .stopping_fast
        .load(std::sync::atomic::Ordering::Acquire)
    {
        let mut state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        state.worker_progress = next;
        shared.wake.notify_all();
    }
    Ok(())
}

fn wait_for_graceful_drain(shared: &Shared) -> io::Result<bool> {
    shared
        .stopping_fast
        .store(true, std::sync::atomic::Ordering::Release);
    let mut state = shared
        .state
        .lock()
        .map_err(|_| io::Error::other("console output worker unavailable"))?;
    let mut progress = shared
        .worker_progress
        .load(std::sync::atomic::Ordering::Acquire);
    let mut deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
    while !state.worker_done {
        let now = Instant::now();
        if now >= deadline {
            return Ok(true);
        }
        let (next, timeout) = shared
            .wake
            .wait_timeout(state, deadline.saturating_duration_since(now))
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        state = next;
        let cur_progress = shared
            .worker_progress
            .load(std::sync::atomic::Ordering::Acquire);
        if cur_progress != progress {
            progress = cur_progress;
            deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
        } else if timeout.timed_out() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(windows, test))]
struct WindowsHelperWriter<I, A> {
    input: I,
    ack: A,
}

#[cfg(any(windows, test))]
impl<I: Write + Send, A: Read + Send> ConsoleWriter for WindowsHelperWriter<I, A> {
    fn write_with_delivery(
        &mut self,
        bytes: &[u8],
        shared: &Shared,
        delivered: &mut dyn FnMut(usize),
    ) -> io::Result<usize> {
        let length = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "console packet too large"))?;
        self.input.write_all(&length.to_le_bytes())?;
        self.input.write_all(bytes)?;
        self.input.flush()?;
        let mut acknowledged = 0usize;
        loop {
            let mut ack = [0u8; 4];
            std::io::Read::read_exact(&mut self.ack, &mut ack)?;
            let count = u32::from_le_bytes(ack) as usize;
            if count == 0 {
                if acknowledged == bytes.len() {
                    break;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "console helper acknowledgement is incomplete",
                ));
            }
            if count > bytes.len() - acknowledged {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "console helper acknowledgement is invalid",
                ));
            }
            acknowledged += count;
            report_worker_progress(shared)?;
            delivered(count);
        }
        Ok(bytes.len())
    }
}

#[cfg(windows)]
fn wait_windows_helper(child: &Mutex<std::process::Child>) -> io::Result<()> {
    let mut child = child
        .lock()
        .map_err(|_| io::Error::other("console helper unavailable"))?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "console helper exited with {status}"
        )))
    }
}

#[cfg(windows)]
fn cancel_windows_helper(child: &Mutex<std::process::Child>) {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
pub(crate) fn run_windows_helper() -> i32 {
    copy_windows_helper_output(
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

#[cfg(any(windows, test))]
fn copy_windows_helper_output(
    mut input: impl Read,
    mut output: impl Write,
    mut acknowledgements: impl Write,
) -> i32 {
    loop {
        let mut length = [0u8; 4];
        match std::io::Read::read_exact(&mut input, &mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return 0,
            Err(_) => return 1,
        }
        let mut bytes = vec![0u8; u32::from_le_bytes(length) as usize];
        if bytes.is_empty() || std::io::Read::read_exact(&mut input, &mut bytes).is_err() {
            return 1;
        }
        let mut remaining = bytes.as_slice();
        while !remaining.is_empty() {
            let chunk = &remaining[..remaining.len().min(4096)];
            let count = match output.write(chunk) {
                Ok(0) => return 1,
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return 1,
            };
            remaining = &remaining[count..];
            // ACKs confirm delivery, not merely acceptance by StdoutLock's
            // buffer. Publish each prefix before another write can block.
            if output.flush().is_err() {
                return 1;
            }
            if acknowledgements
                .write_all(&(count as u32).to_le_bytes())
                .and_then(|()| acknowledgements.flush())
                .is_err()
            {
                return 1;
            }
        }
        if acknowledgements
            .write_all(&0u32.to_le_bytes())
            .and_then(|()| acknowledgements.flush())
            .is_err()
        {
            return 1;
        }
    }
}

/// A FIFO or terminal stdout reopened through `/proc` with `O_NONBLOCK`.
/// The reopen is a separate open file description, so `O_NONBLOCK` never
/// leaks into the inherited stdout the parent shell keeps using.
#[cfg(target_os = "linux")]
fn reopen_nonblocking(stdout: &File) -> Option<File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    let is_fifo = stdout.metadata().is_ok_and(|m| m.file_type().is_fifo());
    if !is_fifo && !rustix::termios::isatty(stdout) {
        return None;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags((rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY).bits() as i32)
        .open(format!("/proc/self/fd/{}", stdout.as_raw_fd()))
        .ok()
}

/// The direct console: the session loop writes without blocking and does
/// the worker's delivery accounting on exactly the bytes written.
#[cfg(target_os = "linux")]
impl State {
    /// Writes an admitted packet straight through when nothing is queued
    /// ahead of it and queues whatever the console did not take.
    fn write_packet(
        &mut self,
        shared: &Shared,
        file: &File,
        bytes: &[u8],
        terminal_modes: &crate::client_terminal::TerminalModeState,
    ) {
        if bytes.is_empty() {
            return;
        }
        let mut sent = 0;
        if self.queue.is_empty() {
            match write_retrying(file, bytes) {
                Ok(0) => return self.fail(io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    report_direct_progress(shared);
                    self.stream.observe(&bytes[..count]);
                    terminal_modes.observe(&bytes[..count]);
                    if count == bytes.len() {
                        self.cursor_reports += usize::from(
                            crate::client_terminal::contains_cursor_report_request(bytes),
                        );
                        return;
                    }
                    sent = count;
                }
                Err(rustix::io::Errno::AGAIN) => {}
                Err(error) => return self.fail(error.into()),
            }
        }
        let mut buffer = self.spare.pop().unwrap_or_default();
        buffer.extend_from_slice(bytes);
        self.bytes += bytes.len() - sent;
        self.queue.push_back(OutputEntry {
            bytes: buffer,
            sent,
            terminal_modes: terminal_modes.clone(),
        });
    }

    /// Writes queued output, several packets per vectored write, until the
    /// console stops taking all of it. Returns whether any byte moved.
    fn write_queued(&mut self, shared: &Shared, file: &File) -> bool {
        let mut progressed = false;
        while !self.queue.is_empty() {
            let mut slices = [io::IoSlice::new(&[]); WRITE_SLICES];
            let mut count = 0;
            let mut offered = 0;
            for (slice, entry) in slices.iter_mut().zip(&self.queue) {
                *slice = io::IoSlice::new(entry.unsent());
                offered += slice.len();
                count += 1;
            }
            let result = loop {
                match rustix::io::writev(file, &slices[..count]) {
                    Err(rustix::io::Errno::INTR) => {}
                    result => break result,
                }
            };
            match result {
                Ok(0) => {
                    self.fail(io::ErrorKind::WriteZero.into());
                    break;
                }
                Ok(written) => {
                    progressed = true;
                    report_direct_progress(shared);
                    self.delivered(written);
                    // A short write means the console is full; asking again
                    // would only return EAGAIN.
                    if written < offered {
                        break;
                    }
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(error) => {
                    self.fail(error.into());
                    break;
                }
            }
        }
        progressed
    }

    /// Accounts `count` bytes written from the front of the queue.
    fn delivered(&mut self, mut count: usize) {
        self.bytes -= count;
        while count != 0 {
            let Some(entry) = self.queue.front_mut() else {
                break;
            };
            let end = entry.bytes.len().min(entry.sent + count);
            let written = &entry.bytes[entry.sent..end];
            self.stream.observe(written);
            entry.terminal_modes.observe(written);
            count -= written.len();
            entry.sent = end;
            self.retire_delivered();
        }
    }

    /// Retires fully written entries: like the worker, a packet counts its
    /// cursor report request only once all of it reached the console.
    fn retire_delivered(&mut self) {
        while self
            .queue
            .front()
            .is_some_and(|entry| entry.sent == entry.bytes.len())
        {
            let Some(entry) = self.queue.pop_front() else {
                break;
            };
            self.cursor_reports += usize::from(
                crate::client_terminal::contains_cursor_report_request(&entry.bytes),
            );
            if self.spare.len() < SPARE_BUFFERS {
                let mut buffer = entry.bytes;
                buffer.clear();
                self.spare.push(buffer);
            }
        }
    }

    /// Stops admission after a write error, as the worker does. The rest of
    /// the queue can never be written, and keeping it would keep `POLLOUT`
    /// polled on a broken descriptor.
    fn fail(&mut self, error: io::Error) {
        self.error = Some(error);
        self.stopping = true;
        self.queue.clear();
        self.bytes = 0;
    }
}

#[cfg(target_os = "linux")]
fn write_retrying(file: &File, bytes: &[u8]) -> rustix::io::Result<usize> {
    loop {
        match rustix::io::write(file, bytes) {
            Err(rustix::io::Errno::INTR) => {}
            result => return result,
        }
    }
}

#[cfg(target_os = "linux")]
fn report_direct_progress(shared: &Shared) {
    shared
        .worker_progress
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// Delivers the direct console's queue on completion, bounded like the
/// worker's graceful drain: give up once the console takes nothing for
/// `GRACEFUL_DRAIN_STALL_TIMEOUT`, and drop the rest as cancelling the
/// worker does.
#[cfg(target_os = "linux")]
fn finish_direct(shared: &Shared, file: &File, already_stalled: bool) -> io::Result<()> {
    let mut state = shared.lock()?;
    state.stopping = true;
    let mut deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
    while !already_stalled && !state.queue.is_empty() && state.error.is_none() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let timeout = rustix::time::Timespec::try_from(deadline - now)
            .map_err(|_| io::Error::other("console drain wait exceeds poll range"))?;
        let mut descriptors = [PollFd::new(file, PollFlags::OUT)];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {}
            Ok(_) => {
                if state.write_queued(shared, file) {
                    deadline = Instant::now() + GRACEFUL_DRAIN_STALL_TIMEOUT;
                }
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(error) = state.error.take() {
        return Err(error);
    }
    if !state.queue.is_empty() {
        state.queue.clear();
        state.bytes = 0;
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "console output cancelled",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn drain_stream(stream: &mut LocalStream) -> io::Result<()> {
    let mut bytes = [0u8; 64];
    loop {
        match stream.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum StdoutKind {
    Regular,
    Other,
}

/// Blocking stdout the worker writes (regular files, sockets, or a FIFO or
/// terminal whose non-blocking reopen failed), interruptible by `cancel`.
#[cfg(unix)]
struct CancellableStdout {
    file: File,
    cancel: LocalStream,
    discard_device: Option<bool>,
    #[cfg(target_os = "linux")]
    stdout_kind: Option<StdoutKind>,
}
#[cfg(unix)]
impl Write for CancellableStdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use rustix::event::poll;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let mut descriptors = [
            PollFd::new(&self.file, PollFlags::OUT),
            PollFd::new(&self.cancel, PollFlags::IN | PollFlags::HUP),
        ];
        loop {
            match poll(&mut descriptors, None) {
                Ok(_)
                    if descriptors[1]
                        .revents()
                        .intersects(PollFlags::IN | PollFlags::HUP) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "console output cancelled",
                    ));
                }
                Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                    // Darwin reports POLLNVAL for /dev/null even though writes
                    // succeed immediately. Only bypass readiness for this
                    // nonblocking discard device, never an arbitrary character
                    // device that could stall the output worker indefinitely.
                    let discard_device = *self.discard_device.get_or_insert_with(|| {
                        self.file.metadata().is_ok_and(|metadata| {
                            metadata.file_type().is_char_device()
                                && std::fs::metadata("/dev/null")
                                    .is_ok_and(|null| metadata.rdev() == null.rdev())
                        })
                    });
                    if discard_device {
                        return self.file.write(&bytes[..bytes.len().min(4096)]);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "console output is unavailable",
                    ));
                }
                Ok(_)
                    if descriptors[0]
                        .revents()
                        .intersects(PollFlags::ERR | PollFlags::HUP) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "console output is unavailable",
                    ));
                }
                Ok(_) if descriptors[0].revents().contains(PollFlags::OUT) => {
                    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
                    let mut max_chunk = 4096usize;
                    #[cfg(target_os = "linux")]
                    if bytes.len() > 4096 {
                        let kind = *self.stdout_kind.get_or_insert_with(|| {
                            let Ok(meta) = self.file.metadata() else {
                                return StdoutKind::Other;
                            };
                            if meta.file_type().is_file() {
                                StdoutKind::Regular
                            } else {
                                StdoutKind::Other
                            }
                        });
                        if matches!(kind, StdoutKind::Regular) {
                            max_chunk = 65536;
                        }
                    }
                    return rustix::io::write(&self.file, &bytes[..bytes.len().min(max_chunk)])
                        .map_err(io::Error::from);
                }
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
fn signal_capacity(signal: &mut LocalStream) {
    match signal.write(&[1]) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(_) => {}
    }
}

#[cfg(test)]
#[path = "client_output_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_output_interrupt_tests.rs"]
mod interrupt_tests;
