//! Bounded, interruptible local console output, including default sessions.

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

const OUTPUT_BYTES: usize = 64 * 1024;
const OUTPUT_PACKETS: usize = 4096;
pub(crate) const GRACEFUL_DRAIN_STALL_TIMEOUT: Duration = Duration::from_secs(1);

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
    terminal_modes: crate::client_terminal::TerminalModeState,
}

struct State {
    queue: VecDeque<OutputEntry>,
    bytes: usize,
    stopping: bool,
    error: Option<io::Error>,
    cursor_reports: usize,
    worker_done: bool,
    worker_progress: usize,
    stream: et_core::output_interrupt::TerminalStream,
    skip_until_newline: bool,
    waiting_for_capacity: bool,
    /// The worker owns a snapshot it has not finished writing; the session
    /// loop must not write around it.
    writing: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    worker_progress: std::sync::atomic::AtomicUsize,
    stopping_fast: std::sync::atomic::AtomicBool,
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
    #[cfg(unix)]
    capacity_wake: LocalStream,
    #[cfg(unix)]
    status_wake: LocalStream,
    cancel: Option<Box<dyn FnOnce() + Send>>,
    graceful_finish: Option<Box<dyn FnOnce() -> io::Result<()> + Send>>,
    worker: Option<thread::JoinHandle<()>>,
    /// Non-blocking descriptor for writing an idle console straight from the
    /// session loop, skipping the worker hand-off.
    #[cfg(target_os = "linux")]
    direct: Option<File>,
}

impl ConsoleOutput {
    pub(crate) fn stdout(mode: FlowControlMode) -> io::Result<Self> {
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            let (file, nonblocking, terminal) = {
                use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
                use std::os::unix::io::AsRawFd;
                let dup_file = File::from(rustix::io::dup(io::stdout().lock().as_fd())?);
                let is_fifo = dup_file.metadata().is_ok_and(|m| m.file_type().is_fifo());
                let is_terminal = rustix::termios::isatty(&dup_file);
                // A FIFO or terminal reopened through /proc is a separate open
                // file description, so O_NONBLOCK never leaks into the
                // inherited stdout the parent shell keeps using.
                if is_fifo || is_terminal {
                    let raw = io::stdout().lock().as_raw_fd();
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(
                            (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY).bits()
                                as i32,
                        )
                        .open(format!("/proc/self/fd/{raw}"))
                    {
                        // The worker writes a terminal through the inherited
                        // blocking description (see `write_terminal`).
                        Ok(file) => (file, true, is_terminal.then_some(dup_file)),
                        Err(_) => (dup_file, false, None),
                    }
                } else {
                    (dup_file, false, None)
                }
            };
            #[cfg(not(target_os = "linux"))]
            let (file, nonblocking) = (
                File::from(rustix::io::dup(io::stdout().lock().as_fd())?),
                false,
            );
            // Only a non-blocking descriptor may be written from the session
            // loop: a full terminal must never stall network and input.
            #[cfg(target_os = "linux")]
            let direct = if nonblocking {
                Some(file.try_clone()?)
            } else {
                None
            };
            let (cancel_reader, mut cancel_writer) = et_net::local::wake_pair()?;
            let cancel = Box::new(move || {
                let _ = cancel_writer.write_all(&[1]);
            });
            #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
            let mut output = Self::new_with_lifecycle(
                mode,
                Box::new(CancellableStdout {
                    file,
                    cancel: cancel_reader,
                    discard_device: None,
                    nonblocking,
                    #[cfg(target_os = "linux")]
                    stdout_kind: None,
                    #[cfg(target_os = "linux")]
                    terminal,
                }),
                cancel,
                Box::new(|| Ok(())),
            )?;
            #[cfg(target_os = "linux")]
            {
                output.direct = direct;
            }
            Ok(output)
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
        let shared = Arc::new(Shared {
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
                writing: false,
            }),
            wake: Condvar::new(),
            worker_progress: std::sync::atomic::AtomicUsize::new(0),
            stopping_fast: std::sync::atomic::AtomicBool::new(false),
        });
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
            capacity_wake,
            #[cfg(unix)]
            status_wake,
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
        let mut state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
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
            let Some(newline) = retained.iter().position(|byte| *byte == b'\n') else {
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
                    let Some(removed) = state.queue.pop_front() else {
                        break;
                    };
                    state.bytes -= removed.bytes.len();
                }
            }
        }
        // An idle console takes the packet straight from the session loop:
        // nothing queued or in flight can be overtaken, and the descriptor is
        // non-blocking. A short write queues the rest for the worker. Cursor
        // report requests keep the worker's delivery accounting, and write
        // errors surface through the worker exactly as before.
        #[cfg(target_os = "linux")]
        if let Some(direct) = &self.direct {
            if state.queue.is_empty()
                && !state.writing
                && !crate::client_terminal::contains_cursor_report_request(retained)
            {
                if let Ok(written) = rustix::io::write(direct, retained) {
                    if written != 0 {
                        state.skip_until_newline = false;
                        state.stream.observe(&retained[..written]);
                        terminal_modes.observe(&retained[..written]);
                        retained = &retained[written..];
                    }
                    if retained.is_empty() {
                        return Ok(true);
                    }
                }
            }
        }
        // Only commit the terminator after admission; a held packet must
        // retry with the same skip state when the queue is still full.
        let was_empty = state.queue.is_empty();
        state.skip_until_newline = false;
        state.bytes += retained.len();
        state.queue.push_back(OutputEntry {
            bytes: retained.to_vec(),
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

    /// Bytes still queued for the console worker. Synchronous writers have none.
    pub(crate) fn has_pending_data(&self) -> io::Result<bool> {
        let Some(shared) = &self.shared else {
            return Ok(false);
        };
        let state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        Ok(state.bytes > 0 || !state.queue.is_empty())
    }

    pub(crate) fn take_cursor_reports(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        let mut state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
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
        let Some(shared) = self.shared.clone() else {
            return Ok(());
        };
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| io::Error::other("console output worker unavailable"))?;
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
        let mut state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        match state.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn worker_progress(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        Ok(shared
            .worker_progress
            .load(std::sync::atomic::Ordering::Acquire))
    }

    #[cfg(unix)]
    pub(crate) fn wake(&self) -> &LocalStream {
        &self.capacity_wake
    }

    #[cfg(unix)]
    pub(crate) fn status_wake(&self) -> &LocalStream {
        &self.status_wake
    }

    #[cfg(unix)]
    pub(crate) fn drain_wake(&mut self) -> io::Result<()> {
        drain_stream(&mut self.capacity_wake)
    }

    #[cfg(unix)]
    pub(crate) fn drain_status_wake(&mut self) -> io::Result<()> {
        drain_stream(&mut self.status_wake)
    }
}

impl Drop for ConsoleOutput {
    fn drop(&mut self) {
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
            state.writing = true;
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
        let notify_capacity = shared.state.lock().is_ok_and(|mut state| {
            state.writing = false;
            std::mem::replace(&mut state.waiting_for_capacity, false)
        });
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

#[cfg(unix)]
struct CancellableStdout {
    file: File,
    cancel: LocalStream,
    discard_device: Option<bool>,
    nonblocking: bool,
    #[cfg(target_os = "linux")]
    stdout_kind: Option<StdoutKind>,
    /// Blocking descriptor of a terminal stdout, written by `write_terminal`.
    #[cfg(target_os = "linux")]
    terminal: Option<File>,
}
#[cfg(unix)]
impl Write for CancellableStdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use rustix::event::{poll, PollFd, PollFlags};
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        #[cfg(target_os = "linux")]
        if let Some(terminal) = &self.terminal {
            return write_terminal(terminal, &self.cancel, bytes);
        }
        if self.nonblocking {
            match rustix::io::write(&self.file, bytes) {
                Ok(count) => return Ok(count),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        }
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
                    if self.nonblocking {
                        match rustix::io::write(&self.file, bytes) {
                            Ok(count) => return Ok(count),
                            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
                            Err(error) => return Err(io::Error::from(error)),
                        }
                    }
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

/// One worker write to a terminal. A PTY takes output only as fast as its
/// reader drains the line discipline, 4 KiB at a time, so non-blocking writes
/// cost a poll and a write per 4 KiB (16 syscalls and wakeups per 64 KiB
/// batch). Wait for room while staying cancellable, then let one blocking
/// write on the inherited description move the whole batch (at most
/// `OUTPUT_BYTES`); a stalled terminal delays cancellation by at most that
/// write, which the bounded graceful drain already tolerates. If another
/// process left the shared description non-blocking, this degrades to
/// partial writes, never to a wrong result.
#[cfg(target_os = "linux")]
fn write_terminal(terminal: &File, cancel: &LocalStream, bytes: &[u8]) -> io::Result<usize> {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut descriptors = [
        PollFd::new(terminal, PollFlags::OUT),
        PollFd::new(cancel, PollFlags::IN | PollFlags::HUP),
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
            Ok(_)
                if descriptors[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "console output is unavailable",
                ));
            }
            Ok(_) if descriptors[0].revents().contains(PollFlags::OUT) => {
                match rustix::io::write(terminal, bytes) {
                    Ok(count) => return Ok(count),
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(io::Error::from(error)),
                }
            }
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(io::Error::from(error)),
        }
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
