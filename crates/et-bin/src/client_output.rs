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
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
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
}

impl ConsoleOutput {
    pub(crate) fn stdout(mode: FlowControlMode) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let file = File::from(rustix::io::dup(io::stdout().lock().as_fd())?);
            let (cancel_reader, mut cancel_writer) = et_net::local::wake_pair()?;
            let cancel = Box::new(move || {
                let _ = cancel_writer.write_all(&[1]);
            });
            Self::new_with_lifecycle(
                mode,
                Box::new(CancellableStdout {
                    file,
                    cancel: cancel_reader,
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
            }),
            wake: Condvar::new(),
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
        // Only commit the terminator after admission; a held packet must
        // retry with the same skip state when the queue is still full.
        state.skip_until_newline = false;
        state.bytes += retained.len();
        state.queue.push_back(OutputEntry {
            bytes: retained.to_vec(),
            terminal_modes: terminal_modes.clone(),
        });
        drop(state);
        shared.wake.notify_one();
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
        let state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        Ok(state.worker_progress)
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
    loop {
        let entries = {
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
            for entry in &entries {
                state.stream.observe(&entry.bytes);
            }
            entries
        };
        #[cfg(unix)]
        signal_capacity(capacity_signal);
        let bytes: Vec<u8> = entries
            .iter()
            .flat_map(|entry| entry.bytes.iter().copied())
            .collect();
        let mut entries = entries.into_iter().peekable();
        let mut confirmed = 0;
        let result = write_all_with_progress(shared, writer, &bytes, &mut |count| {
            confirmed += count;
            let mut cursor_reports = 0;
            while entries
                .peek()
                .is_some_and(|entry| entry.bytes.len() <= confirmed)
            {
                let entry = entries.next().unwrap();
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
    let mut state = shared
        .state
        .lock()
        .map_err(|_| io::Error::other("console output worker unavailable"))?;
    state.worker_progress = state.worker_progress.wrapping_add(1);
    shared.wake.notify_all();
    Ok(())
}

fn wait_for_graceful_drain(shared: &Shared) -> io::Result<bool> {
    let mut state = shared
        .state
        .lock()
        .map_err(|_| io::Error::other("console output worker unavailable"))?;
    let mut progress = state.worker_progress;
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
        if state.worker_progress != progress {
            progress = state.worker_progress;
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

#[cfg(unix)]
struct CancellableStdout {
    file: File,
    cancel: LocalStream,
}

#[cfg(unix)]
impl Write for CancellableStdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use rustix::event::{poll, PollFd, PollFlags};
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
                    return rustix::io::write(&self.file, &bytes[..bytes.len().min(4096)])
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
