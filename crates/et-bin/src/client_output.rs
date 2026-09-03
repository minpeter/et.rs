//! Bounded, nonblocking local console-output worker for opt-in flow control.

use std::collections::VecDeque;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::process::{ChildStderr, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use et_cli::client::FlowControlMode;
#[cfg(unix)]
use et_net::local::LocalStream;

const OUTPUT_BYTES: usize = 64 * 1024;
const OUTPUT_PACKETS: usize = 4096;
const GRACEFUL_DRAIN_STALL_TIMEOUT: Duration = Duration::from_secs(1);

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
    #[cfg(unix)]
    _idle_signals: Option<(LocalStream, LocalStream)>,
    cancel: Option<Box<dyn FnOnce() + Send>>,
    graceful_finish: Option<Box<dyn FnOnce() -> io::Result<()> + Send>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ConsoleOutput {
    pub(crate) fn stdout(mode: FlowControlMode) -> io::Result<Self> {
        if mode == FlowControlMode::None {
            return Self::new_with_lifecycle(
                mode,
                Box::new(io::stdout()),
                Box::new(|| {}),
                Box::new(|| Ok(())),
            );
        }
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
                move |shared| {
                    Box::new(WindowsHelperWriter {
                        input,
                        ack,
                        shared: Arc::clone(shared),
                    })
                },
                Box::new(move || cancel_windows_helper(&cancel_child)),
                Box::new(move || wait_windows_helper(&graceful_child)),
            )
        }
    }

    #[cfg(test)]
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
        Self::new_with_lifecycle_factory(mode, move |_| writer, cancel, graceful_finish)
    }

    fn new_with_lifecycle_factory<F>(
        mode: FlowControlMode,
        writer: F,
        cancel: Box<dyn FnOnce() + Send>,
        graceful_finish: Box<dyn FnOnce() -> io::Result<()> + Send>,
    ) -> io::Result<Self>
    where
        F: FnOnce(&Arc<Shared>) -> Box<dyn Write + Send>,
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
        match mode {
            FlowControlMode::None => {
                return Ok(Self {
                    mode,
                    shared: None,
                    #[cfg(unix)]
                    capacity_wake,
                    #[cfg(unix)]
                    status_wake,
                    #[cfg(unix)]
                    _idle_signals: Some((capacity_signal, status_signal)),
                    cancel: None,
                    graceful_finish: None,
                    worker: None,
                });
            }
            FlowControlMode::Backpressure | FlowControlMode::Discard => {}
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                bytes: 0,
                stopping: false,
                error: None,
                cursor_reports: 0,
                worker_done: false,
                worker_progress: 0,
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
                    &mut writer,
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
            #[cfg(unix)]
            _idle_signals: None,
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
        if self.mode == FlowControlMode::Backpressure && bytes.len() > OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal output packet exceeds console queue capacity",
            ));
        }
        let retained = if bytes.len() > OUTPUT_BYTES {
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
        match self.mode {
            FlowControlMode::None => unreachable!("none has no shared output queue"),
            FlowControlMode::Backpressure
                if state.bytes.saturating_add(retained.len()) > OUTPUT_BYTES
                    || state.queue.len() >= OUTPUT_PACKETS =>
            {
                return Ok(false);
            }
            FlowControlMode::Backpressure => {}
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
        let stalled = wait_for_graceful_drain(&shared)?;
        if stalled {
            if let Some(cancel) = self.cancel.take() {
                cancel();
            }
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("console output worker panicked"))?;
        }
        self.check_error()?;
        if let Some(finish) = self.graceful_finish.take() {
            finish()?;
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
        if let Some(shared) = &self.shared {
            if let Ok(mut state) = shared.state.lock() {
                state.stopping = true;
                shared.wake.notify_all();
            }
        }
        self.graceful_finish = None;
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
    writer: &mut dyn Write,
    #[cfg(unix)] capacity_signal: &mut LocalStream,
    #[cfg(unix)] status_signal: &mut LocalStream,
) {
    let _done = WorkerDone(shared);
    loop {
        let bytes = {
            let Ok(state) = shared.state.lock() else {
                return;
            };
            let Ok(mut state) = shared
                .wake
                .wait_while(state, |state| state.queue.is_empty() && !state.stopping)
            else {
                return;
            };
            let Some(bytes) = state.queue.pop_front() else {
                return;
            };
            state.bytes -= bytes.bytes.len();
            bytes
        };
        #[cfg(unix)]
        signal_capacity(capacity_signal);
        if let Err(error) =
            write_all_with_progress(shared, writer, &bytes.bytes).and_then(|()| writer.flush())
        {
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
        bytes.terminal_modes.observe(&bytes.bytes);
        if crate::client_terminal::contains_cursor_report_request(&bytes.bytes) {
            if let Ok(mut state) = shared.state.lock() {
                state.cursor_reports += 1;
            }
            #[cfg(unix)]
            signal_capacity(capacity_signal);
        }
    }
}

fn write_all_with_progress(
    shared: &Shared,
    writer: &mut dyn Write,
    mut bytes: &[u8],
) -> io::Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                bytes = &bytes[count..];
                report_worker_progress(shared)?;
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

#[cfg(windows)]
struct WindowsHelperWriter {
    input: ChildStdin,
    ack: ChildStderr,
    shared: Arc<Shared>,
}

#[cfg(windows)]
impl Write for WindowsHelperWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "console packet too large"))?;
        self.input.write_all(&length.to_le_bytes())?;
        self.input.write_all(bytes)?;
        self.input.flush()?;
        let mut acknowledged = 0usize;
        while acknowledged < bytes.len() {
            let mut ack = [0u8; 4];
            std::io::Read::read_exact(&mut self.ack, &mut ack)?;
            let count = u32::from_le_bytes(ack) as usize;
            if count == 0 || count > bytes.len() - acknowledged {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "console helper acknowledgement is invalid",
                ));
            }
            acknowledged += count;
            report_worker_progress(&self.shared)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut acknowledgements = io::stderr().lock();
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
            if (remaining.is_empty() && output.flush().is_err())
                || acknowledgements
                    .write_all(&(count as u32).to_le_bytes())
                    .and_then(|()| acknowledgements.flush())
                    .is_err()
            {
                return 1;
            }
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
