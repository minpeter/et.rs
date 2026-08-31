//! Bounded, nonblocking local console-output worker for opt-in flow control.

use std::collections::VecDeque;
#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use et_cli::client::FlowControlMode;
#[cfg(unix)]
use et_net::local::LocalStream;

const OUTPUT_BYTES: usize = 64 * 1024;
const OUTPUT_PACKETS: usize = 4096;

struct State {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    stopping: bool,
    error: Option<io::Error>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

pub(crate) struct ConsoleOutput {
    mode: FlowControlMode,
    shared: Option<Arc<Shared>>,
    #[cfg(unix)]
    capacity_wake: LocalStream,
    #[cfg(unix)]
    _idle_signal: Option<LocalStream>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ConsoleOutput {
    pub(crate) fn stdout(mode: FlowControlMode) -> io::Result<Self> {
        Self::new(mode, Box::new(io::stdout()))
    }

    pub(crate) fn new(
        mode: FlowControlMode,
        mut writer: Box<dyn Write + Send>,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        let (capacity_wake, mut capacity_signal) = {
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
                    _idle_signal: Some(capacity_signal),
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
            }),
            wake: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("et-console-output".to_owned())
            .spawn(move || {
                run_writer(
                    &worker_shared,
                    &mut writer,
                    #[cfg(unix)]
                    &mut capacity_signal,
                );
            })?;
        Ok(Self {
            mode,
            shared: Some(shared),
            #[cfg(unix)]
            capacity_wake,
            #[cfg(unix)]
            _idle_signal: None,
            worker: Some(worker),
        })
    }

    /// Attempt to admit one complete terminal-output packet without waiting.
    ///
    /// `Ok(false)` leaves ownership with the caller, which must retry the same
    /// packet before reading another server packet.
    pub(crate) fn try_write(&self, bytes: &[u8]) -> io::Result<bool> {
        let Some(shared) = &self.shared else {
            io::stdout()
                .lock()
                .write_all(bytes)
                .and_then(|()| io::stdout().lock().flush())?;
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
                    state.bytes -= removed.len();
                }
            }
        }
        state.bytes += retained.len();
        state.queue.push_back(retained.to_vec());
        drop(state);
        shared.wake.notify_one();
        Ok(true)
    }

    #[cfg(unix)]
    pub(crate) fn wake(&self) -> &LocalStream {
        &self.capacity_wake
    }

    #[cfg(unix)]
    pub(crate) fn drain_wake(&mut self) -> io::Result<()> {
        let mut bytes = [0u8; 64];
        loop {
            match self.capacity_wake.read(&mut bytes) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
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
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_writer(
    shared: &Shared,
    writer: &mut dyn Write,
    #[cfg(unix)] capacity_signal: &mut LocalStream,
) {
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
            state.bytes -= bytes.len();
            bytes
        };
        #[cfg(unix)]
        signal_capacity(capacity_signal);
        if let Err(error) = writer.write_all(&bytes).and_then(|()| writer.flush()) {
            if let Ok(mut state) = shared.state.lock() {
                state.error = Some(error);
                state.stopping = true;
                shared.wake.notify_all();
            }
            #[cfg(unix)]
            signal_capacity(capacity_signal);
            return;
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
