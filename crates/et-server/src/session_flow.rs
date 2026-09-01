use std::sync::{Arc, Condvar, Mutex, Weak};

use et_core::flow_control::{FlowControlMode, OutputQueue, QueuePushError};
use et_core::packet::Packet;
use et_net::connection::ConnError;

use super::{ActiveSession, SessionError, FLOW_CONTROL_BUFFER_BYTES};

#[cfg(test)]
#[path = "session_flow_hook.rs"]
mod test_hook;
#[path = "session_flow_write.rs"]
pub(super) mod writer;
#[cfg(test)]
pub(super) use writer::FlowWriteResult;

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopMode {
    Running,
    Graceful,
    Hard,
}

struct WriterState {
    queue: OutputQueue,
    connected: bool,
    paused: bool,
    in_flight: bool,
    reader_waiting: bool,
    stop: StopMode,
    unrecoverable: bool,
}

pub(super) struct FlowControl {
    state: Mutex<WriterState>,
    wake: Condvar,
    #[cfg(test)]
    enqueue_hook: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
}

impl FlowControl {
    pub(super) fn new(mode: FlowControlMode) -> Self {
        Self {
            state: Mutex::new(WriterState {
                queue: OutputQueue::new(mode, FLOW_CONTROL_BUFFER_BYTES),
                connected: true,
                paused: false,
                in_flight: false,
                reader_waiting: false,
                stop: StopMode::Running,
                unrecoverable: false,
            }),
            wake: Condvar::new(),
            #[cfg(test)]
            enqueue_hook: Mutex::new(None),
        }
    }

    pub(super) fn enqueue(&self, packet: Packet) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        if state.stop != StopMode::Running {
            return Err(SessionError::Unavailable);
        }
        match state.queue.push(packet) {
            Ok(()) => {
                #[cfg(test)]
                self.run_enqueue_hook();
                drop(state);
                self.wake.notify_one();
                Ok(())
            }
            Err(QueuePushError::Full(_packet)) => {
                Err(SessionError::Connection(ConnError::Backpressure))
            }
            Err(QueuePushError::Oversized(_packet)) => {
                Err(SessionError::Connection(ConnError::PacketTooLarge))
            }
        }
    }

    pub(super) fn can_accept_terminal(&self, bytes: usize) -> Result<bool, SessionError> {
        let state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        Ok(state.stop == StopMode::Running && state.queue.can_accept_terminal(bytes))
    }

    pub(super) fn pause(&self) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        state.paused = true;
        let state = match self.wake.wait_while(state, |state| state.in_flight) {
            Ok(state) => state,
            Err(error) => {
                error.into_inner().paused = false;
                self.wake.notify_all();
                return Err(SessionError::Unavailable);
            }
        };
        drop(state);
        Ok(())
    }

    pub(super) fn resume(&self, connected: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.connected = connected;
            state.paused = false;
            if !connected && state.stop == StopMode::Graceful {
                state.unrecoverable = true;
                state.stop = StopMode::Hard;
            }
            self.wake.notify_all();
        }
    }

    pub(super) fn disconnected(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.connected = false;
            self.wake.notify_all();
        }
    }

    pub(super) fn set_reader_waiting(&self, waiting: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.reader_waiting = waiting;
            self.wake.notify_all();
        }
    }

    fn wait_for_reader(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok(state) = self.wake.wait_while(state, |state| {
            state.reader_waiting && state.stop != StopMode::Hard
        }) else {
            return false;
        };
        state.stop != StopMode::Hard
    }

    pub(super) fn stop_gracefully(&self) {
        if let Ok(mut state) = self.state.lock() {
            // A recovery pause owns the connection snapshot until its permit
            // installs the candidate (or safely abandons it). Terminal EOF
            // must not bypass that pause and drain queued output onto the old
            // stream; RecoverPermit::drop resumes the writer atomically.
            if state.stop == StopMode::Running {
                if state.connected || state.paused {
                    state.stop = StopMode::Graceful;
                } else {
                    state.unrecoverable = true;
                    state.stop = StopMode::Hard;
                }
                self.wake.notify_all();
            }
        }
    }

    pub(super) fn unrecoverable(&self) -> bool {
        self.state.lock().map_or(true, |state| state.unrecoverable)
    }

    pub(super) fn stop_hard(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stop = StopMode::Hard;
            self.wake.notify_all();
        }
    }

    #[cfg(test)]
    pub(super) fn wait_in_flight(&self) {
        let state = self.state.lock().unwrap();
        drop(
            self.wake
                .wait_while(state, |state| !state.in_flight)
                .unwrap(),
        );
    }

    #[cfg(test)]
    pub(super) fn wait_for_stop(&self, graceful: bool) {
        let state = self.state.lock().unwrap();
        drop(
            self.wake
                .wait_while(state, |state| {
                    state.stop
                        != if graceful {
                            StopMode::Graceful
                        } else {
                            StopMode::Hard
                        }
                })
                .unwrap(),
        );
    }

    fn is_hard_stopped(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.stop == StopMode::Hard)
    }

    pub(super) fn next_packet(&self) -> Option<Packet> {
        let state = self.state.lock().ok()?;
        let mut state = self
            .wake
            .wait_while(state, |state| match state.stop {
                StopMode::Hard => false,
                StopMode::Graceful => {
                    state.paused
                        || (!state.connected && !state.queue.is_empty())
                        || (state.queue.is_empty() && state.in_flight)
                }
                StopMode::Running => state.paused || !state.connected || state.queue.is_empty(),
            })
            .ok()?;
        match state.stop {
            StopMode::Hard => None,
            StopMode::Graceful if state.queue.is_empty() => None,
            StopMode::Running | StopMode::Graceful => {
                let packet = state.queue.take()?;
                state.in_flight = true;
                self.wake.notify_all();
                Some(packet)
            }
        }
    }

    pub(super) fn complete(
        &self,
        packet: Packet,
        result: &writer::FlowWriteResult,
        connected: bool,
    ) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.in_flight = false;
        state.connected = connected;
        match result {
            writer::FlowWriteResult::Delivered => {
                state.queue.complete(&packet);
                if !connected && state.stop == StopMode::Graceful {
                    state.unrecoverable = true;
                    state.stop = StopMode::Hard;
                }
            }
            writer::FlowWriteResult::BeforeReplay(_error) => {
                state.queue.restore_front(packet);
                state.connected = false;
                if state.stop == StopMode::Graceful {
                    state.unrecoverable = true;
                    state.stop = StopMode::Hard;
                }
            }
            writer::FlowWriteResult::ReplayOwned(_error) => {
                state.queue.complete(&packet);
                state.connected = false;
                if state.stop == StopMode::Graceful {
                    state.unrecoverable = true;
                    state.stop = StopMode::Hard;
                }
            }
            writer::FlowWriteResult::Fatal(error) => {
                state.queue.complete(&packet);
                crate::diag::info(format!("flow-control writer stopped: {error}"));
                state.stop = StopMode::Hard;
            }
        }
        self.wake.notify_all();
        state.stop != StopMode::Hard
    }
}

pub(super) fn run_writer(session: Weak<ActiveSession>, flow: Arc<FlowControl>) {
    while let Some(packet) = flow.next_packet() {
        if !flow.wait_for_reader() {
            return;
        }
        let Some(session) = session.upgrade() else {
            return;
        };
        // Popping this packet may have reopened bounded queue capacity.
        // Wake the bridge so it polls terminal output again instead of
        // sleeping indefinitely with terminal readability disabled.
        let _ = session.signal();
        let (result, connected) = writer::write_packet(&session, &flow, &packet);
        if !flow.complete(packet, &result, connected) {
            return;
        }
    }
}
