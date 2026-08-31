use std::sync::{Arc, Condvar, Mutex, Weak};

use et_core::flow_control::{FlowControlMode, OutputQueue};
use et_core::packet::Packet;
use et_net::connection::ConnError;

use super::{ActiveSession, SessionError, FLOW_CONTROL_BUFFER_BYTES};

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
}

pub(super) struct FlowControl {
    state: Mutex<WriterState>,
    wake: Condvar,
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
            }),
            wake: Condvar::new(),
        }
    }

    pub(super) fn enqueue(&self, packet: Packet) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        if state.stop != StopMode::Running {
            return Err(SessionError::Unavailable);
        }
        state
            .queue
            .push(packet)
            .map_err(|_| SessionError::Connection(ConnError::Backpressure))?;
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    pub(super) fn can_accept_terminal(&self, bytes: usize) -> Result<bool, SessionError> {
        let state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        Ok(state.stop == StopMode::Running && state.queue.can_accept_terminal(bytes))
    }

    pub(super) fn pause(&self) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        state.paused = true;
        state = self
            .wake
            .wait_while(state, |state| state.in_flight)
            .map_err(|_| SessionError::Unavailable)?;
        drop(state);
        Ok(())
    }

    pub(super) fn resume(&self, connected: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.connected = connected;
            state.paused = false;
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
            state.stop = StopMode::Graceful;
            state.paused = false;
            self.wake.notify_all();
        }
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

    fn next_packet(&self) -> Option<Packet> {
        let state = self.state.lock().ok()?;
        let mut state = self
            .wake
            .wait_while(state, |state| match state.stop {
                StopMode::Hard => false,
                StopMode::Graceful => state.queue.bytes() == 0 && state.in_flight,
                StopMode::Running => state.paused || !state.connected || state.queue.bytes() == 0,
            })
            .ok()?;
        match state.stop {
            StopMode::Hard => None,
            StopMode::Graceful if state.queue.bytes() == 0 => None,
            StopMode::Running | StopMode::Graceful => {
                let packet = state.queue.pop()?;
                state.in_flight = true;
                self.wake.notify_all();
                Some(packet)
            }
        }
    }

    fn complete(&self, packet: Packet, result: &Result<(), SessionError>, connected: bool) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.in_flight = false;
        state.connected = connected;
        match result {
            Ok(()) => {}
            Err(SessionError::Connection(ConnError::Backpressure)) => {
                state.queue.push_front(packet)
            }
            Err(error) => {
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
        let prepared = match session.connection.lock() {
            Ok(mut connection) => connection
                .prepare_write_packet(packet.header(), packet.payload())
                .map_err(SessionError::Connection),
            Err(_) => Err(SessionError::Unavailable),
        };
        let result =
            prepared.and_then(|prepared| prepared.send().map_err(SessionError::Connection));
        let connected = match session.connection.lock() {
            Ok(mut connection) => {
                if result.is_err() {
                    connection.disconnect();
                }
                connection.connected()
            }
            Err(_) => false,
        };
        if !flow.complete(packet, &result, connected) {
            return;
        }
    }
}
