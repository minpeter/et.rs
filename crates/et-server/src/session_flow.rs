use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use et_core::flow_control::{FlowControlMode, OutputQueue, QueuePushError};
use et_core::packet::Packet;
use et_net::connection::ConnError;

use super::{ActiveSession, SessionError, FLOW_CONTROL_BUFFER_BYTES};

const CONNECTED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const DISCONNECTED_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

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
    pending_live_in_flight: Option<Packet>,
    bridge_waiting: bool,
    stop: StopMode,
    unrecoverable: bool,
    default_buffering: bool,
    input: et_core::output_interrupt::InterruptInput,
}

impl WriterState {
    fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
        if self.default_buffering {
            self.queue.set_limit(if connected {
                CONNECTED_OUTPUT_BYTES
            } else {
                DISCONNECTED_OUTPUT_BYTES
            });
        }
    }
}

pub(super) struct FlowControl {
    state: Mutex<WriterState>,
    wake: Condvar,
    reader_waiting: AtomicBool,
    writer_waiting_for_reader: AtomicBool,
    #[cfg(test)]
    enqueue_hook: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
}

impl FlowControl {
    pub(super) fn new(mode: FlowControlMode) -> Self {
        Self::with_limit(mode, FLOW_CONTROL_BUFFER_BYTES)
    }

    pub(super) fn new_default() -> Self {
        Self::with_limit(FlowControlMode::Backpressure, CONNECTED_OUTPUT_BYTES)
    }

    fn with_limit(mode: FlowControlMode, limit: usize) -> Self {
        Self {
            state: Mutex::new(WriterState {
                queue: OutputQueue::new(mode, limit),
                connected: true,
                paused: false,
                in_flight: false,
                pending_live_in_flight: None,
                bridge_waiting: false,
                stop: StopMode::Running,
                unrecoverable: false,
                default_buffering: limit == CONNECTED_OUTPUT_BYTES,
                input: et_core::output_interrupt::InterruptInput::default(),
            }),
            wake: Condvar::new(),
            reader_waiting: AtomicBool::new(false),
            writer_waiting_for_reader: AtomicBool::new(false),
            #[cfg(test)]
            enqueue_hook: Mutex::new(None),
        }
    }

    pub(super) fn enqueue(&self, packet: Packet) -> Result<(), SessionError> {
        self.enqueue_owned(packet).map_err(|(_, error)| error)
    }

    pub(super) fn enqueue_owned(&self, packet: Packet) -> Result<(), (Packet, SessionError)> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err((packet, SessionError::Unavailable)),
        };
        if state.stop != StopMode::Running {
            return Err((packet, SessionError::Unavailable));
        }
        // The client may exit as soon as it sees status. Do not let the
        // fair control lane overtake preceding terminal output. The bridge
        // retains this packet and retries after the writer's completion wake.
        if packet.header() == et_core::proto::TerminalPacketType::TerminalExitStatus as u8
            && (state.in_flight || !state.queue.is_empty())
        {
            state.bridge_waiting = true;
            return Err((packet, SessionError::Connection(ConnError::Backpressure)));
        }
        let was_empty = state.queue.is_empty();
        match state.queue.push(packet) {
            Ok(()) => {
                #[cfg(test)]
                self.run_enqueue_hook();
                let should_wake = was_empty && !state.in_flight;
                drop(state);
                if should_wake {
                    self.wake.notify_one();
                }
                Ok(())
            }
            Err(QueuePushError::Full(packet)) => {
                state.bridge_waiting = true;
                Err((packet, SessionError::Connection(ConnError::Backpressure)))
            }
            Err(QueuePushError::Oversized(packet)) => {
                Err((packet, SessionError::Connection(ConnError::PacketTooLarge)))
            }
        }
    }

    pub(super) fn enqueue_bridge_owned(
        &self,
        session: &ActiveSession,
        packet: Packet,
    ) -> Result<(), (Packet, SessionError)> {
        #[cfg(test)]
        if self.enqueue_hook.lock().unwrap().is_some()
            || session.prepared_write_hook.lock().unwrap().is_some()
        {
            return self.enqueue_owned(packet);
        }
        if session.recovering.load(Ordering::Acquire) {
            return self.enqueue_owned(packet);
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err((packet, SessionError::Unavailable)),
        };
        if state.stop != StopMode::Running {
            return Err((packet, SessionError::Unavailable));
        }
        if packet.header() == et_core::proto::TerminalPacketType::TerminalExitStatus as u8
            && (state.in_flight || !state.queue.is_empty())
        {
            state.bridge_waiting = true;
            return Err((packet, SessionError::Connection(ConnError::Backpressure)));
        }
        let is_forward_data = matches!(
            packet.header(),
            h if h == et_core::proto::TerminalPacketType::PortForwardData as u8
                || h == et_core::proto::TerminalPacketType::TerminalBuffer as u8
        );
        let was_empty = state.queue.is_empty();
        if was_empty
            && !state.in_flight
            && state.pending_live_in_flight.is_none()
            && state.connected
            && !state.paused
            && packet.header() != et_core::proto::TerminalPacketType::TerminalExitStatus as u8
        {
            if let Ok(_write_serial) = session.write_serial.try_lock() {
                if let Ok(mut connection) = session.connection.try_lock() {
                    if !connection.write_pending() {
                        match state.queue.push(packet) {
                            Ok(()) => {}
                            Err(QueuePushError::Full(packet)) => {
                                state.bridge_waiting = true;
                                return Err((
                                    packet,
                                    SessionError::Connection(ConnError::Backpressure),
                                ));
                            }
                            Err(QueuePushError::Oversized(packet)) => {
                                return Err((
                                    packet,
                                    SessionError::Connection(ConnError::PacketTooLarge),
                                ));
                            }
                        }
                        let packet = state.queue.take().expect("just pushed");
                        match connection
                            .start_write_packet_owned_unprobed(packet.header(), packet.payload())
                        {
                            Ok(()) if !connection.write_pending() => {
                                let connected = connection.connected();
                                drop(connection);
                                drop(_write_serial);
                                state.queue.complete(&packet);
                                if !connected {
                                    state.set_connected(false);
                                }
                                return Ok(());
                            }
                            Ok(()) => {
                                drop(connection);
                                drop(_write_serial);
                                state.pending_live_in_flight = Some(packet);
                                if !is_forward_data {
                                    state.in_flight = true;
                                    drop(state);
                                    self.wake.notify_one();
                                }
                                return Ok(());
                            }
                            Err(et_net::connection::WritePacketError::BeforeReplay(
                                ConnError::Backpressure,
                            )) => {
                                state.queue.restore_front(packet);
                                drop(connection);
                                drop(_write_serial);
                                drop(state);
                                self.wake.notify_one();
                                return Ok(());
                            }
                            Err(error) => {
                                drop(connection);
                                drop(_write_serial);
                                state.queue.complete(&packet);
                                state.set_connected(false);
                                return Err((packet, SessionError::Connection(error.into_inner())));
                            }
                        }
                    }
                }
            }
        }
        match state.queue.push(packet) {
            Ok(()) => {
                let should_wake = !state.in_flight && (!is_forward_data && was_empty);
                drop(state);
                if should_wake {
                    self.wake.notify_one();
                }
                Ok(())
            }
            Err(QueuePushError::Full(packet)) => {
                state.bridge_waiting = true;
                Err((packet, SessionError::Connection(ConnError::Backpressure)))
            }
            Err(QueuePushError::Oversized(packet)) => {
                Err((packet, SessionError::Connection(ConnError::PacketTooLarge)))
            }
        }
    }

    pub(super) fn flush_bridge_wake(&self) {
        if let Ok(mut state) = self.state.lock() {
            if state.pending_live_in_flight.is_some() {
                state.in_flight = true;
                drop(state);
                self.wake.notify_one();
            } else if !state.queue.is_empty() && !state.in_flight {
                drop(state);
                self.wake.notify_one();
            }
        }
    }

    pub(super) fn observe_input(&self, bytes: &[u8]) -> Result<usize, SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        let dropped = if state.input.feed(bytes) {
            state.queue.flush_terminal_on_interrupt()
        } else {
            0
        };
        self.wake.notify_all();
        Ok(dropped)
    }

    pub(super) fn can_accept_terminal(&self, bytes: usize) -> Result<bool, SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        let ok = state.stop == StopMode::Running && state.queue.can_accept_terminal(bytes);
        if !ok {
            state.bridge_waiting = true;
        }
        Ok(ok)
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
            state.set_connected(connected);
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
            state.set_connected(false);
            self.wake.notify_all();
        }
    }

    pub(super) fn set_reader_waiting(&self, waiting: bool) {
        self.reader_waiting.store(waiting, Ordering::Release);
        if !waiting && self.writer_waiting_for_reader.swap(false, Ordering::AcqRel) {
            if let Ok(_state) = self.state.lock() {
                self.wake.notify_all();
            }
        }
    }

    fn wait_for_reader(&self) -> bool {
        if !self.reader_waiting.load(Ordering::Acquire) {
            return !self.is_hard_stopped();
        }
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok(state) = self.wake.wait_while(state, |state| {
            if self.reader_waiting.load(Ordering::Acquire) && state.stop != StopMode::Hard {
                self.writer_waiting_for_reader
                    .store(true, Ordering::Release);
                true
            } else {
                false
            }
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

    pub(super) fn is_hard_stopped(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.stop == StopMode::Hard)
    }

    #[cfg(test)]
    pub(super) fn next_packet(&self) -> Option<Packet> {
        self.next_item().map(|(packet, _)| packet)
    }

    fn next_item(&self) -> Option<(Packet, bool)> {
        let state = self.state.lock().ok()?;
        let mut state = self
            .wake
            .wait_while(state, |state| match state.stop {
                StopMode::Hard => false,
                StopMode::Graceful => {
                    state.paused
                        || (!state.connected
                            && (!state.queue.is_empty() || state.pending_live_in_flight.is_some()))
                        || (state.queue.is_empty()
                            && state.pending_live_in_flight.is_none()
                            && state.in_flight)
                }
                StopMode::Running => {
                    state.paused
                        || !state.connected
                        || (state.queue.is_empty() && state.pending_live_in_flight.is_none())
                }
            })
            .ok()?;
        match state.stop {
            StopMode::Hard => None,
            StopMode::Graceful
                if state.queue.is_empty() && state.pending_live_in_flight.is_none() =>
            {
                None
            }
            StopMode::Running | StopMode::Graceful => {
                if let Some(packet) = state.pending_live_in_flight.take() {
                    state.in_flight = true;
                    #[cfg(test)]
                    self.wake.notify_all();
                    return Some((packet, true));
                }
                let packet = state.queue.take()?;
                state.in_flight = true;
                #[cfg(test)]
                self.wake.notify_all();
                Some((packet, false))
            }
        }
    }

    #[cfg(test)]
    pub(super) fn complete(
        &self,
        packet: Packet,
        result: &writer::FlowWriteResult,
        connected: bool,
    ) -> bool {
        self.complete_with_signal(packet, result, connected).0
    }

    pub(super) fn complete_with_signal(
        &self,
        packet: Packet,
        result: &writer::FlowWriteResult,
        connected: bool,
    ) -> (bool, bool) {
        let Ok(mut state) = self.state.lock() else {
            return (false, true);
        };
        state.in_flight = false;
        state.set_connected(connected);
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
                state.set_connected(false);
                if state.stop == StopMode::Graceful {
                    state.unrecoverable = true;
                    state.stop = StopMode::Hard;
                }
            }
            writer::FlowWriteResult::ReplayOwned(_error) => {
                state.queue.complete(&packet);
                state.set_connected(false);
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
        let capacity_ready = state.queue.is_empty() || state.queue.can_accept_terminal(32 * 1024);
        let should_signal = (state.bridge_waiting && capacity_ready && {
            state.bridge_waiting = false;
            true
        }) || !connected
            || !matches!(result, writer::FlowWriteResult::Delivered)
            || state.stop == StopMode::Hard;
        if state.paused
            || state.stop != StopMode::Running
            || !connected
            || !matches!(result, writer::FlowWriteResult::Delivered)
            || cfg!(test)
        {
            self.wake.notify_all();
        }
        (state.stop != StopMode::Hard, should_signal)
    }
}

pub(super) fn run_writer(session: Weak<ActiveSession>, flow: Arc<FlowControl>) {
    while let Some((packet, is_pending_live)) = flow.next_item() {
        if !flow.wait_for_reader() {
            return;
        }
        let Some(session) = session.upgrade() else {
            return;
        };
        let (result, connected) = if is_pending_live {
            writer::finish_pending_packet(&session, &flow)
        } else {
            writer::write_packet(&session, &flow, &packet)
        };
        let (running, should_signal) = flow.complete_with_signal(packet, &result, connected);
        // In-flight packets still own queue capacity until complete. Wake
        // after releasing it when the bridge observed backpressure or a
        // state transition: a signal before the write can strand the
        // bridge's retained packet.
        if should_signal {
            let _ = session.signal();
        }
        if !running {
            return;
        }
    }
}
