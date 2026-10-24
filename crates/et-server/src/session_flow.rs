#[cfg(windows)]
use std::sync::atomic::Ordering;
#[cfg(windows)]
use std::sync::{Arc, Weak};
use std::sync::{Condvar, Mutex};
#[cfg(unix)]
use std::time::Instant;

use et_core::flow_control::{
    is_terminal_output, FlowControlMode, OutputLane, OutputQueue, QueuePushError,
};
use et_core::packet::Packet;
use et_net::connection::ConnError;

use super::{ActiveSession, SessionError, FLOW_CONTROL_BUFFER_BYTES};

/// Unsent output staged while the client is connected, summed over both
/// output lanes. Upstream's `TerminalServer` WriteBuffer caps this at 16 MB,
/// but the queue only has to keep the transport fed between writes (its
/// unsent bytes are bounded by `TCP_NOTSENT_LOWAT` on Linux); anything beyond
/// that is resident memory that only grows when the client is slower than
/// the producer, and stale output Ctrl+C must discard. The producer is held
/// back by terminal/pipe backpressure instead of the daemon heap. This bounds
/// admission: output staged while disconnected drains after reconnection
/// rather than being evicted.
pub(super) const CONNECTED_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
/// `OutputQueue` bounds its terminal and control lanes independently, so
/// terminal floods never starve keepalives or forwarding. Each connected lane
/// gets half of [`CONNECTED_OUTPUT_BYTES`]; 1 MiB still spans several
/// transport send-buffer refills and admits the largest single packet a
/// terminal or jump terminal relays.
const CONNECTED_LANE_BYTES: usize = CONNECTED_OUTPUT_BYTES / 2;
/// Terminal output the bridge reads ahead while a default-buffered client is
/// connected. Admission still takes one packet up to the whole lane, but
/// the bridge stops reading the terminal past this, so a keystroke echo
/// waits behind less flood: during a `yes` flood, echo dropped from about
/// 25 to 15 ms against reading up to the 1 MiB lane, throughput unchanged.
/// Eight times the unsent-byte bound still keeps the transport fed.
const CONNECTED_TERMINAL_READ_AHEAD: usize = 256 * 1024;
/// Per-lane bound while no client is connected; both lanes together may
/// stage twice this until reconnection.
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
    bridge_waiting: BridgeWait,
    stop: StopMode,
    unrecoverable: bool,
    default_buffering: bool,
    input: et_core::output_interrupt::InterruptInput,
    /// An interrupt flush dropped output, so the bridge must drain and
    /// discard what the terminal already emitted before it delivers that
    /// input (upstream `drainDiscardReadableBytes`).
    interrupt_drain: bool,
    /// A blocking writer is parked in [`FlowControl::next_item`]. Only it
    /// needs an enqueue wake: the Unix session loop pumps output itself, and
    /// an unconditional notify costs a futex syscall per packet.
    writer_waiting: bool,
}

/// Refusals the bridge is waiting on; a writer completion signals it once the
/// matching condition clears.
#[derive(Default)]
struct BridgeWait {
    /// The terminal lane refused output.
    terminal: bool,
    /// The control lane (forwarding, keepalive, ...) refused a packet.
    control: bool,
    /// Exit status is held until all preceding output has drained.
    drain: bool,
}

impl WriterState {
    fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
        if self.default_buffering {
            self.queue.set_limit(if connected {
                CONNECTED_LANE_BYTES
            } else {
                DISCONNECTED_OUTPUT_BYTES
            });
        }
    }

    fn wait_for_lane(&mut self, packet: &Packet) {
        if is_terminal_output(packet) {
            self.bridge_waiting.terminal = true;
        } else {
            self.bridge_waiting.control = true;
        }
    }

    /// Terminal bytes past which the bridge stops reading the terminal, if
    /// that is below the lane bound.
    fn terminal_read_ahead(&self) -> Option<usize> {
        (self.default_buffering && self.connected).then_some(CONNECTED_TERMINAL_READ_AHEAD)
    }

    /// Clears the bridge waits whose refusal has cleared and reports whether
    /// any did. Each refused lane resumes on its own occupancy: half of its
    /// byte budget and packet slots free, so a saturated stream refills in
    /// batches; a fully drained queue releases every wait.
    fn take_ready_bridge_wait(&mut self) -> bool {
        let resume_bytes = (self.queue.limit() / 2).max(32 * 1024);
        let drained = self.queue.is_empty();
        let mut ready = false;
        if self.bridge_waiting.terminal
            && (drained
                || (self.queue.can_resume(OutputLane::Terminal, resume_bytes)
                    && self
                        .terminal_read_ahead()
                        .is_none_or(|ahead| self.queue.terminal_bytes() <= ahead / 2)))
        {
            self.bridge_waiting.terminal = false;
            ready = true;
        }
        if self.bridge_waiting.control
            && (drained || self.queue.can_resume(OutputLane::Control, resume_bytes))
        {
            self.bridge_waiting.control = false;
            ready = true;
        }
        if self.bridge_waiting.drain && drained {
            self.bridge_waiting.drain = false;
            ready = true;
        }
        ready
    }
}

pub(super) struct FlowControl {
    state: Mutex<WriterState>,
    wake: Condvar,
    #[cfg(test)]
    enqueue_hook: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
}

impl FlowControl {
    pub(super) fn new(mode: FlowControlMode) -> Self {
        Self::with_limit(mode, FLOW_CONTROL_BUFFER_BYTES)
    }

    pub(super) fn new_default() -> Self {
        Self::with_limit(FlowControlMode::Backpressure, CONNECTED_LANE_BYTES)
    }

    fn with_limit(mode: FlowControlMode, limit: usize) -> Self {
        Self {
            state: Mutex::new(WriterState {
                queue: OutputQueue::new(mode, limit),
                connected: true,
                paused: false,
                in_flight: false,
                pending_live_in_flight: None,
                bridge_waiting: BridgeWait::default(),
                stop: StopMode::Running,
                unrecoverable: false,
                default_buffering: limit == CONNECTED_LANE_BYTES,
                input: et_core::output_interrupt::InterruptInput::default(),
                interrupt_drain: false,
                writer_waiting: false,
            }),
            wake: Condvar::new(),
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
            state.bridge_waiting.drain = true;
            return Err((packet, SessionError::Connection(ConnError::Backpressure)));
        }
        let was_empty = state.queue.is_empty();
        match state.queue.push(packet) {
            Ok(()) => {
                #[cfg(test)]
                self.run_enqueue_hook();
                let should_wake = was_empty && !state.in_flight && state.writer_waiting;
                drop(state);
                if should_wake {
                    self.wake.notify_one();
                }
                Ok(())
            }
            Err(QueuePushError::Full(packet)) => {
                state.wait_for_lane(&packet);
                Err((packet, SessionError::Connection(ConnError::Backpressure)))
            }
            Err(QueuePushError::Oversized(packet)) => {
                Err((packet, SessionError::Connection(ConnError::PacketTooLarge)))
            }
        }
    }

    /// Windows bridge output: writes directly while nothing is queued or in
    /// flight, otherwise stages the packet for the writer thread.
    #[cfg(windows)]
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
            state.bridge_waiting.drain = true;
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
                                state.wait_for_lane(&packet);
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
                state.wait_for_lane(&packet);
                Err((packet, SessionError::Connection(ConnError::Backpressure)))
            }
            Err(QueuePushError::Oversized(packet)) => {
                Err((packet, SessionError::Connection(ConnError::PacketTooLarge)))
            }
        }
    }

    #[cfg(windows)]
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

    pub(super) fn observe_input(&self, bytes: &[u8]) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        if state.input.feed(bytes) && state.queue.flush_terminal_on_interrupt() > 0 {
            state.interrupt_drain = true;
        }
        self.wake.notify_all();
        Ok(())
    }

    /// Whether input observed since the last call flushed output on
    /// interrupt, so the bridge must drain the terminal before writing it.
    pub(super) fn take_interrupt_drain(&self) -> Result<bool, SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        Ok(std::mem::take(&mut state.interrupt_drain))
    }

    /// Queue terminal output drained after an interrupt flush and drop
    /// every droppable terminal byte; see
    /// [`OutputQueue::discard_drained_terminal`].
    pub(super) fn discard_drained_terminal(
        &self,
        drained: Vec<Packet>,
    ) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        state.queue.discard_drained_terminal(drained);
        Ok(())
    }

    pub(super) fn can_accept_terminal(&self, bytes: usize) -> Result<bool, SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Unavailable)?;
        let ok = state.stop == StopMode::Running
            && state.queue.can_accept_terminal(bytes)
            && state
                .terminal_read_ahead()
                .is_none_or(|ahead| state.queue.terminal_bytes().saturating_add(bytes) <= ahead);
        if !ok {
            state.bridge_waiting.terminal = true;
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

    #[cfg(all(test, windows))]
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
        let mut state = self.state.lock().ok()?;
        state.writer_waiting = true;
        let mut state = self.wake.wait_while(state, writer_must_wait).ok()?;
        state.writer_waiting = false;
        self.take_item(&mut state)
    }

    /// [`Self::next_item`] for the session loop: `None` wherever a blocking
    /// writer would wait.
    #[cfg(unix)]
    fn try_next_item(&self) -> Option<(Packet, bool)> {
        let mut state = self.state.lock().ok()?;
        if writer_must_wait(&mut state) {
            return None;
        }
        self.take_item(&mut state)
    }

    fn take_item(&self, state: &mut WriterState) -> Option<(Packet, bool)> {
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

    /// The session loop stopped while `packet`'s frame was still partly on
    /// the wire. The blocking drain that follows finishes that frame first.
    #[cfg(unix)]
    fn hand_back_live(&self, packet: Packet) {
        if let Ok(mut state) = self.state.lock() {
            debug_assert!(state.pending_live_in_flight.is_none());
            state.pending_live_in_flight = Some(packet);
            state.in_flight = false;
            self.wake.notify_all();
        }
    }

    /// The session loop took `packet` but the transport had no room to start
    /// its frame: put it back at the front, still droppable on interrupt.
    #[cfg(unix)]
    fn return_unstarted(&self, packet: Packet) {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight = false;
            state.queue.restore_front(packet);
            if state.paused {
                self.wake.notify_all();
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
        // Wake a backpressured bridge once the lane that refused it has room
        // for a batch (see `take_ready_bridge_wait`), not after every
        // delivered packet.
        let should_signal = state.take_ready_bridge_wait()
            || !connected
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

/// Whether a writer must wait before taking its next item.
fn writer_must_wait(state: &mut WriterState) -> bool {
    match state.stop {
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
    }
}

/// Write one item taken by [`FlowControl::next_item`], blocking until its
/// frame is on the wire or fails. Returns whether the writer keeps running
/// and whether the bridge must re-check backpressure or connection state.
fn write_item(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: Packet,
    is_pending_live: bool,
) -> (bool, bool) {
    let (result, connected) = if is_pending_live {
        writer::finish_pending_packet(session, flow)
    } else {
        writer::write_packet(session, flow, &packet)
    };
    flow.complete_with_signal(packet, &result, connected)
}

/// Deliver what the session loop left queued, on the calling thread, until
/// the queue stops. The terminal bridge has exited, so nothing needs waking.
#[cfg(unix)]
pub(super) fn write_until_stopped(session: &ActiveSession, flow: &FlowControl) {
    while let Some((packet, is_pending_live)) = flow.next_item() {
        if flow.is_hard_stopped() || !write_item(session, flow, packet, is_pending_live).0 {
            return;
        }
    }
}

/// Windows writer thread. The bridge there cannot poll the client socket
/// together with its other sources, so a thread owns blocking writes.
#[cfg(windows)]
pub(super) fn run_writer(session: Weak<ActiveSession>, flow: Arc<FlowControl>) {
    while let Some((packet, is_pending_live)) = flow.next_item() {
        if flow.is_hard_stopped() {
            return;
        }
        let Some(session) = session.upgrade() else {
            return;
        };
        let (running, should_signal) = write_item(&session, &flow, packet, is_pending_live);
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

/// Session-loop output (Unix): writes queued packets without blocking, so
/// one thread both reads and writes the client transport, as upstream
/// `TerminalServer::runTerminal` drains its `WriteBuffer` in its select loop.
#[cfg(unix)]
pub(crate) struct OutputPump<'a> {
    session: &'a ActiveSession,
    /// Packet whose frame is partly on the wire. It keeps its queue capacity
    /// and the in-flight state recovery waits on until the frame completes.
    live: Option<Packet>,
    /// When queued output started waiting for transport room to start its
    /// next frame; see [`writer::write_nonblocking`].
    room_wait: Option<Instant>,
}

#[cfg(unix)]
pub(crate) struct PumpOutcome {
    /// Live-write deadline while a frame, or queued output that has no
    /// transport room to start one, waits for the client socket to drain.
    pub(crate) deadline: Option<Instant>,
    /// A completion changed state the loop waits on (lane capacity,
    /// connectivity, stop); re-check before sleeping.
    pub(crate) wake: bool,
}

#[cfg(unix)]
impl<'a> OutputPump<'a> {
    pub(crate) fn new(session: &'a ActiveSession) -> Self {
        Self {
            session,
            live: None,
            room_wait: None,
        }
    }

    /// Write until the queue is empty or paused, or output waits for
    /// transport room. A partly written frame keeps advancing during a
    /// recovery pause, which waits for it.
    pub(crate) fn run(&mut self) -> PumpOutcome {
        let mut outcome = PumpOutcome {
            deadline: None,
            wake: false,
        };
        let Some(flow) = self.session.output_flow() else {
            return outcome;
        };
        loop {
            let (packet, started) = match self.live.take() {
                Some(packet) => (packet, true),
                None => match flow.try_next_item() {
                    Some(item) => item,
                    None => {
                        self.room_wait = None;
                        return outcome;
                    }
                },
            };
            match writer::write_nonblocking(
                self.session,
                flow,
                &packet,
                started,
                &mut self.room_wait,
            ) {
                writer::NonblockingWrite::Pending(deadline) => {
                    self.live = Some(packet);
                    outcome.deadline = Some(deadline);
                    return outcome;
                }
                writer::NonblockingWrite::NoRoom(deadline) => {
                    flow.return_unstarted(packet);
                    outcome.deadline = Some(deadline);
                    return outcome;
                }
                writer::NonblockingWrite::Done(result, connected) => {
                    let (running, should_signal) =
                        flow.complete_with_signal(packet, &result, connected);
                    outcome.wake |= should_signal;
                    if !running {
                        return outcome;
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
impl Drop for OutputPump<'_> {
    fn drop(&mut self) {
        if let (Some(packet), Some(flow)) = (self.live.take(), self.session.output_flow()) {
            flow.hand_back_live(packet);
        }
    }
}

#[cfg(all(test, unix))]
impl OutputPump<'_> {
    /// Run like the session loop until nothing more can be written now,
    /// waiting on `stream` for room. `wake` reports any completion's wake.
    pub(crate) fn run_until_idle(&mut self, stream: &std::net::TcpStream) -> PumpOutcome {
        let mut woke = false;
        loop {
            let mut outcome = self.run();
            woke |= outcome.wake;
            let Some(deadline) = outcome.deadline else {
                outcome.wake = woke;
                return outcome;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = rustix::time::Timespec::try_from(remaining).unwrap();
            let mut descriptors = [rustix::event::PollFd::new(
                stream,
                rustix::event::PollFlags::OUT,
            )];
            let _ = rustix::event::poll(&mut descriptors, Some(&timeout));
        }
    }
}
