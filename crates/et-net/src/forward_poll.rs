//! Unix single-poll forwarding engine.
//!
//! Upstream `PortForwardHandler::update` walks every forwarded socket from
//! one `select()` loop. The first Unix port instead gave each socket a
//! reader/writer thread pair, which cost one context switch per packet per
//! hop (reader wake, writer wake) even under saturation. This module moves
//! socket I/O back into the worker thread: one `poll(2)` over the command
//! wake pipe and every socket, with reads, writes, half-closes, and window
//! credit handled inline. Windows keeps the threaded model (`poll` does not
//! cover arbitrary handles there), so this file is Unix-only.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use et_core::proto::{PortForwardData, PortForwardWindow, TerminalPacketType};
use rustix::event::{poll, PollFd, PollFlags};

use crate::forward_endpoint::ForwardStream;
use crate::forward_io::{cancellation_requested, shutdown_write, FlowWindow};
use crate::ssh_agent_session_bind::AgentSessionBindReplies;

use super::state::{CREDIT_RETURN_THRESHOLD, PACKET_CREDIT_RETURN_THRESHOLD};
use super::{CommandPop, ForwardError, Role, Worker};

/// Queued network-to-socket buffers per socket, matching the bound of the
/// writer channel the threaded model used.
const OUT_QUEUE_PACKETS: usize = 64;
/// Idle sockets flush sub-threshold window credit after this delay, the same
/// cadence the writer thread's `default(2ms)` select arm provided.
const IDLE_CREDIT_FLUSH: Duration = Duration::from_millis(2);
/// Reads serviced per socket per poll cycle before moving to the next socket.
/// Large enough to drain a saturated socket buffer in one cycle, so a bulk
/// transfer does not return to poll once per handful of packets.
const READS_PER_CYCLE: usize = 64;

pub(crate) struct SocketIo {
    pub(crate) stream: ForwardStream,
    pub(crate) role: Role,
    pub(crate) socket_id: i32,
    /// Network data queued for the local socket.
    out: VecDeque<Vec<u8>>,
    /// Write progress into the front buffer.
    out_offset: usize,
    read_open: bool,
    /// Peer sent `closed`: flush `out`, then drop the socket.
    close_when_drained: bool,
    /// Peer half-closed (`et -W` stdin EOF): flush `out`, then shutdown our
    /// write side while keeping the reply direction open.
    shutdown_write_when_drained: bool,
    write_closed: bool,
    pub(crate) half_close_on_eof: bool,
    bind_replies: Option<AgentSessionBindReplies>,
    /// Peer's advertised windows, `-1` for a legacy (unwindowed) peer.
    window_bytes: i64,
    window_packets: i64,
    /// Bytes/packets sent to the peer but not yet confirmed delivered.
    in_flight_bytes: i64,
    in_flight_packets: i64,
    /// Local drains not yet returned to the peer as window credit.
    credit_bytes: i64,
    credit_packets: i64,
    credit_flush_at: Option<Instant>,
}

pub(crate) enum ReadOutcome {
    Data(Vec<u8>),
    /// No data ready right now (or the window just closed).
    Idle,
    Eof,
}

/// What the worker must do with a socket after servicing it.
enum SocketVerdict {
    Keep,
    /// Close the socket in full (peer notification already emitted).
    Drop,
    /// Local EOF: route through `read_closed`, which owns the map.
    Eof,
}

impl SocketIo {
    pub(crate) fn new(
        role: Role,
        socket_id: i32,
        stream: ForwardStream,
        peer_window: Option<FlowWindow>,
        bind_replies: Option<AgentSessionBindReplies>,
    ) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            role,
            socket_id,
            stream,
            out: VecDeque::new(),
            out_offset: 0,
            read_open: true,
            close_when_drained: false,
            shutdown_write_when_drained: false,
            write_closed: false,
            half_close_on_eof: false,
            bind_replies,
            window_bytes: peer_window.map_or(-1, |window| window.bytes),
            window_packets: peer_window.map_or(-1, |window| window.packets),
            in_flight_bytes: 0,
            in_flight_packets: 0,
            credit_bytes: 0,
            credit_packets: 0,
            credit_flush_at: None,
        })
    }

    fn windowed(&self) -> bool {
        self.window_bytes >= 0 && self.window_packets >= 0
    }

    fn read_interest(&self) -> bool {
        self.read_open
            && !self.close_when_drained
            && (!self.windowed()
                || (self.in_flight_bytes < self.window_bytes
                    && self.in_flight_packets < self.window_packets))
    }

    fn write_interest(&self) -> bool {
        !self.out.is_empty()
    }

    /// Queue network data for the local socket. The buffer comes back when
    /// the per-socket queue is full; the worker then holds it and retries
    /// before popping new commands, mirroring the backpressure the bounded
    /// writer channel provided.
    fn queue_write(&mut self, buffer: Vec<u8>) -> Result<(), Vec<u8>> {
        if self.out.len() >= OUT_QUEUE_PACKETS {
            return Err(buffer);
        }
        self.out.push_back(buffer);
        Ok(())
    }

    /// Writes after `shutdownWrite` are dropped, as upstream does. A pending
    /// half-close counts: once the peer stops reading our writes, late data
    /// has nowhere meaningful to go.
    fn write_closed(&self) -> bool {
        self.write_closed || self.close_when_drained || self.shutdown_write_when_drained
    }

    fn apply_delivery(&mut self, delivered: FlowWindow) {
        if delivered.bytes > 0 {
            self.in_flight_bytes = self.in_flight_bytes.saturating_sub(delivered.bytes).max(0);
        }
        if delivered.packets > 0 {
            self.in_flight_packets = self
                .in_flight_packets
                .saturating_sub(delivered.packets)
                .max(0);
        }
    }

    fn note_sent(&mut self, bytes: usize) {
        if !self.windowed() {
            return;
        }
        self.in_flight_bytes = self
            .in_flight_bytes
            .saturating_add(i64::try_from(bytes).unwrap_or(i64::MAX));
        self.in_flight_packets = self.in_flight_packets.saturating_add(1);
    }

    /// Read one chunk, bounded by the remaining window. Bind replies are
    /// consumed locally and never charged against the peer's window.
    fn read_chunk(&mut self, scratch: &mut [u8]) -> io::Result<ReadOutcome> {
        let limit = if self.windowed() {
            let remaining = self.window_bytes.saturating_sub(self.in_flight_bytes);
            usize::try_from(remaining.min(scratch.len() as i64)).unwrap_or(0)
        } else {
            scratch.len()
        };
        if limit == 0 {
            return Ok(ReadOutcome::Idle);
        }
        loop {
            match self.stream.read(&mut scratch[..limit]) {
                Ok(0) => return Ok(ReadOutcome::Eof),
                Ok(count) => {
                    let forwarded = match self.bind_replies.as_mut() {
                        Some(replies) => match replies.consume(&scratch[..count]) {
                            Ok(forwarded) => forwarded,
                            Err(()) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid ssh agent reply to session binding",
                                ));
                            }
                        },
                        None => scratch[..count].to_vec(),
                    };
                    // Only session-bind replies so far: keep reading, and do
                    // not present an empty read as EOF.
                    if forwarded.is_empty() {
                        continue;
                    }
                    return Ok(ReadOutcome::Data(forwarded));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(ReadOutcome::Idle);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Flush queued network data toward the local socket, crediting the peer
    /// for every buffer fully delivered (delivery, not receipt, returns
    /// credit — see `Command::Drained`).
    fn flush_out(&mut self) -> io::Result<()> {
        while let Some(front) = self.out.front() {
            let pending = &front[self.out_offset..];
            match self.stream.write(pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "forwarded socket closed during write",
                    ));
                }
                Ok(written) => {
                    self.out_offset += written;
                    if self.out_offset == front.len() {
                        let done = self.out.pop_front().unwrap_or_default();
                        self.out_offset = 0;
                        if self.windowed() {
                            self.credit_bytes = self
                                .credit_bytes
                                .saturating_add(i64::try_from(done.len()).unwrap_or(i64::MAX));
                            self.credit_packets = self.credit_packets.saturating_add(1);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if self.out.is_empty() && self.credit_bytes > 0 && self.credit_flush_at.is_none() {
            self.credit_flush_at = Some(Instant::now());
        }
        Ok(())
    }

    fn credit_due(&self, now: Instant) -> bool {
        if self.credit_bytes <= 0 || self.credit_packets <= 0 {
            return false;
        }
        if self.credit_bytes >= CREDIT_RETURN_THRESHOLD
            || self.credit_packets >= PACKET_CREDIT_RETURN_THRESHOLD
        {
            return true;
        }
        self.out.is_empty()
            && self
                .credit_flush_at
                .is_some_and(|since| now.duration_since(since) >= IDLE_CREDIT_FLUSH)
    }

    fn take_credit(&mut self) -> Option<(i64, i64)> {
        if self.credit_bytes <= 0 || self.credit_packets <= 0 {
            return None;
        }
        self.credit_flush_at = None;
        Some((
            std::mem::take(&mut self.credit_bytes),
            std::mem::take(&mut self.credit_packets),
        ))
    }

    fn credit_deadline(&self) -> Option<Instant> {
        if self.credit_bytes <= 0 || self.credit_packets <= 0 || !self.out.is_empty() {
            return None;
        }
        Some(self.credit_flush_at.unwrap_or_else(Instant::now) + IDLE_CREDIT_FLUSH)
    }
}

/// Socket readiness copied out of the poll set so the maps can be mutated.
struct ReadySocket {
    role: Role,
    socket_id: i32,
    readable: bool,
    writable: bool,
    error: bool,
}

impl Worker {
    /// Unix activation: no per-socket threads; the worker poll loop drives
    /// the socket directly.
    pub(crate) fn activate(
        &mut self,
        role: Role,
        socket_id: i32,
        stream: ForwardStream,
        peer_window: Option<FlowWindow>,
        bind_replies: Option<AgentSessionBindReplies>,
    ) -> Result<(), ForwardError> {
        let socket = SocketIo::new(role, socket_id, stream, peer_window, bind_replies)
            .map_err(ForwardError::Io)?;
        self.map_mut(role).insert(socket_id, socket);
        Ok(())
    }

    pub(crate) fn map_mut(&mut self, role: Role) -> &mut std::collections::HashMap<i32, SocketIo> {
        match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        }
    }

    pub(crate) fn map_ref(&self, role: Role) -> &std::collections::HashMap<i32, SocketIo> {
        match role {
            Role::Source => &self.sources,
            Role::Destination => &self.destinations,
        }
    }

    pub(super) fn remove(&mut self, role: Role, socket_id: i32) {
        if role == Role::Source && self.stdio_socket == Some(socket_id) {
            // The stdout copier clears the bridge flag once every queued byte
            // is flushed, so `et -W` cannot exit ahead of its trailing output.
            self.stdio_socket = None;
        }
        // Dropping the socket closes the local descriptor in full.
        self.map_mut(role).remove(&socket_id);
    }

    pub(crate) fn apply_window(&mut self, role: Role, socket_id: i32, delivered: FlowWindow) {
        if let Some(socket) = self.map_mut(role).get_mut(&socket_id) {
            socket.apply_delivery(delivered);
        }
    }

    /// The peer half-closed this socket (`et -W` stdin EOF): flush whatever
    /// is queued, then shutdown our write side and keep the reply open.
    pub(crate) fn peer_half_close(
        &mut self,
        role: Role,
        socket_id: i32,
    ) -> Result<(), ForwardError> {
        let map = match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        };
        let Some(socket) = map.get_mut(&socket_id) else {
            return Ok(());
        };
        socket.shutdown_write_when_drained = true;
        if socket.out.is_empty() && !socket.write_closed {
            socket.shutdown_write_when_drained = false;
            socket.write_closed = true;
            shutdown_write(&socket.stream);
        }
        Ok(())
    }

    /// Queue network data for the local socket, holding it worker-side when
    /// the per-socket queue is full. Held packets keep per-socket order and
    /// are retried before new commands are popped.
    pub(crate) fn admit_data(
        &mut self,
        role: Role,
        socket_id: i32,
        buffer: Vec<u8>,
    ) -> Result<(), ForwardError> {
        let map = match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        };
        let Some(socket) = map.get_mut(&socket_id) else {
            // Data for an already-closed socket id is a normal race; upstream
            // logs a warning and drops it.
            return Ok(());
        };
        if socket.write_closed() {
            return Ok(());
        }
        if let Err(buffer) = socket.queue_write(buffer) {
            self.held.push_back((role, socket_id, buffer));
        }
        Ok(())
    }

    /// The peer closed this socket: echo the close, stop reading, and flush
    /// whatever is already queued before dropping the socket, matching the
    /// threaded model's `stop_io` drain.
    pub(crate) fn peer_closed(&mut self, role: Role, socket_id: i32) -> Result<(), ForwardError> {
        if !self.map_ref(role).contains_key(&socket_id) {
            return Ok(());
        }
        self.send_data(role, socket_id, Vec::new(), true, None)?;
        let drained = {
            let map = match role {
                Role::Source => &mut self.sources,
                Role::Destination => &mut self.destinations,
            };
            match map.get_mut(&socket_id) {
                Some(socket) => {
                    socket.close_when_drained = true;
                    socket.read_open = false;
                    socket.stream.shutdown_read();
                    socket.out.is_empty()
                }
                None => true,
            }
        };
        if drained {
            self.remove(role, socket_id);
        }
        Ok(())
    }

    /// Local EOF on a socket, detected by the poll loop's zero-length read.
    pub(super) fn read_closed(&mut self, role: Role, socket_id: i32) -> Result<(), ForwardError> {
        let half_close = {
            let map = match role {
                Role::Source => &mut self.sources,
                Role::Destination => &mut self.destinations,
            };
            let Some(socket) = map.get_mut(&socket_id) else {
                // A socket the peer already closed reports nothing: upstream
                // only emits EOF for a socket it still owns.
                return Ok(());
            };
            if socket.close_when_drained {
                // The peer's close already reported this socket; a trailing
                // local EOF must not emit a second close.
                return Ok(());
            }
            socket.read_open = false;
            if socket.half_close_on_eof {
                socket.half_close_on_eof = false;
                true
            } else {
                false
            }
        };
        if half_close {
            // Upstream stdio mode: half-close the request direction and keep
            // the reply open until the remote side closes.
            return self.send_half_close(role, socket_id);
        }
        // Upstream sends `closed` and closes the socket in full. Writes
        // already queued still flush first: upstream wrote them synchronously
        // before it handled the EOF.
        self.send_data(role, socket_id, Vec::new(), true, None)?;
        let drained = {
            let map = match role {
                Role::Source => &mut self.sources,
                Role::Destination => &mut self.destinations,
            };
            match map.get_mut(&socket_id) {
                Some(socket) => {
                    socket.close_when_drained = true;
                    socket.out.is_empty()
                }
                None => true,
            }
        };
        if drained {
            self.remove(role, socket_id);
        }
        Ok(())
    }

    /// Move held network data into socket queues that have room again.
    fn flush_held(&mut self) {
        while let Some((role, socket_id)) = self.held.front().map(|(role, id, _)| (*role, *id)) {
            let map = match role {
                Role::Source => &mut self.sources,
                Role::Destination => &mut self.destinations,
            };
            match map.get_mut(&socket_id) {
                Some(socket) if !socket.write_closed() => {
                    let (_, _, buffer) = self.held.pop_front().unwrap();
                    if let Err(buffer) = socket.queue_write(buffer) {
                        self.held.push_front((role, socket_id, buffer));
                        return;
                    }
                }
                // Socket closed while its data was held: drop it, keep going.
                _ => {
                    self.held.pop_front();
                }
            }
        }
    }

    /// Return window credit whose batch or idle timer is due.
    fn flush_due_credits(&mut self) -> Result<(), ForwardError> {
        let now = Instant::now();
        for role in [Role::Source, Role::Destination] {
            let due: Vec<i32> = self
                .map_ref(role)
                .iter()
                .filter(|(_, socket)| socket.credit_due(now))
                .map(|(socket_id, _)| *socket_id)
                .collect();
            for socket_id in due {
                let Some((credit, packet_credit)) = self
                    .map_mut(role)
                    .get_mut(&socket_id)
                    .and_then(SocketIo::take_credit)
                else {
                    continue;
                };
                self.emit_priority(
                    TerminalPacketType::PortForwardData as u8,
                    PortForwardData {
                        // Credit travels toward the peer that SENDS on this
                        // socket, the same direction flag data uses for this
                        // role. Inverting it would land the credit in the
                        // peer's other map and silently strand the sender.
                        sourcetodestination: Some(role == Role::Source),
                        socketid: Some(socket_id),
                        buffer: None,
                        error: None,
                        closed: None,
                        half_close: None,
                        window: Some(PortForwardWindow {
                            bytes: Some(credit),
                            packets: Some(i32::try_from(packet_credit).unwrap_or(i32::MAX)),
                        }),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn next_poll_timeout(&self) -> Option<Duration> {
        let now = Instant::now();
        let credit = [Role::Source, Role::Destination]
            .into_iter()
            .flat_map(|role| self.map_ref(role).values())
            .filter_map(SocketIo::credit_deadline)
            .min();
        let deadline = match (self.next_park_deadline(), credit) {
            (Some(park), Some(credit)) => Some(park.min(credit)),
            (Some(park), None) => Some(park),
            (None, Some(credit)) => Some(credit),
            (None, None) => None,
        };
        deadline.map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Poll the command wake pipe (when given) and every socket once.
    /// Returns whether the wake pipe fired plus the ready socket events,
    /// copied out so the maps can be mutated while servicing them.
    fn poll_cycle(
        &mut self,
        wake: Option<&UnixStream>,
        timeout: Option<Duration>,
    ) -> Result<(bool, Vec<ReadySocket>), ForwardError> {
        let mut index: Vec<(Role, i32)> = Vec::new();
        let mut descriptors: Vec<PollFd> = Vec::new();
        if let Some(wake) = wake {
            descriptors.push(PollFd::new(wake, PollFlags::IN));
        }
        for role in [Role::Source, Role::Destination] {
            for (socket_id, socket) in self.map_ref(role).iter() {
                let mut flags = PollFlags::empty();
                if socket.read_interest() {
                    flags |= PollFlags::IN;
                }
                if socket.write_interest() {
                    flags |= PollFlags::OUT;
                }
                // HUP/ERR are reported even with no requested events, so a
                // window-parked socket still surfaces a dead peer.
                index.push((role, *socket_id));
                descriptors.push(PollFd::new(&socket.stream, flags));
            }
        }
        let timespec = timeout.map(|timeout| rustix::event::Timespec {
            tv_sec: timeout.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        });
        loop {
            match poll(&mut descriptors, timespec.as_ref()) {
                Ok(_) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    return Err(ForwardError::Io(io::Error::from_raw_os_error(
                        error.raw_os_error(),
                    )));
                }
            }
        }
        let wake_ready = wake
            .map(|_| {
                descriptors[0]
                    .revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            })
            .unwrap_or(false);
        let offset = usize::from(wake.is_some());
        let ready = index
            .into_iter()
            .zip(descriptors[offset..].iter())
            .filter_map(|((role, socket_id), descriptor)| {
                let revents = descriptor.revents();
                if revents.is_empty() {
                    return None;
                }
                Some(ReadySocket {
                    role,
                    socket_id,
                    readable: revents.intersects(PollFlags::IN | PollFlags::HUP),
                    writable: revents.contains(PollFlags::OUT),
                    error: revents.intersects(PollFlags::ERR | PollFlags::NVAL),
                })
            })
            .collect();
        Ok((wake_ready, ready))
    }

    /// Service one ready socket: flush queued writes, then read and emit.
    fn service_socket(
        &mut self,
        socket: &mut SocketIo,
        event: &ReadySocket,
    ) -> Result<SocketVerdict, ForwardError> {
        if event.writable || (event.error && socket.write_interest()) {
            if let Err(error) = socket.flush_out() {
                self.send_data(
                    socket.role,
                    socket.socket_id,
                    Vec::new(),
                    true,
                    Some(error.to_string()),
                )?;
                return Ok(SocketVerdict::Drop);
            }
        }
        if socket.out.is_empty() {
            if socket.close_when_drained {
                return Ok(SocketVerdict::Drop);
            }
            if socket.shutdown_write_when_drained && !socket.write_closed {
                socket.shutdown_write_when_drained = false;
                socket.write_closed = true;
                shutdown_write(&socket.stream);
            }
        }
        if event.error && !event.readable {
            self.send_data(
                socket.role,
                socket.socket_id,
                Vec::new(),
                true,
                Some("forwarded socket error".to_owned()),
            )?;
            return Ok(SocketVerdict::Drop);
        }
        if event.readable {
            let mut reads = 0;
            while socket.read_interest() && reads < READS_PER_CYCLE {
                let outcome = {
                    let scratch = &mut self.read_scratch[..];
                    socket.read_chunk(scratch)
                };
                match outcome {
                    Ok(ReadOutcome::Data(data)) => {
                        socket.note_sent(data.len());
                        self.send_data(socket.role, socket.socket_id, data, false, None)?;
                        reads += 1;
                    }
                    Ok(ReadOutcome::Idle) => break,
                    Ok(ReadOutcome::Eof) => return Ok(SocketVerdict::Eof),
                    Err(error) => {
                        self.send_data(
                            socket.role,
                            socket.socket_id,
                            Vec::new(),
                            true,
                            Some(error.to_string()),
                        )?;
                        return Ok(SocketVerdict::Drop);
                    }
                }
            }
        }
        if socket.close_when_drained && socket.out.is_empty() {
            return Ok(SocketVerdict::Drop);
        }
        Ok(SocketVerdict::Keep)
    }

    /// Service one readiness event, taking the socket out of its map so the
    /// emit paths can borrow `self` freely.
    fn service_event(&mut self, event: &ReadySocket) -> Result<(), ForwardError> {
        let Some(mut socket) = self.map_mut(event.role).remove(&event.socket_id) else {
            return Ok(());
        };
        match self.service_socket(&mut socket, event)? {
            SocketVerdict::Keep => {
                self.map_mut(event.role).insert(event.socket_id, socket);
            }
            SocketVerdict::Drop => {
                self.map_mut(event.role).insert(event.socket_id, socket);
                self.remove(event.role, event.socket_id);
            }
            SocketVerdict::Eof => {
                self.map_mut(event.role).insert(event.socket_id, socket);
                self.read_closed(event.role, event.socket_id)?;
            }
        }
        Ok(())
    }

    /// Drive one poll cycle over every socket without touching the command
    /// queue. Tests use this to pump socket I/O after calling worker methods
    /// directly; returns true when at least one socket reported readiness.
    #[cfg(test)]
    pub(crate) fn poll_once(&mut self, timeout: Duration) -> Result<bool, ForwardError> {
        self.flush_held();
        self.flush_due_credits()?;
        let (_, ready) = self.poll_cycle(None, Some(timeout))?;
        let serviced = !ready.is_empty();
        for event in &ready {
            self.service_event(event)?;
        }
        Ok(serviced)
    }

    /// Hand spilled outbound packets back to the session. Stops at the first
    /// one that still does not fit, keeping emission order.
    fn flush_outbound_spill(&mut self) -> Result<(), ForwardError> {
        while let Some(packet) = self.outbound_spill.pop_front() {
            match self.outbound.try_send(packet) {
                Ok(()) => {}
                Err(crossbeam_channel::TrySendError::Full(packet)) => {
                    self.outbound_spill.push_front(packet);
                    break;
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    return Err(ForwardError::Unavailable);
                }
            }
        }
        if !self.outbound_spill.is_empty()
            && !self
                .wake_signalled
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = (&*self.outbound_wake).write(&[1]);
        }
        Ok(())
    }

    /// Flush writes queued by a command batch immediately, without waiting
    /// for a second `poll(2)` cycle to report `POLLOUT`.
    fn flush_queued_writes(&mut self) -> Result<(), ForwardError> {
        loop {
            self.flush_held();
            let pending: Vec<(Role, i32)> = self
                .sources
                .values()
                .chain(self.destinations.values())
                .filter(|socket| !socket.out.is_empty())
                .map(|socket| (socket.role, socket.socket_id))
                .collect();
            if pending.is_empty() {
                break;
            }
            let mut progressed = false;
            for (role, socket_id) in pending {
                let Some(mut socket) = self.map_mut(role).remove(&socket_id) else {
                    continue;
                };
                let before = (socket.out.len(), socket.out_offset);
                let write_err = socket.flush_out().err();
                let after = (socket.out.len(), socket.out_offset);
                if after != before {
                    progressed = true;
                }
                if let Some(error) = write_err {
                    self.map_mut(role).insert(socket_id, socket);
                    self.send_data(role, socket_id, Vec::new(), true, Some(error.to_string()))?;
                    self.remove(role, socket_id);
                    continue;
                }
                if socket.out.is_empty() {
                    if socket.close_when_drained {
                        self.map_mut(role).insert(socket_id, socket);
                        self.remove(role, socket_id);
                        continue;
                    }
                    if socket.shutdown_write_when_drained && !socket.write_closed {
                        socket.shutdown_write_when_drained = false;
                        socket.write_closed = true;
                        shutdown_write(&socket.stream);
                    }
                }
                self.map_mut(role).insert(socket_id, socket);
            }
            if !progressed || self.held.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Unix worker loop: one poll over the command wake pipe and all
    /// sockets. Commands and socket I/O are handled inline, so a saturated
    /// worker never sleeps mid-batch.
    pub(crate) fn run_poll(
        &mut self,
        commands: &super::CommandReceiver,
    ) -> Result<(), ForwardError> {
        loop {
            if cancellation_requested(&self.cancel) {
                return Ok(());
            }
            self.defer_outbound_wake = true;
            self.flush_outbound_spill()?;
            self.expire_parked();
            self.flush_held();
            self.flush_due_credits()?;
            self.defer_outbound_wake = false;
            self.flush_outbound_wake();
            let (wake_ready, ready) =
                self.poll_cycle(Some(commands.wake_reader()), self.next_poll_timeout())?;
            self.defer_outbound_wake = true;
            if wake_ready || commands.has_pending() {
                commands.drain_wake();
                loop {
                    match commands.pop() {
                        CommandPop::Command(command) => {
                            let step = self.handle_command(command);
                            commands.complete_one();
                            step?;
                        }
                        CommandPop::Empty => {
                            // One wake covered the whole batch. Clear the
                            // flag only now, so pushes that arrived mid-drain
                            // did not each write a wake byte; any push that
                            // lands after this point writes exactly one.
                            commands.arm_wake();
                            break;
                        }
                        CommandPop::Disconnected => return Ok(()),
                    }
                }
                self.flush_queued_writes()?;
                self.flush_due_credits()?;
            }
            for event in &ready {
                self.service_event(event)?;
            }
            self.flush_due_credits()?;
            self.defer_outbound_wake = false;
            self.flush_outbound_wake();
        }
    }

    /// Graceful or hard stop for every remaining socket. Graceful mirrors
    /// `stop_io`: the read side is discarded, queued writes flush fully, then
    /// the socket closes. Hard mirrors `abort_io`: close immediately and
    /// report abandoned bytes.
    pub(crate) fn stop_sockets(&mut self, hard: bool) {
        if hard {
            if !self.held.is_empty() {
                self.abandoned
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            self.held.clear();
            for (_, socket) in self.sources.drain().chain(self.destinations.drain()) {
                if !socket.out.is_empty() {
                    self.abandoned
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                socket.stream.shutdown();
            }
            return;
        }
        for socket in self
            .sources
            .values_mut()
            .chain(self.destinations.values_mut())
        {
            socket.stream.shutdown_read();
        }
        // Drain held data into queues, then flush every queue to completion.
        // Held data for a closing socket is dropped (as the threaded model
        // dropped commands admitted after a close), everything else delivers.
        loop {
            self.flush_held();
            let mut pending = false;
            for socket in self
                .sources
                .values_mut()
                .chain(self.destinations.values_mut())
            {
                if socket.out.is_empty() {
                    continue;
                }
                match socket.flush_out() {
                    Ok(()) => {}
                    Err(_) => {
                        // The app is gone; the threaded model counted
                        // undelivered queue bytes as abandoned too.
                        self.abandoned
                            .store(true, std::sync::atomic::Ordering::Release);
                        socket.out.clear();
                        continue;
                    }
                }
                pending |= !socket.out.is_empty();
            }
            // Held packets move in only once a queue has room again, so the
            // loop continues while either queues or held data remain.
            if !pending && self.held.is_empty() {
                break;
            }
            // Wait for writability instead of spinning.
            let mut descriptors: Vec<PollFd> = self
                .sources
                .values()
                .chain(self.destinations.values())
                .filter(|socket| !socket.out.is_empty())
                .map(|socket| PollFd::new(&socket.stream, PollFlags::OUT))
                .collect();
            if descriptors.is_empty() {
                if self.held.is_empty() {
                    break;
                }
                // Queues are empty but held data remains: the next flush_held
                // moves it in without needing a writability wait.
                continue;
            }
            loop {
                match poll(&mut descriptors, None) {
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => return,
                }
            }
        }
        self.sources.clear();
        self.destinations.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::{FlowWindow, ReadOutcome, SocketIo};
    use crate::forward_endpoint::ForwardStream;
    use crate::forward_worker::Role;

    const EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

    fn socket_pair(
        window: Option<FlowWindow>,
    ) -> (
        SocketIo,
        UnixStream,
        Box<[u8; crate::forward_io::READ_CHUNK]>,
    ) {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
        (
            SocketIo::new(Role::Source, 1, ForwardStream::Unix(stream), window, None).unwrap(),
            peer,
            Box::new([0u8; crate::forward_io::READ_CHUNK]),
        )
    }

    #[test]
    fn reads_park_at_byte_window_and_resume_after_delivery() {
        let window = FlowWindow {
            bytes: 2,
            packets: 8,
        };
        let (mut socket, mut peer, mut scratch) = socket_pair(Some(window));
        peer.write_all(&[1, 2, 3, 4]).unwrap();

        // The window caps each read at the remaining allowance.
        let first = match socket.read_chunk(&mut scratch[..]).unwrap() {
            ReadOutcome::Data(data) => data,
            _ => panic!("first read did not produce data"),
        };
        assert_eq!(first, [1, 2]);
        socket.note_sent(first.len());
        assert!(!socket.read_interest(), "window full but still readable");

        // A partial confirmation reopens exactly its delivered amount.
        socket.apply_delivery(FlowWindow {
            bytes: 1,
            packets: 1,
        });
        assert!(socket.read_interest());
        let second = match socket.read_chunk(&mut scratch[..]).unwrap() {
            ReadOutcome::Data(data) => data,
            _ => panic!("second read did not produce data"),
        };
        assert_eq!(second, [3]);
        socket.note_sent(second.len());
        assert!(!socket.read_interest());
    }

    #[test]
    fn reads_park_at_packet_window_even_with_byte_allowance() {
        let window = FlowWindow {
            bytes: i64::MAX,
            packets: 1,
        };
        let (mut socket, mut peer, mut scratch) = socket_pair(Some(window));
        peer.write_all(&[9, 9]).unwrap();
        let data = match socket.read_chunk(&mut scratch[..]).unwrap() {
            ReadOutcome::Data(data) => data,
            _ => panic!("read did not produce data"),
        };
        socket.note_sent(data.len());
        assert!(
            !socket.read_interest(),
            "packet allowance spent but still readable"
        );
        socket.apply_delivery(FlowWindow {
            bytes: 1,
            packets: 1,
        });
        assert!(socket.read_interest());
    }

    #[test]
    fn hostile_credit_saturates_in_flight_at_zero_without_granting_capacity() {
        let window = FlowWindow {
            bytes: 4,
            packets: 4,
        };
        let (mut socket, mut peer, mut scratch) = socket_pair(Some(window));
        peer.write_all(&[1, 2]).unwrap();
        let data = match socket.read_chunk(&mut scratch[..]).unwrap() {
            ReadOutcome::Data(data) => data,
            _ => panic!("read did not produce data"),
        };
        socket.note_sent(data.len());

        // Impossible credit cannot underflow the counters or create room the
        // peer never had.
        socket.apply_delivery(FlowWindow {
            bytes: i64::MAX,
            packets: i64::MAX,
        });
        assert_eq!(socket.in_flight_bytes, 0);
        assert_eq!(socket.in_flight_packets, 0);
        socket.apply_delivery(FlowWindow {
            bytes: i64::MAX,
            packets: i64::MAX,
        });
        assert_eq!(socket.in_flight_bytes, 0);
        assert_eq!(socket.in_flight_packets, 0);

        // New traffic charges the window from scratch.
        peer.write_all(&[3, 4]).unwrap();
        let data = match socket.read_chunk(&mut scratch[..]).unwrap() {
            ReadOutcome::Data(data) => data,
            _ => panic!("read after hostile credit did not produce data"),
        };
        assert_eq!(data, [3, 4]);
        socket.note_sent(data.len());
        assert_eq!(socket.in_flight_bytes, 2);
        assert_eq!(socket.in_flight_packets, 1);
    }

    #[test]
    fn delivered_buffers_batch_credit_and_idle_queues_flush_it() {
        let window = FlowWindow {
            bytes: 512 * 1024,
            packets: 32,
        };
        let (mut socket, mut peer, _scratch) = socket_pair(Some(window));
        peer.set_read_timeout(Some(EVENT_TIMEOUT)).unwrap();
        socket.queue_write(vec![7; 100]).unwrap();
        socket.queue_write(vec![8; 100]).unwrap();

        // Delivering both buffers accumulates credit but stays below the
        // return threshold until the queue goes idle.
        socket.flush_out().unwrap();
        assert_eq!(peer.read(&mut [0u8; 200]).unwrap(), 200);
        assert_eq!(socket.credit_bytes, 200);
        assert_eq!(socket.credit_packets, 2);
        assert!(
            !socket.credit_due(std::time::Instant::now()),
            "sub-threshold credit flushed before the idle delay"
        );

        // Once the queue sits idle past the flush delay the credit is due.
        socket.credit_flush_at = Some(
            std::time::Instant::now()
                - super::IDLE_CREDIT_FLUSH
                - std::time::Duration::from_millis(1),
        );
        assert!(socket.credit_due(std::time::Instant::now()));
        assert_eq!(socket.take_credit(), Some((200, 2)));
        assert_eq!(socket.take_credit(), None);
    }

    #[test]
    fn threshold_credit_is_due_immediately() {
        let window = FlowWindow {
            bytes: 512 * 1024,
            packets: 32,
        };
        let (mut socket, mut peer, _scratch) = socket_pair(Some(window));
        for _ in 0..super::PACKET_CREDIT_RETURN_THRESHOLD {
            socket.queue_write(vec![0; 10]).unwrap();
        }
        socket.flush_out().unwrap();
        let mut buf = [0u8; 80];
        peer.read_exact(&mut buf).unwrap();
        assert!(socket.credit_due(std::time::Instant::now()));
    }
}
