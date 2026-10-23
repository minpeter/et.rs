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
//!
//! Listeners are polled from the same loop (upstream `ForwardSourceHandler::
//! listen` runs inside `update` too), so an accept costs no thread hop.
//! Once a session loop attaches, the worker thread hands its whole state to
//! that loop as an [`Engine`]: the session's own `poll(2)` then covers the
//! forwarding descriptors, and setup, data, and teardown run on one thread
//! exactly like upstream's single `select()` loop.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel as channel;
use et_core::packet::Packet;
use et_core::proto::{
    PortForwardData, PortForwardSourceRequest, PortForwardWindow, SocketEndpoint,
    TerminalPacketType,
};
use rustix::event::{poll, PollFd, PollFlags};

use crate::forward_endpoint::{ForwardListener, ForwardStream};
use crate::forward_io::{cancellation_requested, shutdown_write, BoundSource, FlowWindow};
use crate::ssh_agent_session_bind::AgentSessionBindReplies;

use super::state::{CREDIT_RETURN_THRESHOLD, PACKET_CREDIT_RETURN_THRESHOLD};
use super::{Command, CommandReceiver, ForwardError, PendingAccept, Role, Worker, MAX_DATA_PACKET};

/// Queued network-to-socket buffers per socket, matching the bound of the
/// writer channel the threaded model used.
pub(super) const OUT_QUEUE_PACKETS: usize = 128;
/// Idle sockets flush sub-threshold window credit after this delay. Liveness
/// never waits on it: the return thresholds are an eighth of the advertised
/// window, so a stalled sender always has threshold credit pending. It only
/// returns the remainder of a stream that paused, so it is long enough that
/// a request/response exchange does not pay an extra credit packet (and a
/// peer wake-up) every couple of milliseconds.
const IDLE_CREDIT_FLUSH: Duration = Duration::from_millis(50);
/// Reads serviced per socket per poll cycle before moving to the next socket.
/// Large enough to drain a saturated socket buffer in one cycle, so a bulk
/// transfer does not return to poll once per handful of packets.
const READS_PER_CYCLE: usize = 128;
/// Smallest piece a pending message is split into, see [`pipelined_split`].
const PIPELINE_CHUNK: usize = 16 * 1024;

/// How to read what a socket still had queued after a full first piece of
/// [`PIPELINE_CHUNK`]: as `(split_bytes, split_len)`, read the next
/// `split_bytes` in `split_len` pieces and anything after them in full
/// packets. A message of at most four full packets is read in parts of at
/// least [`PIPELINE_CHUNK`], so the peer decrypts and forwards the first part
/// while the rest is still being encrypted and sent; a 64 KiB
/// request/response round trip otherwise pays the whole message's crypto
/// serially at every hop. Larger or unknown backlogs (bulk transfers) and
/// data arriving later use full packets.
fn pipelined_split(available: Option<u64>) -> (usize, usize) {
    let full = crate::forward_io::FORWARD_READ_LEN;
    match available.and_then(|bytes| usize::try_from(bytes).ok()) {
        Some(available) if available <= 4 * full => {
            (available, available.div_ceil(4).clamp(PIPELINE_CHUNK, full))
        }
        _ => (0, full),
    }
}

#[derive(Debug)]
pub(crate) struct QueuedBuffer {
    pub(crate) data: Vec<u8>,
    pub(crate) start: usize,
    pub(crate) len: usize,
}

pub(crate) struct SocketIo {
    /// Shared so the session-driven engine can hand the descriptor to the
    /// session's `poll(2)` set without borrowing the worker.
    pub(crate) stream: Arc<ForwardStream>,
    pub(crate) role: Role,
    pub(crate) socket_id: i32,
    /// Network data queued for the local socket.
    out: VecDeque<QueuedBuffer>,
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
    /// The last read filled its whole buffer, so more may still be queued.
    last_read_full: bool,
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
        if let ForwardStream::Tcp(tcp) = &stream {
            let _ = tcp.set_nodelay(true);
            let sock = socket2::SockRef::from(tcp);
            let _ = sock.set_send_buffer_size(2 * 1024 * 1024);
            let _ = sock.set_recv_buffer_size(2 * 1024 * 1024);
        }
        Ok(Self {
            role,
            socket_id,
            stream: Arc::new(stream),
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
            last_read_full: false,
        })
    }

    fn windowed(&self) -> bool {
        self.window_bytes >= 0 && self.window_packets >= 0
    }

    fn read_interest(&self) -> bool {
        if !self.read_open || self.close_when_drained {
            return false;
        }
        if !self.windowed() {
            return true;
        }
        self.in_flight_bytes < self.window_bytes && self.in_flight_packets < self.window_packets
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
        let len = buffer.len();
        self.out.push_back(QueuedBuffer {
            data: buffer,
            start: 0,
            len,
        });
        Ok(())
    }

    fn queue_write_span(&mut self, data: Vec<u8>, start: usize, len: usize) -> Result<(), Vec<u8>> {
        if len == 0 {
            return Ok(());
        }
        if len > MAX_DATA_PACKET || self.out.len() >= OUT_QUEUE_PACKETS {
            return Err(data);
        }
        self.out.push_back(QueuedBuffer { data, start, len });
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
    #[cfg(test)]
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
            match self.stream.read_shared(&mut scratch[..limit]) {
                Ok(0) => return Ok(ReadOutcome::Eof),
                Ok(count) => {
                    if let Some(replies) = self.bind_replies.as_mut() {
                        let forwarded = replies.consume(&scratch[..count]).map_err(|()| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid ssh agent reply to session binding",
                            )
                        })?;
                        if forwarded.is_empty() {
                            continue;
                        }
                        return Ok(ReadOutcome::Data(forwarded));
                    }
                    return Ok(ReadOutcome::Data(scratch[..count].to_vec()));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(ReadOutcome::Idle);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Read one chunk and encode it directly into a `PortForwardData` payload
    /// without an intermediate `Vec<u8>` copy.
    fn read_encoded_chunk(&mut self, scratch: &mut [u8]) -> io::Result<ReadOutcome> {
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
            match self.stream.read_shared(&mut scratch[..limit]) {
                Ok(0) => return Ok(ReadOutcome::Eof),
                Ok(count) => {
                    self.last_read_full = count == scratch.len();
                    if let Some(replies) = self.bind_replies.as_mut() {
                        let forwarded = replies.consume(&scratch[..count]).map_err(|()| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid ssh agent reply to session binding",
                            )
                        })?;
                        if forwarded.is_empty() {
                            continue;
                        }
                        self.note_sent(forwarded.len());
                        let payload = super::state::encode_data_packet(
                            self.role == Role::Source,
                            self.socket_id,
                            &forwarded,
                        );
                        return Ok(ReadOutcome::Data(payload));
                    }
                    self.note_sent(count);
                    let payload = super::state::encode_data_packet(
                        self.role == Role::Source,
                        self.socket_id,
                        &scratch[..count],
                    );
                    return Ok(ReadOutcome::Data(payload));
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
        while !self.out.is_empty() {
            let result = if self.out.len() == 1 {
                let front = self.out.front().unwrap();
                let pending = &front.data[front.start + self.out_offset..front.start + front.len];
                self.stream.write_shared(pending)
            } else {
                let mut slices = [io::IoSlice::new(&[]); 16];
                let mut count = 0;
                for (idx, buf) in self.out.iter().take(16).enumerate() {
                    let offset = if idx == 0 { self.out_offset } else { 0 };
                    slices[idx] =
                        io::IoSlice::new(&buf.data[buf.start + offset..buf.start + buf.len]);
                    count += 1;
                }
                self.stream.write_vectored_shared(&slices[..count])
            };
            match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "forwarded socket closed during write",
                    ));
                }
                Ok(mut written) => {
                    while written > 0 {
                        let front = self.out.front().unwrap();
                        let rem = front.len - self.out_offset;
                        if written >= rem {
                            written -= rem;
                            let done_len = front.len;
                            self.out.pop_front();
                            self.out_offset = 0;
                            if self.windowed() {
                                self.credit_bytes = self
                                    .credit_bytes
                                    .saturating_add(i64::try_from(done_len).unwrap_or(i64::MAX));
                                self.credit_packets = self.credit_packets.saturating_add(1);
                            }
                        } else {
                            self.out_offset += written;
                            break;
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

    pub(crate) fn admit_data_span(
        &mut self,
        role: Role,
        socket_id: i32,
        data: Vec<u8>,
        start: usize,
        len: usize,
    ) -> Result<(), ForwardError> {
        let map = match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        };
        let Some(socket) = map.get_mut(&socket_id) else {
            return Ok(());
        };
        if socket.write_closed() || len == 0 {
            return Ok(());
        }
        if len > MAX_DATA_PACKET {
            self.remove(role, socket_id);
            return Ok(());
        }
        if let Err(data) = socket.queue_write_span(data, start, len) {
            let buffer = data[start..start + len].to_vec();
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
                    let drained = socket.out.is_empty();
                    if !drained {
                        // Stay open only to flush; nothing more is read.
                        socket.stream.shutdown_read();
                    }
                    drained
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

    fn send_credit(
        &mut self,
        role: Role,
        socket_id: i32,
        credit: i64,
        packet_credit: i64,
    ) -> Result<(), ForwardError> {
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
        )
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
                self.send_credit(role, socket_id, credit, packet_credit)?;
            }
        }
        Ok(())
    }

    pub(super) fn next_poll_deadline(&self) -> Option<Instant> {
        let credit = [Role::Source, Role::Destination]
            .into_iter()
            .flat_map(|role| self.map_ref(role).values())
            .filter_map(SocketIo::credit_deadline)
            .min();
        match (self.next_park_deadline(), credit) {
            (Some(park), Some(credit)) => Some(park.min(credit)),
            (Some(park), None) => Some(park),
            (None, Some(credit)) => Some(credit),
            (None, None) => None,
        }
    }

    fn next_poll_timeout(&self) -> Option<Duration> {
        self.next_poll_deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Engine mode bounds what the session has not drained yet: past this,
    /// sockets and listeners stop being read until the session catches up
    /// and the data waits in the kernel socket buffer, the way OpenSSH stops
    /// reading channel input while its outgoing packet buffer is full. Bytes,
    /// not packets, bound it so a few bulk tunnels cannot queue tens of MiB.
    pub(super) fn outbound_backlog_full(&self) -> bool {
        self.engine
            && (self.engine_outbound_bytes >= ENGINE_OUTBOUND_BYTES
                || self.engine_outbound.len() >= ENGINE_OUTBOUND_LIMIT)
    }

    /// Poll the command wake pipe (when given), every listener, and every
    /// socket once. Returns whether the wake pipe fired, the ready socket
    /// events (copied out so the maps can be mutated while servicing them),
    /// and the connections accepted from ready listeners. The listener
    /// snapshot is released before returning, so a concurrent cancel can
    /// close the listener without waiting on whatever this worker does next.
    fn poll_cycle(
        &mut self,
        wake: Option<&UnixStream>,
        timeout: Option<Duration>,
    ) -> Result<(bool, Vec<ReadySocket>, Vec<AcceptedStream>), ForwardError> {
        let listeners = self.listeners.snapshot(true);
        let result = self.poll_snapshot(wake, timeout, &listeners);
        drop(listeners);
        self.listeners.release();
        result
    }

    fn poll_snapshot(
        &mut self,
        wake: Option<&UnixStream>,
        timeout: Option<Duration>,
        listeners: &[Arc<ListenerEntry>],
    ) -> Result<(bool, Vec<ReadySocket>, Vec<AcceptedStream>), ForwardError> {
        let mut index: Vec<(Role, i32)> = Vec::new();
        let mut descriptors: Vec<PollFd> = Vec::new();
        if let Some(wake) = wake {
            descriptors.push(PollFd::new(wake, PollFlags::IN));
        }
        for entry in listeners {
            descriptors.push(PollFd::new(&entry.listener, PollFlags::IN));
        }
        for role in [Role::Source, Role::Destination] {
            for (socket_id, socket) in self.map_ref(role).iter() {
                // HUP/ERR are reported even with no requested events, so a
                // window-parked socket still surfaces a dead peer.
                index.push((role, *socket_id));
                descriptors.push(PollFd::new(&*socket.stream, socket.poll_flags(true)));
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
        let revents: Vec<PollFlags> = descriptors.iter().map(PollFd::revents).collect();
        drop(descriptors);
        let wake_ready = wake.is_some()
            && revents[0].intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR);
        let offset = usize::from(wake.is_some());
        let socket_offset = offset + listeners.len();
        let mut accepted = Vec::new();
        for (entry, revents) in listeners.iter().zip(&revents[offset..socket_offset]) {
            if !revents.is_empty() {
                accept_streams(entry, ACCEPTS_PER_CYCLE, &mut accepted);
            }
        }
        let ready = index
            .into_iter()
            .zip(&revents[socket_offset..])
            .filter(|(_, revents)| !revents.is_empty())
            .map(|((role, socket_id), revents)| ReadySocket::new(role, socket_id, *revents))
            .collect();
        Ok((wake_ready, ready, accepted))
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
            // The first read takes one pipeline piece, so a message that fits
            // in it (the interactive case) needs no FIONREAD probe; a full
            // piece asks how much is still queued and splits that.
            let mut split: Option<(usize, usize)> = None;
            let mut reads = 0;
            while socket.read_interest() && reads < READS_PER_CYCLE && !self.outbound_backlog_full()
            {
                let read_len = match split {
                    None => PIPELINE_CHUNK,
                    Some((bytes, len)) if bytes > 0 => len,
                    Some(_) => crate::forward_io::FORWARD_READ_LEN,
                };
                let outcome = {
                    let scratch = &mut self.read_scratch[..read_len];
                    socket.read_encoded_chunk(scratch)
                };
                match outcome {
                    Ok(ReadOutcome::Data(payload)) => {
                        let is_small = payload.len() <= 4096;
                        split = Some(match split {
                            None if socket.last_read_full => {
                                pipelined_split(rustix::io::ioctl_fionread(&*socket.stream).ok())
                            }
                            None => (0, crate::forward_io::FORWARD_READ_LEN),
                            Some((bytes, len)) => (bytes.saturating_sub(payload.len()), len),
                        });
                        self.emit_raw(TerminalPacketType::PortForwardData as u8, payload)?;
                        reads += 1;
                        if is_small {
                            break;
                        }
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
        let (_, ready, _) = self.poll_cycle(None, Some(timeout))?;
        let serviced = !ready.is_empty();
        for event in &ready {
            self.service_event(event)?;
        }
        Ok(serviced)
    }

    /// Hand spilled outbound packets back to the session. Stops at the first
    /// one that still does not fit, keeping emission order.
    ///
    /// The worker loop calls this before every `poll(2)`. Packets left over
    /// are flagged in `spill_pending` so the session's next pop wakes the
    /// worker: no socket or command event may ever arrive (the local sender
    /// already finished), and the spill would otherwise strand its tail.
    pub(super) fn flush_outbound_spill(&mut self) -> Result<(), ForwardError> {
        if self.engine {
            return Ok(());
        }
        self.send_spilled()?;
        if !self.outbound_spill.is_empty() {
            // Publish, then retry: a pop after the store sees the flag and
            // wakes us; a pop before it freed a slot this retry fills.
            self.spill_pending.store(true, Ordering::SeqCst);
            self.send_spilled()?;
        }
        if self.outbound_spill.is_empty() {
            self.spill_pending.store(false, Ordering::SeqCst);
        } else if !self
            .wake_signalled
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = (&*self.outbound_wake).write(&[1]);
        }
        Ok(())
    }

    fn send_spilled(&mut self) -> Result<(), ForwardError> {
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
        Ok(())
    }

    /// Flush writes queued by a command batch immediately, without waiting
    /// for a second `poll(2)` cycle to report `POLLOUT`.
    pub(super) fn flush_queued_writes(&mut self) -> Result<(), ForwardError> {
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
                let credit_to_flush = if socket.out.is_empty() && socket.credit_due(Instant::now())
                {
                    socket.take_credit()
                } else {
                    None
                };
                if socket.out.is_empty() {
                    if socket.close_when_drained {
                        self.map_mut(role).insert(socket_id, socket);
                        if let Some((credit, packet_credit)) = credit_to_flush {
                            self.send_credit(role, socket_id, credit, packet_credit)?;
                        }
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
                if let Some((credit, packet_credit)) = credit_to_flush {
                    self.send_credit(role, socket_id, credit, packet_credit)?;
                }
            }
            if !progressed || self.held.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Unix worker loop: one poll over the command wake pipe, every
    /// listener, and every socket. Commands and socket I/O are handled
    /// inline, so a saturated worker never sleeps mid-batch. Returns true
    /// when the session loop took the worker over.
    pub(crate) fn run_poll(&mut self, commands: &CommandReceiver) -> Result<bool, ForwardError> {
        let mut batch = Vec::with_capacity(128);
        loop {
            if cancellation_requested(&self.cancel) {
                return Ok(false);
            }
            if self.handover_requested() {
                return Ok(true);
            }
            self.defer_outbound_wake = true;
            self.flush_outbound_spill()?;
            self.expire_parked();
            self.flush_held();
            self.flush_due_credits()?;
            self.defer_outbound_wake = false;
            if self.outbound_wake_needed {
                self.flush_outbound_wake();
            }
            let (wake_ready, ready, accepted) =
                self.poll_cycle(Some(commands.wake_reader()), self.next_poll_timeout())?;
            self.defer_outbound_wake = true;
            for stream in accepted {
                self.admit_accepted(stream)?;
            }
            // Socket readiness is level-triggered, so whatever this cycle saw
            // is reported again to the session's own poll after a handover.
            if self.handover_requested() {
                return Ok(true);
            }
            self.defer_outbound_wake = true;
            if wake_ready || commands.has_pending() {
                batch.clear();
                if !commands.drain_batch(&mut batch) {
                    return Ok(false);
                }
                let count = batch.len();
                for command in batch.drain(..) {
                    self.handle_command(command)?;
                }
                self.flush_queued_writes()?;
                commands.complete_count(count);
                commands.arm_wake();
                self.flush_due_credits()?;
            }
            for event in &ready {
                self.service_event(event)?;
            }
            self.flush_due_credits()?;
            self.defer_outbound_wake = false;
            if self.outbound_wake_needed {
                self.flush_outbound_wake();
            }
        }
    }

    fn handover_requested(&mut self) -> bool {
        if !self.handover_pending && self.handover_request.try_recv().is_ok() {
            self.handover_pending = true;
        }
        self.handover_pending
    }

    /// Hand one accepted connection to forwarding: SOCKS clients finish
    /// their handshake on a helper thread, plain forwards request their
    /// destination right away.
    fn admit_accepted(&mut self, accepted: AcceptedStream) -> Result<(), ForwardError> {
        let AcceptedStream {
            listener,
            destination,
            socks,
            stream,
        } = accepted;
        let client_fd = self.next_client_fd.fetch_add(1, Ordering::Relaxed);
        if client_fd <= 0 {
            // Client ids are exhausted: stop accepting, as upstream would
            // once its request ids could collide.
            stream.shutdown();
            if let Some(listener) = listener.upgrade() {
                listener.retire();
            }
            self.listeners.prune();
            return Ok(());
        }
        if let Some(pending_socks) = socks {
            crate::forward_io::spawn_socks_handshake(
                client_fd,
                stream,
                &pending_socks,
                self.commands.clone(),
                self.cancel.clone(),
            );
            return Ok(());
        }
        self.accepted(
            client_fd,
            destination,
            PendingAccept::park(stream, Vec::new(), None, false, false),
        )
    }

    /// Tear down: close listeners and parked accepts, stop every socket,
    /// and join helper threads.
    pub(super) fn finish(&mut self, hard: bool) {
        self.listeners.retire_all();
        for (_, pending) in self.pending.drain() {
            pending.stream.shutdown();
        }
        self.stop_sockets(hard);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
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

impl SocketIo {
    /// Poll interest; `reads` is false while the engine's outbound backlog
    /// is full, so a readable socket cannot spin the loop.
    fn poll_flags(&self, reads: bool) -> PollFlags {
        let mut flags = PollFlags::empty();
        if reads && self.read_interest() {
            flags |= PollFlags::IN;
        }
        if self.write_interest() {
            flags |= PollFlags::OUT;
        }
        flags
    }
}

impl ReadySocket {
    fn new(role: Role, socket_id: i32, revents: PollFlags) -> Self {
        Self {
            role,
            socket_id,
            readable: revents.intersects(PollFlags::IN | PollFlags::HUP),
            writable: revents.contains(PollFlags::OUT),
            error: revents.intersects(PollFlags::ERR | PollFlags::NVAL),
        }
    }
}

/// Packets the session has not drained yet before the engine stops reading
/// sockets and listeners; the bound the outbound channel gives the thread.
const ENGINE_OUTBOUND_LIMIT: usize = crate::forward::CHANNEL_SPILL_LIMIT;
/// Bytes of undrained data packets before the engine pauses socket reads.
/// One socket window's worth keeps a bulk transfer streaming while the
/// session encrypts, without queueing tens of MiB per session.
const ENGINE_OUTBOUND_BYTES: usize = 2 * 1024 * 1024;
/// Connections accepted from one ready listener per cycle, so a connect
/// storm cannot starve established sockets.
const ACCEPTS_PER_CYCLE: usize = 64;

/// One bound listener (TCP, Unix, or SOCKS). Shared between the forwarder
/// (runtime add/cancel) and whichever thread polls it.
pub(crate) struct ListenerEntry {
    pub(crate) listener: ForwardListener,
    destination: SocketEndpoint,
    socks: bool,
    pub(crate) request: Option<PortForwardSourceRequest>,
    retired: AtomicBool,
    pending_socks: Arc<AtomicUsize>,
}

impl ListenerEntry {
    pub(crate) fn new(source: BoundSource) -> Option<Arc<Self>> {
        let BoundSource {
            listener,
            destination,
            socks,
            stdio: _,
            request,
        } = source;
        Some(Arc::new(Self {
            listener: listener?,
            destination,
            socks,
            request,
            retired: AtomicBool::new(false),
            pending_socks: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Stop accepting. The descriptor closes once the last poll snapshot
    /// holding it is dropped.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    pub(crate) fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// A runtime `-L` listener for exactly `request` (what mux add/cancel
    /// address); SOCKS and named-pipe listeners are not cancellable.
    pub(crate) fn is_local_forward(&self, request: &PortForwardSourceRequest) -> bool {
        !self.socks && self.request.as_ref() == Some(request)
    }

    pub(crate) fn is_local_forward_any(&self) -> bool {
        !self.socks && self.request.is_some()
    }
}

/// A connection taken off a ready listener, admitted once the listener
/// snapshot is released. Holds the listener only weakly so a cancel can
/// close it in the meantime.
pub(crate) struct AcceptedStream {
    listener: std::sync::Weak<ListenerEntry>,
    destination: SocketEndpoint,
    socks: Option<Arc<AtomicUsize>>,
    stream: ForwardStream,
}

/// Accept up to `limit` queued connections from `entry`. Accepting never
/// blocks (listeners are non-blocking). A connection that failed before it
/// was accepted is skipped, like upstream's `accept` loop; any other failure
/// retires the listener, as its own thread used to end.
fn accept_streams(entry: &Arc<ListenerEntry>, limit: usize, out: &mut Vec<AcceptedStream>) {
    for _ in 0..limit {
        if entry.retired() {
            return;
        }
        match entry.listener.accept() {
            Ok(stream) => out.push(AcceptedStream {
                listener: Arc::downgrade(entry),
                destination: entry.destination.clone(),
                socks: entry.socks.then(|| entry.pending_socks.clone()),
                stream,
            }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if connection_failed_before_accept(&error) => {}
            Err(_) => {
                entry.retire();
                return;
            }
        }
    }
}

/// accept(2) reports a pending connection's own network error (the peer
/// reset first, or its route vanished); the listener itself is fine.
fn connection_failed_before_accept(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    ) {
        return true;
    }
    let Some(code) = error
        .raw_os_error()
        .map(rustix::io::Errno::from_raw_os_error)
    else {
        return false;
    };
    [
        rustix::io::Errno::PROTO,
        rustix::io::Errno::NOPROTOOPT,
        rustix::io::Errno::HOSTDOWN,
        rustix::io::Errno::OPNOTSUPP,
    ]
    .contains(&code)
}

/// Every listener a forwarder accepts on, shared by the forwarder (runtime
/// add/cancel) and whichever thread polls them.
#[derive(Clone, Default)]
pub(crate) struct ListenerRegistry(Arc<RegistryShared>);

#[derive(Default)]
struct RegistryShared {
    state: Mutex<RegistryState>,
    released: std::sync::Condvar,
}

#[derive(Default)]
struct RegistryState {
    entries: Vec<Arc<ListenerEntry>>,
    /// A worker thread is inside `poll(2)` holding snapshot `epoch`.
    polling: bool,
    epoch: u64,
}

impl ListenerRegistry {
    pub(crate) fn push(&self, entries: impl IntoIterator<Item = Arc<ListenerEntry>>) {
        self.0.state.lock().unwrap().entries.extend(entries);
    }

    /// Live listeners. A worker thread passes `for_poll` and must call
    /// [`ListenerRegistry::release`] once it dropped the snapshot.
    pub(crate) fn snapshot(&self, for_poll: bool) -> Vec<Arc<ListenerEntry>> {
        let mut state = self.0.state.lock().unwrap();
        state.entries.retain(|entry| !entry.retired());
        if for_poll {
            state.polling = true;
            state.epoch = state.epoch.wrapping_add(1);
        }
        state.entries.clone()
    }

    pub(crate) fn release(&self) {
        self.0.state.lock().unwrap().polling = false;
        self.0.released.notify_all();
    }

    /// Drop retired listeners.
    pub(crate) fn prune(&self) {
        self.0
            .state
            .lock()
            .unwrap()
            .entries
            .retain(|entry| !entry.retired());
    }

    /// Runtime `-L` listeners: whether `request` is already open, and how
    /// many are.
    pub(crate) fn local_forwards(&self, request: &PortForwardSourceRequest) -> (bool, usize) {
        let mut state = self.0.state.lock().unwrap();
        state.entries.retain(|entry| !entry.retired());
        let open = state
            .entries
            .iter()
            .any(|entry| entry.is_local_forward(request));
        let count = state
            .entries
            .iter()
            .filter(|entry| entry.is_local_forward_any())
            .count();
        (open, count)
    }

    /// Retire and remove the runtime `-L` listeners for `request`; returns
    /// whether any existed. A worker thread polling an older snapshot is
    /// woken (`wake` never blocks) and waited for, so the listening
    /// address is released before this returns. The wait is bounded: the
    /// snapshot is released right after `poll(2)` returns.
    pub(crate) fn cancel(&self, request: &PortForwardSourceRequest, wake: impl FnOnce()) -> bool {
        let mut state = self.0.state.lock().unwrap();
        let mut removed = Vec::new();
        state.entries.retain(|entry| {
            if entry.is_local_forward(request) {
                entry.retire();
                removed.push(entry.clone());
                return false;
            }
            true
        });
        if !removed.is_empty() && state.polling {
            let epoch = state.epoch;
            wake();
            while state.polling && state.epoch == epoch {
                state = self.0.released.wait(state).unwrap();
            }
        }
        drop(state);
        !removed.is_empty()
    }

    pub(crate) fn retire_all(&self) {
        let removed = std::mem::take(&mut self.0.state.lock().unwrap().entries);
        for entry in removed {
            entry.retire();
        }
    }
}

/// Session → worker request to take the worker over, and the reply that
/// carries it.
pub(crate) struct HandoverLink {
    pub(crate) request: channel::Receiver<()>,
    pub(crate) reply: channel::Sender<Box<Engine>>,
}

/// One descriptor of the session-driven engine, owned so the session can
/// poll it without borrowing the engine.
pub(crate) enum EngineFd {
    Wake(Arc<UnixStream>),
    Listener(Arc<ListenerEntry>),
    Socket {
        role: Role,
        socket_id: i32,
        stream: Arc<ForwardStream>,
        flags: PollFlags,
    },
}

impl EngineFd {
    pub(crate) fn poll_fd(&self) -> PollFd<'_> {
        match self {
            Self::Wake(wake) => PollFd::new(&**wake, PollFlags::IN),
            Self::Listener(entry) => PollFd::new(&entry.listener, PollFlags::IN),
            Self::Socket { stream, flags, .. } => PollFd::new(&**stream, *flags),
        }
    }
}

/// The forwarding worker driven by the session thread.
///
/// Upstream runs `PortForwardHandler::update` from the terminal loop's own
/// `select()`, so accepting, destination setup, data, and close all happen
/// on one thread. The Unix worker thread hands itself over as an `Engine`
/// once a session loop polls forwarding, which removes the thread hop (two
/// context switches) every lifecycle event used to pay.
pub(crate) struct Engine {
    worker: Worker,
    commands: CommandReceiver,
    wake: Option<Arc<UnixStream>>,
    batch: Vec<Command>,
    failed: bool,
    /// First failure, reported once through `pop_outbound`.
    error: Option<ForwardError>,
}

impl Engine {
    pub(super) fn new(mut worker: Worker, commands: CommandReceiver) -> Self {
        worker.engine = true;
        worker.handover_pending = false;
        worker.handover_request = channel::never();
        worker.defer_outbound_wake = false;
        worker.outbound_wake_needed = false;
        let wake = commands.wake_reader_shared();
        Self {
            worker,
            commands,
            wake,
            batch: Vec::with_capacity(128),
            failed: false,
            error: None,
        }
    }

    /// Put packets the thread already published ahead of everything it
    /// queued while handing over, keeping emission order per lane.
    pub(crate) fn adopt_channels(
        &mut self,
        priority: &channel::Receiver<super::Outbound>,
        outbound: &channel::Receiver<super::Outbound>,
    ) {
        let worker = &mut self.worker;
        let mut lane: VecDeque<super::Outbound> = priority.try_iter().collect();
        lane.append(&mut worker.engine_priority);
        worker.engine_priority = lane;
        let mut lane: VecDeque<super::Outbound> = outbound.try_iter().collect();
        lane.append(&mut worker.outbound_spill);
        lane.append(&mut worker.engine_outbound);
        worker.engine_outbound_bytes = lane.iter().map(outbound_len).sum();
        worker.engine_outbound = lane;
    }

    /// Run `step`; a failure tears the engine down hard, as the worker
    /// thread's exit did, and every later call reports `Unavailable`.
    fn guard<T>(
        &mut self,
        step: impl FnOnce(&mut Self) -> Result<T, ForwardError>,
    ) -> Result<T, ForwardError> {
        if self.failed {
            return Err(ForwardError::Unavailable);
        }
        let result = step(self);
        if result.is_err() {
            // Packets already emitted still reach the session first, like
            // the thread's channel contents ahead of its published error.
            self.failed = true;
            self.worker.finish(true);
        }
        result
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    /// Commands from helper threads (connectors, SOCKS handshakes, stdio)
    /// and anything queued before the handover.
    fn drain_commands(&mut self, woken: bool) -> Result<(), ForwardError> {
        if woken || self.commands.has_pending() {
            let mut batch = std::mem::take(&mut self.batch);
            batch.clear();
            if !self.commands.drain_batch(&mut batch) {
                self.batch = batch;
                return Err(ForwardError::Unavailable);
            }
            let count = batch.len();
            let mut result = Ok(());
            for command in batch.drain(..) {
                if result.is_ok() {
                    result = self.worker.handle_command(command);
                }
            }
            self.batch = batch;
            self.commands.complete_count(count);
            self.commands.arm_wake();
            result?;
            if count > 0 {
                self.worker.flush_queued_writes()?;
            }
        }
        self.read_fresh_sources()
    }

    fn read_fresh_sources(&mut self) -> Result<(), ForwardError> {
        while let Some(socket_id) = self.worker.fresh_sources.pop() {
            self.worker.service_event(&ReadySocket {
                role: Role::Source,
                socket_id,
                readable: true,
                writable: false,
                error: false,
            })?;
        }
        Ok(())
    }

    /// Timers and held data, then the descriptors the session should poll.
    /// Returns when the session must come back even without readiness.
    pub(crate) fn collect(&mut self, entries: &mut Vec<EngineFd>) -> Option<Instant> {
        entries.clear();
        let prepared = self.guard(|engine| {
            engine.drain_commands(false)?;
            engine.worker.expire_parked();
            engine.worker.flush_held();
            engine.worker.flush_due_credits()
        });
        if let Err(error) = prepared {
            self.record(error);
            return Some(Instant::now());
        }
        if let Some(wake) = &self.wake {
            entries.push(EngineFd::Wake(wake.clone()));
        }
        let reads = !self.worker.outbound_backlog_full();
        if reads {
            for entry in self.worker.listeners.snapshot(false) {
                entries.push(EngineFd::Listener(entry));
            }
        }
        for role in [Role::Source, Role::Destination] {
            for (socket_id, socket) in self.worker.map_ref(role) {
                entries.push(EngineFd::Socket {
                    role,
                    socket_id: *socket_id,
                    stream: socket.stream.clone(),
                    flags: socket.poll_flags(reads),
                });
            }
        }
        if self.has_outbound() {
            return Some(Instant::now());
        }
        self.worker.next_poll_deadline()
    }

    /// Service what the session's poll reported for `entries`.
    pub(crate) fn service(
        &mut self,
        entries: &[EngineFd],
        revents: &[PollFlags],
    ) -> Result<(), ForwardError> {
        self.guard(|engine| {
            let woken = entries
                .iter()
                .zip(revents)
                .any(|(entry, revents)| matches!(entry, EngineFd::Wake(_)) && !revents.is_empty());
            engine.drain_commands(woken)?;
            for (entry, revents) in entries.iter().zip(revents) {
                if revents.is_empty() {
                    continue;
                }
                match entry {
                    EngineFd::Wake(_) => {}
                    EngineFd::Listener(listener) => {
                        let mut accepted = Vec::new();
                        if !engine.worker.outbound_backlog_full() {
                            accept_streams(listener, ACCEPTS_PER_CYCLE, &mut accepted);
                        }
                        for stream in accepted {
                            engine.worker.admit_accepted(stream)?;
                        }
                    }
                    EngineFd::Socket {
                        role,
                        socket_id,
                        stream,
                        ..
                    } => {
                        // A socket closed and replaced since the poll set
                        // was built must not receive the stale readiness.
                        let current = engine
                            .worker
                            .map_ref(*role)
                            .get(socket_id)
                            .is_some_and(|socket| Arc::ptr_eq(&socket.stream, stream));
                        if current {
                            engine
                                .worker
                                .service_event(&ReadySocket::new(*role, *socket_id, *revents))?;
                        }
                    }
                }
            }
            engine.worker.flush_due_credits()
        })
    }

    /// Handle session packets inline. Stops (leaving the rest queued) while
    /// the outbound backlog is full, which stops the session reading the
    /// transport exactly like a full command queue did.
    pub(crate) fn receive(
        &mut self,
        queue: &mut VecDeque<Packet>,
        bounded: bool,
    ) -> Result<(), ForwardError> {
        self.guard(|engine| {
            engine.drain_commands(false)?;
            let mut handled = false;
            while !(bounded && engine.worker.outbound_backlog_full()) {
                let Some(packet) = queue.pop_front() else {
                    break;
                };
                engine.worker.handle_packet(packet)?;
                handled = true;
            }
            if handled {
                engine.worker.flush_queued_writes()?;
                engine.read_fresh_sources()?;
            }
            Ok(())
        })
    }

    pub(crate) fn set_ssh_agent_session_binds(
        &mut self,
        agent_socket_path: String,
        binds: Vec<Vec<u8>>,
    ) -> Result<(), ForwardError> {
        self.guard(|engine| {
            engine.drain_commands(false)?;
            engine
                .worker
                .handle_command(Command::SetSshAgentSessionBinds {
                    agent_socket_path,
                    binds,
                })
        })
    }

    /// Whether the session should call `pop_outbound`: packets are queued
    /// or a failure waits to be reported.
    pub(crate) fn has_outbound(&self) -> bool {
        self.failed || self.queued()
    }

    fn queued(&self) -> bool {
        !self.worker.engine_priority.is_empty() || !self.worker.engine_outbound.is_empty()
    }

    /// Keep a failure from a call that cannot return it (servicing poll
    /// readiness) for the session's next `pop_outbound`.
    pub(crate) fn record(&mut self, error: ForwardError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Next packet for the session, credit (priority) lane first. After a
    /// failure, the error (then `Unavailable`) ends the session's forwarding
    /// as the worker thread's published error did.
    pub(crate) fn pop_outbound(&mut self) -> Option<super::Outbound> {
        let next = self.worker.engine_priority.pop_front().or_else(|| {
            let packet = self.worker.engine_outbound.pop_front()?;
            self.worker.engine_outbound_bytes = self
                .worker
                .engine_outbound_bytes
                .saturating_sub(outbound_len(&packet));
            Some(packet)
        });
        if next.is_none() && self.failed {
            return Some(Err(self.error.take().unwrap_or(ForwardError::Unavailable)));
        }
        next
    }

    /// Stop everything. Returns whether packets the session never drained
    /// were abandoned.
    pub(crate) fn finish(&mut self, hard: bool) -> bool {
        let abandoned = self.queued();
        self.worker.engine_priority.clear();
        self.worker.engine_outbound.clear();
        self.worker.engine_outbound_bytes = 0;
        if !self.failed {
            self.failed = true;
            self.worker.finish(hard);
        }
        abandoned || self.worker.abandoned.load(Ordering::Acquire)
    }
}

/// Payload bytes an outbound entry holds.
pub(super) fn outbound_len(packet: &super::Outbound) -> usize {
    packet.as_ref().map_or(0, |packet| packet.payload().len())
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
