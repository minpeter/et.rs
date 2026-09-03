#[cfg(unix)]
use std::io::Write;
use std::io::{self};

use crossbeam_channel as channel;
use et_core::packet::Packet;
use et_core::proto::{
    PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
    PortForwardWindow, SocketEndpoint, TerminalPacketType,
};
use prost::Message;

use crate::forward_endpoint::Endpoint;

use super::{
    close_write, spawn_connector, spawn_io, ActiveIo, ForwardError, ForwardStream, Role, Worker,
    WriteCommand, MAX_ACTIVE_SOCKETS, MAX_DATA_PACKET,
};

/// Per-socket receive window.
///
/// INVARIANT: this must not exceed what a socket can absorb WITHOUT blocking
/// the worker thread. `spawn_io` gives each socket a `bounded(64)` writer
/// channel of chunks up to `READ_CHUNK` (16 KiB), so ~1 MiB is absorbable.
/// Advertising more lets the peer overfill that channel, at which point
/// `receive_data`'s blocking send stalls the WORKER, the inbound queue fills
/// behind it, and the pump stops reading the transport again - the exact
/// deadlock this change exists to remove. Half the absorbable capacity leaves
/// room for the in-flight chunk and the packet being decoded.
pub(super) const WINDOW_BYTES: i64 = 512 * 1024;

/// Return credit once this much has drained, so a full window costs a bounded
/// number of control packets instead of one per data packet.
const CREDIT_RETURN_THRESHOLD: i64 = WINDOW_BYTES / 4;

pub(super) fn advertised_window() -> PortForwardWindow {
    PortForwardWindow {
        bytes: Some(WINDOW_BYTES),
        packets: None,
    }
}

/// Grant credit to a socket's sender and wake its parked reader.
///
/// Enabling enforcement here (rather than at socket creation) is what keeps
/// mixed-version safety: a peer that never advertises a window never enables
/// it, so that socket stays unwindowed in both directions.
/// A window field carries two independent facts: an advertised window
/// (handshake) and a confirmed-delivery byte count (steady state). Applying
/// both through one helper keeps the accounting in one place.
///
/// Enabling enforcement only when a window arrives is what preserves
/// mixed-version safety: a peer that never advertises a window leaves
/// `window` at its disabled sentinel, and that socket stays unwindowed.
fn apply_window(active: &ActiveIo, advertised: Option<i64>, delivered: i64) {
    use std::sync::atomic::Ordering;
    if let Some(window) = advertised {
        active.window.store(window, Ordering::Release);
    }
    if delivered > 0 {
        let prior = active.in_flight.fetch_sub(delivered, Ordering::AcqRel);
        let now = prior - delivered;
        let window = active.window.load(Ordering::Acquire);
        if window >= 0 && prior >= window && now < window {
            let _ = active.in_flight_wake.try_send(());
        }
    }
}

impl Worker {
    pub(super) fn accepted(
        &mut self,
        client_fd: i32,
        destination: SocketEndpoint,
        stream: ForwardStream,
    ) -> Result<(), ForwardError> {
        if self.total_sockets() >= MAX_ACTIVE_SOCKETS {
            stream.shutdown();
            return Ok(());
        }
        self.pending.insert(client_fd, stream);
        self.emit(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(destination),
                fd: Some(client_fd),
                window: Some(advertised_window()),
            },
        )
    }

    pub(super) fn connected(
        &mut self,
        client_fd: i32,
        socket_id: i32,
        result: io::Result<ForwardStream>,
        peer_advertised: Option<i64>,
    ) -> Result<(), ForwardError> {
        self.connecting.remove(&socket_id);
        let error = match result {
            Ok(stream) => {
                self.activate(Role::Destination, socket_id, stream)?;
                // Credit is symmetric: grant the peer's window to our sender
                // and remember what we advertised so returns can be sized.
                if let Some(active) = self.map(Role::Destination).get_mut(&socket_id) {
                    apply_window(active, peer_advertised, 0);
                }
                None
            }
            Err(error) => Some(error.to_string()),
        };
        self.emit(
            TerminalPacketType::PortForwardDestinationResponse as u8,
            PortForwardDestinationResponse {
                clientfd: Some(client_fd),
                socketid: error.is_none().then_some(socket_id),
                // Mixed-version safety: only answer with a window when the
                // socket was actually established AND the peer advertised one.
                // A peer that advertises nothing gets nothing back, and both
                // ends stay on unwindowed behavior.
                window: (error.is_none() && peer_advertised.is_some()).then(advertised_window),
                error,
            },
        )
    }

    pub(super) fn handle_packet(&mut self, packet: Packet) -> Result<(), ForwardError> {
        match packet.header() {
            value if value == TerminalPacketType::PortForwardDestinationRequest as u8 => {
                let request = PortForwardDestinationRequest::decode(packet.payload())
                    .map_err(|_| ForwardError::Protocol("malformed destination request"))?;
                self.request_destination(request)
            }
            value if value == TerminalPacketType::PortForwardDestinationResponse as u8 => {
                let response = PortForwardDestinationResponse::decode(packet.payload())
                    .map_err(|_| ForwardError::Protocol("malformed destination response"))?;
                self.destination_response(response)
            }
            value if value == TerminalPacketType::PortForwardData as u8 => {
                let data = PortForwardData::decode(packet.payload())
                    .map_err(|_| ForwardError::Protocol("malformed forwarding data"))?;
                self.receive_data(data)
            }
            _ => Err(ForwardError::Protocol("unsupported forwarding packet")),
        }
    }

    fn request_destination(
        &mut self,
        request: PortForwardDestinationRequest,
    ) -> Result<(), ForwardError> {
        let client_fd = request
            .fd
            .filter(|value| *value > 0)
            .ok_or(ForwardError::Protocol("destination request fd is invalid"))?;
        // Upstream (`PortForwardHandler::createDestination`) never tears the
        // session down for a bad destination: every failure is reported back
        // in a PORT_FORWARD_DESTINATION_RESPONSE with the error field set.
        // Absent window = a peer that predates windowing. Keep it as None so
        // the response withholds a window and both ends stay unwindowed.
        let peer_advertised = request.window.and_then(|window| window.bytes);
        let destination = match Endpoint::parse_destination(request.destination) {
            Ok(destination) => destination,
            Err(error) => return self.connected(client_fd, 0, Err(error), peer_advertised),
        };
        if self.total_sockets() >= MAX_ACTIVE_SOCKETS {
            return self.connected(
                client_fd,
                0,
                Err(io::Error::other("forwarding socket limit reached")),
                peer_advertised,
            );
        }
        let socket_id = self.allocate_socket_id()?;
        self.connecting.insert(socket_id);
        self.pending_windows.insert(socket_id, peer_advertised);
        self.threads.push(spawn_connector(
            client_fd,
            socket_id,
            destination,
            self.commands.clone(),
            self.cancel.clone(),
            self.session_user,
        ));
        Ok(())
    }

    fn destination_response(
        &mut self,
        response: PortForwardDestinationResponse,
    ) -> Result<(), ForwardError> {
        // A response for an fd we no longer track is logged-and-ignored
        // upstream (`closeSourceFd`), not treated as a fatal protocol error.
        let Some(stream) = response
            .clientfd
            .and_then(|client_fd| self.pending.remove(&client_fd))
        else {
            return Ok(());
        };
        if response.error.is_some() {
            stream.shutdown();
            return Ok(());
        }
        let Some(socket_id) = response.socketid.filter(|value| *value > 0) else {
            stream.shutdown();
            return Ok(());
        };
        // The response carries a window only when the peer supports windowing
        // and the socket was established, so this is the source side's
        // negotiation point.
        let peer_advertised = response.window.and_then(|window| window.bytes);
        self.activate(Role::Source, socket_id, stream)?;
        if let Some(active) = self.map(Role::Source).get_mut(&socket_id) {
            apply_window(active, peer_advertised, 0);
        }
        Ok(())
    }

    fn receive_data(&mut self, data: PortForwardData) -> Result<(), ForwardError> {
        // proto2 defaults: missing socket id is 0 and missing direction is
        // false; upstream reads them through the generated accessors without
        // presence checks.
        let socket_id = data.socketid.unwrap_or(0);
        let source_to_destination = data.sourcetodestination.unwrap_or(false);
        let buffer = data.buffer.unwrap_or_default();
        let role = if source_to_destination {
            Role::Destination
        } else {
            Role::Source
        };
        if data.error.is_some() {
            self.remove(role, socket_id);
            return Ok(());
        }
        // Credit returned by the peer frees our sender for THIS socket only.
        // A pure credit packet carries no buffer and must not be mistaken for
        // an empty-data close.
        if let Some(delivered) = data.window.and_then(|window| window.bytes) {
            if let Some(active) = self.map(role).get_mut(&socket_id) {
                apply_window(active, None, delivered);
            }
            if buffer.is_empty() && !data.closed.unwrap_or(false) {
                return Ok(());
            }
        }
        if data.closed.unwrap_or(false) {
            let Some(active) = self.map(role).get_mut(&socket_id) else {
                return Ok(());
            };
            if !close_write(active) {
                return Err(ForwardError::Unavailable);
            }
            let fully_closed = active.read_closed;
            if fully_closed {
                self.remove(role, socket_id);
            }
            return Ok(());
        }
        if buffer.is_empty() {
            return Ok(());
        }
        if buffer.len() > MAX_DATA_PACKET {
            // Defensive bound: drop the offending socket, never the session.
            self.remove(role, socket_id);
            return Ok(());
        }
        // Data for an already-closed socket id is a normal race; upstream
        // logs a warning and drops it.
        let Some(active) = self.map_ref(role).get(&socket_id) else {
            return Ok(());
        };
        let byte_count = buffer.len();
        active
            .pending_bytes
            .fetch_add(byte_count, std::sync::atomic::Ordering::AcqRel);
        let send_started = std::time::Instant::now();
        let admitted = channel::select! {
            send(active.writer, WriteCommand::Data(buffer)) -> result => result.is_ok(),
            recv(self.cancel) -> _ => false,
        };
        if std::env::var_os("ET_CREDIT_DEBUG").is_some() {
            let waited = send_started.elapsed().as_millis();
            if waited > 100 {
                eprintln!("WORKER-SEND-BLOCKED role={role:?} sid={socket_id} waited_ms={waited}");
            }
        }
        if !admitted {
            active
                .pending_bytes
                .fetch_sub(byte_count, std::sync::atomic::Ordering::AcqRel);
            return Err(ForwardError::Unavailable);
        }
        Ok(())
    }

    /// Give the peer back credit for bytes our local socket has drained.
    ///
    /// This is what replaces "stop reading the transport": the peer's sender
    /// is throttled per socket, so a congested forwarded socket never stalls
    /// the shared transport that also carries keepalives.
    pub(super) fn return_credit(
        &mut self,
        role: Role,
        socket_id: i32,
        received: usize,
    ) -> Result<(), ForwardError> {
        let Some(active) = self.map(role).get_mut(&socket_id) else {
            return Ok(());
        };
        // Only confirm delivery to a windowed peer: an unwindowed peer
        // tracks no in-flight count, so telling it would be meaningless.
        if active.window.load(std::sync::atomic::Ordering::Acquire) < 0 {
            return Ok(());
        }
        let drained = i64::try_from(received).unwrap_or(i64::MAX);
        active.credit_to_return = active.credit_to_return.saturating_add(drained);
        // Batch returns so a full window costs a bounded number of control
        // packets, but ALSO flush whenever the socket has gone idle. Without
        // the idle flush a sub-threshold remainder is stranded, the peer's
        // window shrinks by that much for the rest of the connection, and a
        // steady stream eventually parks its sender permanently.
        let idle = active
            .pending_bytes
            .load(std::sync::atomic::Ordering::Acquire)
            == 0;
        if active.credit_to_return < CREDIT_RETURN_THRESHOLD && !idle {
            return Ok(());
        }
        let credit = std::mem::take(&mut active.credit_to_return);
        if credit == 0 {
            return Ok(());
        }
        self.emit_priority(
            TerminalPacketType::PortForwardData as u8,
            PortForwardData {
                // Credit travels toward the peer that SENDS on this socket,
                // which is the same direction flag data uses for this role.
                // Inverting it would land the credit in the peer's other map
                // and silently strand the sender.
                sourcetodestination: Some(role == Role::Source),
                socketid: Some(socket_id),
                buffer: None,
                error: None,
                closed: None,
                window: Some(PortForwardWindow {
                    bytes: Some(credit),
                    packets: None,
                }),
            },
        )
    }

    pub(super) fn read_closed(&mut self, role: Role, socket_id: i32) -> Result<(), ForwardError> {
        let fully_closed = self.map(role).get_mut(&socket_id).is_some_and(|active| {
            active.read_closed = true;
            active.write_closed
        });
        self.send_data(role, socket_id, Vec::new(), true, None)?;
        if fully_closed {
            self.remove(role, socket_id);
        }
        Ok(())
    }

    pub(super) fn send_data(
        &mut self,
        role: Role,
        socket_id: i32,
        buffer: Vec<u8>,
        closed: bool,
        error: Option<String>,
    ) -> Result<(), ForwardError> {
        // proto2 fields carry explicit presence, and upstream branches on
        // `has_closed()` / `has_error()`: exactly one of buffer, closed, or
        // error may be set. Emitting `closed = false` would make upstream
        // tear the socket down on every data packet.
        let (buffer, closed) = if error.is_some() {
            (None, None)
        } else if closed {
            (None, Some(true))
        } else {
            (Some(buffer).filter(|bytes| !bytes.is_empty()), None)
        };
        self.emit(
            TerminalPacketType::PortForwardData as u8,
            PortForwardData {
                sourcetodestination: Some(role == Role::Source),
                socketid: Some(socket_id),
                buffer,
                error,
                closed,
                window: None,
            },
        )
    }

    fn activate(
        &mut self,
        role: Role,
        socket_id: i32,
        stream: ForwardStream,
    ) -> Result<(), ForwardError> {
        let (active, handles) = spawn_io(
            role,
            socket_id,
            stream,
            self.commands.clone(),
            self.cancel.clone(),
            self.abandoned.clone(),
        )
        .map_err(ForwardError::Io)?;
        self.map(role).insert(socket_id, active);
        self.threads.extend(handles);
        Ok(())
    }

    pub(super) fn remove(&mut self, role: Role, socket_id: i32) {
        if let Some(active) = self.map(role).remove(&socket_id) {
            super::stop_io(active);
        }
    }

    fn map(&mut self, role: Role) -> &mut std::collections::HashMap<i32, ActiveIo> {
        match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        }
    }

    fn map_ref(&self, role: Role) -> &std::collections::HashMap<i32, ActiveIo> {
        match role {
            Role::Source => &self.sources,
            Role::Destination => &self.destinations,
        }
    }

    pub(super) fn total_sockets(&self) -> usize {
        self.pending.len() + self.connecting.len() + self.sources.len() + self.destinations.len()
    }

    fn allocate_socket_id(&mut self) -> Result<i32, ForwardError> {
        let socket_id = self.next_socket_id;
        self.next_socket_id = self
            .next_socket_id
            .checked_add(1)
            .ok_or(ForwardError::Protocol("forwarding socket id exhausted"))?;
        Ok(socket_id)
    }

    /// Emit on the priority lane, which the consumer drains before ordinary
    /// outbound packets. Only valid for control messages whose delivery must
    /// not wait behind the data flow they regulate.
    fn emit_priority<M: Message>(&mut self, header: u8, message: M) -> Result<(), ForwardError> {
        let packet = Ok(Packet::new(header, message.encode_to_vec()));
        channel::select! {
            send(self.priority, packet) -> result => {
                result.map_err(|_| ForwardError::Unavailable)?;
            }
            recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
        }
        #[cfg(unix)]
        let _ = self.outbound_wake.write(&[1]);
        Ok(())
    }

    fn emit<M: Message>(&mut self, header: u8, message: M) -> Result<(), ForwardError> {
        let packet = Ok(Packet::new(header, message.encode_to_vec()));
        channel::select! {
            send(self.outbound, packet) -> result => {
                result.map_err(|_| ForwardError::Unavailable)?;
            }
            recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
        }
        // Unix consumers poll the wake socket; Windows consumers drain
        // `try_outbound` on the client loop's 10ms cadence.
        #[cfg(unix)]
        let _ = self.outbound_wake.write(&[1]);
        Ok(())
    }
}
