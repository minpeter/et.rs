#[cfg(unix)]
use std::io::Write;
use std::io::{self};
use std::time::Instant;

use crossbeam_channel as channel;
use et_core::packet::Packet;
use et_core::proto::{
    PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
    PortForwardWindow, SocketEndpoint, TerminalPacketType,
};
use prost::Message;

use crate::forward_endpoint::Endpoint;
use crate::ssh_agent_session_bind::{
    binds_for_destination, write_session_binds, AgentSessionBindReplies,
};

#[cfg(windows)]
use super::FastRoute;
use super::{
    spawn_connector, FlowWindow, ForwardError, ForwardStream, Role, Worker, MAX_ACTIVE_SOCKETS,
    MAX_DATA_PACKET, MAX_UNASSIGNED_FDS,
};
#[cfg(windows)]
use crate::forward_io::{close_write, spawn_io_direct, subtract_saturating, ActiveIo, DirectLanes};

/// Per-socket receive window.
///
/// Both limits must stay below the socket's 64-slot writer channel. A byte
/// limit alone is insufficient because legal one-byte reads can create far
/// more packets than the queue can absorb.
pub(super) const WINDOW_BYTES: i64 = 2 * 1024 * 1024;
pub(super) const WINDOW_PACKETS: i64 = 63;

/// Return credit once this much has drained, so a full window costs a bounded
/// number of control packets instead of one per data packet.
pub(crate) const CREDIT_RETURN_THRESHOLD: i64 = WINDOW_BYTES / 4;
pub(crate) const PACKET_CREDIT_RETURN_THRESHOLD: i64 = WINDOW_PACKETS / 4;

pub(super) fn advertised_window() -> PortForwardWindow {
    PortForwardWindow {
        bytes: Some(WINDOW_BYTES),
        packets: Some(WINDOW_PACKETS as i32),
    }
}

pub(crate) fn decode_window(window: Option<PortForwardWindow>) -> Option<FlowWindow> {
    let window = window?;
    let bytes = window.bytes.filter(|bytes| *bytes > 0)?;
    let packets = window.packets.filter(|packets| *packets > 0)?;
    Some(FlowWindow {
        bytes: bytes.min(WINDOW_BYTES),
        packets: i64::from(packets).min(WINDOW_PACKETS),
    })
}

#[cfg(windows)]
pub(crate) fn apply_delivery(active: &ActiveIo, delivered: FlowWindow) {
    use std::sync::atomic::Ordering;
    if delivered.bytes <= 0 || delivered.packets <= 0 {
        return;
    }
    let prior_bytes = subtract_saturating(&active.in_flight, delivered.bytes);
    let prior_packets = subtract_saturating(&active.packets_in_flight, delivered.packets);
    let byte_window = active.window.load(Ordering::Acquire);
    let packet_window = active.packet_window.load(Ordering::Acquire);
    if (byte_window >= 0 && prior_bytes >= byte_window)
        || (packet_window >= 0 && prior_packets >= packet_window)
    {
        let _ = active.in_flight_wake.try_send(());
    }
}

#[cfg(windows)]
pub(crate) fn apply_delivery_route(route: &FastRoute, delivered: FlowWindow) {
    use std::sync::atomic::Ordering;
    if delivered.bytes <= 0 || delivered.packets <= 0 {
        return;
    }
    let prior_bytes = subtract_saturating(&route.in_flight, delivered.bytes);
    let prior_packets = subtract_saturating(&route.packets_in_flight, delivered.packets);
    let byte_window = route.window.load(Ordering::Acquire);
    let packet_window = route.packet_window.load(Ordering::Acquire);
    if (byte_window >= 0 && prior_bytes >= byte_window)
        || (packet_window >= 0 && prior_packets >= packet_window)
    {
        let _ = route.in_flight_wake.try_send(());
    }
}

impl Worker {
    pub(super) fn accepted(
        &mut self,
        client_fd: i32,
        destination: SocketEndpoint,
        pending: super::PendingAccept,
    ) -> Result<(), ForwardError> {
        if self.total_sockets() >= MAX_ACTIVE_SOCKETS || self.pending.len() >= MAX_UNASSIGNED_FDS {
            pending.stream.shutdown();
            if pending.stdio {
                self.clear_stdio();
            }
            return Ok(());
        }
        self.pending.insert(client_fd, pending);
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
        peer_advertised: Option<FlowWindow>,
    ) -> Result<(), ForwardError> {
        self.connecting.remove(&socket_id);
        let pending_binds = self.pending_agent_binds.remove(&socket_id);
        let error = match result {
            Ok(mut stream) => match pending_binds {
                Some(pending) => {
                    match write_session_binds(&mut stream, &pending.path, &pending.binds) {
                        Ok(()) => {
                            let replies = AgentSessionBindReplies::new(
                                pending.binds.len(),
                                pending.path.clone(),
                            );
                            self.activate(
                                Role::Destination,
                                socket_id,
                                stream,
                                peer_advertised,
                                Some(replies),
                            )?;
                            None
                        }
                        Err(_) => {
                            // The warning is already logged. Drop closes the socket.
                            drop(stream);
                            Some("could not send ssh agent session binding".to_owned())
                        }
                    }
                }
                None => {
                    self.activate(Role::Destination, socket_id, stream, peer_advertised, None)?;
                    None
                }
            },
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
                #[cfg(unix)]
                if let Some((source_to_dest, socket_id, start, len)) =
                    try_fast_parse_data(packet.payload())
                {
                    let role = if source_to_dest {
                        Role::Destination
                    } else {
                        Role::Source
                    };
                    if len == 0 {
                        return Ok(());
                    }
                    if len > MAX_DATA_PACKET {
                        self.remove(role, socket_id);
                        return Ok(());
                    }
                    return self.admit_data_span(
                        role,
                        socket_id,
                        packet.into_payload(),
                        start,
                        len,
                    );
                }
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
        let peer_advertised = decode_window(request.window);
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
        if destination.can_connect_inline(self.session_user)
            && self.recorded_binds_for(&destination).is_none()
        {
            let result = destination.connect_with_user(self.session_user);
            return self.connected(client_fd, socket_id, result, peer_advertised);
        }
        self.connecting.insert(socket_id);
        self.pending_windows.insert(socket_id, peer_advertised);
        if let Some(pending) = self.recorded_binds_for(&destination) {
            self.pending_agent_binds.insert(socket_id, pending);
        }
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
        // A response for a token we no longer track must not attach to a later
        // accept that reused a descriptor. Close the destination the peer
        // opened instead of ignoring a live socket.
        let Some(client_fd) = response.clientfd else {
            return Ok(());
        };
        let Some(pending) = self.pending.remove(&client_fd) else {
            return self.reject_stale_destination(&response);
        };
        if response.error.is_some() {
            write_socks_reply(&pending.stream, pending.socks_version, false);
            pending.stream.shutdown();
            if pending.stdio {
                self.clear_stdio();
            }
            return Ok(());
        }
        let Some(socket_id) = response.socketid.filter(|value| *value > 0) else {
            write_socks_reply(&pending.stream, pending.socks_version, false);
            pending.stream.shutdown();
            if pending.stdio {
                self.clear_stdio();
            }
            return Ok(());
        };
        // The response carries a window only when the peer supports windowing
        // and the socket was established, so this is the source side's
        // negotiation point.
        let peer_advertised = decode_window(response.window);
        write_socks_reply(&pending.stream, pending.socks_version, true);
        let super::PendingAccept {
            stream,
            early,
            half_close_on_eof,
            stdio,
            ..
        } = pending;
        if !early.is_empty() {
            self.send_data(Role::Source, socket_id, early, false, None)?;
        }
        self.activate(Role::Source, socket_id, stream, peer_advertised, None)?;
        if let Some(active) = self.sources.get_mut(&socket_id) {
            active.half_close_on_eof = half_close_on_eof;
        }
        if stdio {
            self.stdio_socket = Some(socket_id);
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
        if let Some(delivered) = decode_window(data.window) {
            self.apply_window(role, socket_id, delivered);
            if buffer.is_empty()
                && !data.closed.unwrap_or(false)
                && !data.half_close.unwrap_or(false)
            {
                return Ok(());
            }
        }
        if role == Role::Destination && data.half_close.unwrap_or(false) {
            // Upstream `ForwardDestinationHandler::shutdownWrite`: the source
            // finished writing (`et -W` stdin EOF). Keep this socket readable
            // so the reply still flows back.
            return self.peer_half_close(role, socket_id);
        }
        if data.closed.unwrap_or(false) {
            // Upstream closes the local socket in full on a peer close, in
            // either role (`destinationHandlers.erase`, `closeSourceSocketId`).
            // Writes already queued still flush first: upstream wrote them
            // synchronously before it handled this packet.
            return self.peer_closed(role, socket_id);
        }
        if buffer.is_empty() {
            return Ok(());
        }
        if buffer.len() > MAX_DATA_PACKET {
            // Defensive bound: drop the offending socket, never the session.
            self.remove(role, socket_id);
            return Ok(());
        }
        self.admit_data(role, socket_id, buffer)
    }

    #[cfg(windows)]
    pub(crate) fn peer_closed(&mut self, role: Role, socket_id: i32) -> Result<(), ForwardError> {
        if self.map_ref(role).contains_key(&socket_id) {
            self.send_data(role, socket_id, Vec::new(), true, None)?;
        }
        self.remove(role, socket_id);
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn apply_window(&mut self, role: Role, socket_id: i32, delivered: FlowWindow) {
        if let Some(active) = self.map(role).get_mut(&socket_id) {
            apply_delivery(active, delivered);
        }
    }

    #[cfg(windows)]
    pub(crate) fn peer_half_close(
        &mut self,
        role: Role,
        socket_id: i32,
    ) -> Result<(), ForwardError> {
        let Some(active) = self.map(role).get_mut(&socket_id) else {
            return Ok(());
        };
        close_write(active);
        if let Some(route) = self.routes.write().unwrap().get_mut(&(role, socket_id)) {
            route.writer = None;
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn admit_data(
        &mut self,
        role: Role,
        socket_id: i32,
        buffer: Vec<u8>,
    ) -> Result<(), ForwardError> {
        // Data for an already-closed socket id is a normal race; upstream
        // logs a warning and drops it.
        let Some(active) = self.map_ref(role).get(&socket_id) else {
            return Ok(());
        };
        let Some(writer) = &active.writer else {
            // Upstream drops writes after `shutdownWrite`.
            return Ok(());
        };
        let byte_count = buffer.len();
        active
            .pending_bytes
            .fetch_add(byte_count, std::sync::atomic::Ordering::AcqRel);
        let admitted = channel::select! {
            send(writer, buffer) -> result => result.is_ok(),
            recv(self.cancel) -> _ => false,
        };
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
    #[cfg(windows)]
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
        active.packet_credit_to_return = active.packet_credit_to_return.saturating_add(1);
        // Batch returns so a full window costs a bounded number of control
        // packets, but ALSO flush whenever the socket has gone idle. Without
        // the idle flush a sub-threshold remainder is stranded, the peer's
        // window shrinks by that much for the rest of the connection, and a
        // steady stream eventually parks its sender permanently.
        let idle = active
            .pending_bytes
            .load(std::sync::atomic::Ordering::Acquire)
            == 0;
        if active.credit_to_return < CREDIT_RETURN_THRESHOLD
            && active.packet_credit_to_return < PACKET_CREDIT_RETURN_THRESHOLD
            && !idle
        {
            return Ok(());
        }
        let credit = std::mem::take(&mut active.credit_to_return);
        let packet_credit = std::mem::take(&mut active.packet_credit_to_return);
        if credit == 0 || packet_credit == 0 {
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
                half_close: None,
                window: Some(PortForwardWindow {
                    bytes: Some(credit),
                    packets: Some(i32::try_from(packet_credit).unwrap_or(i32::MAX)),
                }),
            },
        )
    }

    #[cfg(windows)]
    pub(super) fn read_closed(&mut self, role: Role, socket_id: i32) -> Result<(), ForwardError> {
        // A socket the peer already closed reports nothing: upstream only
        // emits EOF for a socket it still owns.
        let Some(active) = self.map(role).get_mut(&socket_id) else {
            return Ok(());
        };
        if active.half_close_on_eof {
            // Upstream stdio mode: half-close the request direction and keep
            // the reply open until the remote side closes.
            active.half_close_on_eof = false;
            return self.send_half_close(role, socket_id);
        }
        // Upstream sends `closed` and closes the socket in full.
        self.send_data(role, socket_id, Vec::new(), true, None)?;
        self.remove(role, socket_id);
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
                half_close: None,
                window: None,
            },
        )
    }

    pub(super) fn send_half_close(
        &mut self,
        role: Role,
        socket_id: i32,
    ) -> Result<(), ForwardError> {
        self.emit(
            TerminalPacketType::PortForwardData as u8,
            PortForwardData {
                sourcetodestination: Some(role == Role::Source),
                socketid: Some(socket_id),
                buffer: None,
                error: None,
                closed: Some(true),
                half_close: Some(true),
                window: None,
            },
        )
    }

    fn reject_stale_destination(
        &mut self,
        response: &PortForwardDestinationResponse,
    ) -> Result<(), ForwardError> {
        if response.error.is_some() {
            return Ok(());
        }
        let Some(socket_id) = response.socketid.filter(|value| *value > 0) else {
            return Ok(());
        };
        self.emit(
            TerminalPacketType::PortForwardData as u8,
            PortForwardData {
                sourcetodestination: Some(true),
                socketid: Some(socket_id),
                buffer: None,
                error: None,
                closed: Some(true),
                half_close: None,
                window: None,
            },
        )
    }

    pub(super) fn expire_parked(&mut self) {
        let now = Instant::now();
        let expired: Vec<i32> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(client_fd, _)| *client_fd)
            .collect();
        for client_fd in expired {
            if let Some(pending) = self.pending.remove(&client_fd) {
                pending.stream.shutdown();
                if pending.stdio {
                    self.clear_stdio();
                }
            }
        }
    }

    pub(super) fn next_park_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    #[cfg(test)]
    pub(super) fn expire_for_test(&mut self, client_fd: i32) {
        if let Some(pending) = self.pending.get_mut(&client_fd) {
            pending.deadline = Instant::now() - std::time::Duration::from_secs(1);
        }
    }

    fn clear_stdio(&mut self) {
        self.stdio_socket = None;
        if let Some(open) = &self.stdio_open {
            open.store(false, std::sync::atomic::Ordering::Release);
        }
    }

    fn recorded_binds_for(
        &self,
        destination: &Endpoint,
    ) -> Option<crate::ssh_agent_session_bind::PendingSessionBinds> {
        let (is_tcp, name) = match destination {
            Endpoint::Tcp { .. } => (true, None),
            #[cfg(unix)]
            Endpoint::Unix(path) => (false, path.to_str()),
        };
        binds_for_destination(
            &self.ssh_agent_socket_path,
            &self.ssh_agent_session_binds,
            is_tcp,
            name,
        )
    }

    #[cfg(windows)]
    fn activate(
        &mut self,
        role: Role,
        socket_id: i32,
        stream: ForwardStream,
        peer_window: Option<FlowWindow>,
        bind_replies: Option<AgentSessionBindReplies>,
    ) -> Result<(), ForwardError> {
        let active_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let direct = self.direct_enabled.then(|| DirectLanes {
            outbound: self.outbound.clone(),
            priority: self.priority.clone(),
            #[cfg(unix)]
            wake_writer: self.outbound_wake.clone(),
            #[cfg(unix)]
            wake_signalled: self.wake_signalled.clone(),
            active_flag: active_flag.clone(),
        });
        let (active, handles) = spawn_io_direct(
            role,
            socket_id,
            stream,
            peer_window,
            self.commands.clone(),
            self.cancel.clone(),
            self.abandoned.clone(),
            bind_replies,
            direct,
        )
        .map_err(ForwardError::Io)?;
        self.routes.write().unwrap().insert(
            (role, socket_id),
            FastRoute {
                writer: active.writer.clone(),
                pending_bytes: active.pending_bytes.clone(),
                in_flight: active.in_flight.clone(),
                packets_in_flight: active.packets_in_flight.clone(),
                window: active.window.clone(),
                packet_window: active.packet_window.clone(),
                in_flight_wake: active.in_flight_wake.clone(),
            },
        );
        self.map(role).insert(socket_id, active);
        self.threads.extend(handles);
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn remove(&mut self, role: Role, socket_id: i32) {
        if role == Role::Source && self.stdio_socket == Some(socket_id) {
            // The stdout copier clears the bridge flag once every queued byte
            // is flushed, so `et -W` cannot exit ahead of its trailing output.
            self.stdio_socket = None;
        }
        self.routes.write().unwrap().remove(&(role, socket_id));
        if let Some(active) = self.map(role).remove(&socket_id) {
            super::stop_io(active);
        }
    }

    #[cfg(windows)]
    fn map(&mut self, role: Role) -> &mut std::collections::HashMap<i32, ActiveIo> {
        match role {
            Role::Source => &mut self.sources,
            Role::Destination => &mut self.destinations,
        }
    }

    #[cfg(windows)]
    pub(crate) fn map_ref(&self, role: Role) -> &std::collections::HashMap<i32, ActiveIo> {
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
    pub(super) fn emit_priority<M: Message>(
        &mut self,
        header: u8,
        message: M,
    ) -> Result<(), ForwardError> {
        let packet = Ok(Packet::new(header, message.encode_to_vec()));
        channel::select! {
            send(self.priority, packet) -> result => {
                result.map_err(|_| ForwardError::Unavailable)?;
            }
            recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
        }
        #[cfg(unix)]
        {
            self.note_outbound_emitted();
        }
        Ok(())
    }
    #[cfg(unix)]
    pub(super) fn flush_outbound_wake(&mut self) {
        self.outbound_wake_needed = false;
        // Always write the byte. Gating it on the queues being non-empty
        // loses the wake when the session drains the last packet and goes
        // back to poll between this check and the write.
        if !self
            .wake_signalled
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = (&*self.outbound_wake).write(&[1]);
        }
    }

    #[cfg(unix)]
    pub(super) fn note_outbound_emitted(&mut self) {
        if !self.defer_outbound_wake || self.outbound.len() >= 4 {
            self.flush_outbound_wake();
        } else {
            self.outbound_wake_needed = true;
        }
    }

    pub(super) fn emit<M: Message>(&mut self, header: u8, message: M) -> Result<(), ForwardError> {
        let packet = Ok(Packet::new(header, message.encode_to_vec()));
        #[cfg(unix)]
        {
            // A full outbound channel must not freeze the poll loop: the
            // session drains it, and the worker has sockets to service in the
            // meantime. Spill up to one channel's worth and retry next cycle.
            // Past that the session is not draining, so block as before.
            if self.outbound_spill.len() < crate::forward::CHANNEL_SPILL_LIMIT {
                match self.outbound.try_send(packet) {
                    Ok(()) => {}
                    Err(crossbeam_channel::TrySendError::Full(packet)) => {
                        self.outbound_spill.push_back(packet);
                    }
                    Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                        return Err(ForwardError::Unavailable);
                    }
                }
            } else {
                channel::select! {
                    send(self.outbound, packet) -> result => {
                        result.map_err(|_| ForwardError::Unavailable)?;
                    }
                    recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
                }
            }
            self.note_outbound_emitted();
            Ok(())
        }
        #[cfg(windows)]
        {
            channel::select! {
                send(self.outbound, packet) -> result => {
                    result.map_err(|_| ForwardError::Unavailable)?;
                }
                recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
            }
            Ok(())
        }
    }

    pub(super) fn emit_raw(&mut self, header: u8, payload: Vec<u8>) -> Result<(), ForwardError> {
        #[cfg(unix)]
        let is_small = payload.len() <= 4096;
        let packet = Ok(Packet::new(header, payload));
        #[cfg(unix)]
        {
            if !self.outbound_spill.is_empty() {
                if self.outbound_spill.len() < crate::forward::CHANNEL_SPILL_LIMIT {
                    self.outbound_spill.push_back(packet);
                } else {
                    channel::select! {
                        send(self.outbound, packet) -> result => {
                            result.map_err(|_| ForwardError::Unavailable)?;
                        }
                        recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
                    }
                }
            } else if self.outbound_spill.len() < crate::forward::CHANNEL_SPILL_LIMIT {
                match self.outbound.try_send(packet) {
                    Ok(()) => {}
                    Err(crossbeam_channel::TrySendError::Full(packet)) => {
                        self.outbound_spill.push_back(packet);
                    }
                    Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                        return Err(ForwardError::Unavailable);
                    }
                }
            } else {
                channel::select! {
                    send(self.outbound, packet) -> result => {
                        result.map_err(|_| ForwardError::Unavailable)?;
                    }
                    recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
                }
            }
            if is_small {
                self.flush_outbound_wake();
            } else {
                self.note_outbound_emitted();
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            channel::select! {
                send(self.outbound, packet) -> result => {
                    result.map_err(|_| ForwardError::Unavailable)?;
                }
                recv(self.cancel) -> _ => return Err(ForwardError::Unavailable),
            }
            Ok(())
        }
    }
}

fn write_socks_reply(stream: &ForwardStream, version: Option<u8>, success: bool) {
    let Some(version) = version else {
        return;
    };
    let mut stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let reply = crate::socks::socks_connect_reply(version, success);
    let _ = std::io::Write::write_all(&mut stream, &reply);
}

#[cfg(unix)]
pub(crate) fn try_fast_parse_data(payload: &[u8]) -> Option<(bool, i32, usize, usize)> {
    if payload.len() < 6 || payload[0] != 0x08 {
        return None;
    }
    let source_to_dest = match payload[1] {
        0 => false,
        1 => true,
        _ => return None,
    };
    if payload[2] != 0x10 {
        return None;
    }
    let mut offset = 3;
    let socket_id = decode_varint_u32(payload, &mut offset)? as i32;
    if offset >= payload.len() || payload[offset] != 0x1a {
        return None;
    }
    offset += 1;
    let buf_len = decode_varint_usize(payload, &mut offset)?;
    let end = offset.checked_add(buf_len)?;
    if end == payload.len() {
        Some((source_to_dest, socket_id, offset, buf_len))
    } else {
        None
    }
}

#[cfg(unix)]
fn decode_varint_u32(slice: &[u8], offset: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0;
    while *offset < slice.len() {
        if shift >= 32 {
            return None;
        }
        let byte = slice[*offset];
        *offset += 1;
        let bits = (byte & 0x7f) as u32;
        if shift == 28 && bits > 0x0f {
            return None;
        }
        result |= bits << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

#[cfg(unix)]
fn decode_varint_usize(slice: &[u8], offset: &mut usize) -> Option<usize> {
    let mut result = 0usize;
    let mut shift = 0;
    while *offset < slice.len() {
        if shift >= (usize::BITS as usize) {
            return None;
        }
        let byte = slice[*offset];
        *offset += 1;
        result |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

pub(crate) fn encode_data_packet(
    source_to_destination: bool,
    socket_id: i32,
    buffer: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(12 + buffer.len());
    payload.push(0x08);
    payload.push(source_to_destination as u8);
    payload.push(0x10);
    prost::encoding::encode_varint(socket_id as u64, &mut payload);
    payload.push(0x1a);
    prost::encoding::encode_varint(buffer.len() as u64, &mut payload);
    payload.extend_from_slice(buffer);
    payload
}
#[cfg(test)]
mod tests {
    use super::{decode_window, FlowWindow, PortForwardWindow, WINDOW_BYTES, WINDOW_PACKETS};

    #[test]
    fn hostile_window_values_are_rejected_or_bounded() {
        assert_eq!(decode_window(None), None);
        assert_eq!(
            decode_window(Some(PortForwardWindow {
                bytes: Some(0),
                packets: Some(1),
            })),
            None
        );
        assert_eq!(
            decode_window(Some(PortForwardWindow {
                bytes: Some(-1),
                packets: Some(1),
            })),
            None
        );
        assert_eq!(
            decode_window(Some(PortForwardWindow {
                bytes: Some(1),
                packets: None,
            })),
            None
        );
        assert_eq!(
            decode_window(Some(PortForwardWindow {
                bytes: Some(i64::MAX),
                packets: Some(i32::MAX),
            })),
            Some(FlowWindow {
                bytes: WINDOW_BYTES,
                packets: WINDOW_PACKETS,
            })
        );
    }
}
