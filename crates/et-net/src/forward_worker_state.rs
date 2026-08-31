#[cfg(unix)]
use std::io::Write;
use std::io::{self};

use et_core::packet::Packet;
use et_core::proto::{
    PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse, SocketEndpoint,
    TerminalPacketType,
};
use prost::Message;

use crate::forward_endpoint::Endpoint;

use super::{
    spawn_connector, spawn_io, ActiveIo, ForwardError, ForwardStream, Role, Worker, WriteCommand,
    MAX_ACTIVE_SOCKETS, MAX_DATA_PACKET,
};

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
            },
        )
    }

    pub(super) fn connected(
        &mut self,
        client_fd: i32,
        socket_id: i32,
        result: io::Result<ForwardStream>,
    ) -> Result<(), ForwardError> {
        self.connecting.remove(&socket_id);
        let error = match result {
            Ok(stream) => {
                self.activate(Role::Destination, socket_id, stream)?;
                None
            }
            Err(error) => Some(error.to_string()),
        };
        self.emit(
            TerminalPacketType::PortForwardDestinationResponse as u8,
            PortForwardDestinationResponse {
                clientfd: Some(client_fd),
                socketid: error.is_none().then_some(socket_id),
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
        let destination = match Endpoint::parse_destination(request.destination) {
            Ok(destination) => destination,
            Err(error) => return self.connected(client_fd, 0, Err(error)),
        };
        if self.total_sockets() >= MAX_ACTIVE_SOCKETS {
            return self.connected(
                client_fd,
                0,
                Err(io::Error::other("forwarding socket limit reached")),
            );
        }
        let socket_id = self.allocate_socket_id()?;
        self.connecting.insert(socket_id);
        self.threads.push(spawn_connector(
            client_fd,
            socket_id,
            destination,
            self.commands.clone(),
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
        self.activate(Role::Source, socket_id, stream)
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
        if data.closed.unwrap_or(false) || data.error.is_some() {
            self.remove(role, socket_id);
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
        active
            .writer
            .send(WriteCommand::Data(buffer))
            .map_err(|_| ForwardError::Unavailable)
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
            },
        )
    }

    fn activate(
        &mut self,
        role: Role,
        socket_id: i32,
        stream: ForwardStream,
    ) -> Result<(), ForwardError> {
        let (active, handles) =
            spawn_io(role, socket_id, stream, self.commands.clone()).map_err(ForwardError::Io)?;
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

    fn emit<M: Message>(&mut self, header: u8, message: M) -> Result<(), ForwardError> {
        let mut outbound = Ok(Packet::new(header, message.encode_to_vec()));
        loop {
            if self.shutdown.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ForwardError::Unavailable);
            }
            match self.outbound.try_send(outbound) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(value)) => {
                    outbound = value;
                    std::thread::yield_now();
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(ForwardError::Unavailable);
                }
            }
        }
        // Unix consumers poll the wake socket; Windows consumers drain
        // `try_outbound` on the client loop's 10ms cadence.
        #[cfg(unix)]
        let _ = self.outbound_wake.write(&[1]);
        Ok(())
    }
}
