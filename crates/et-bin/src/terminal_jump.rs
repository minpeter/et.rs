//! `etterminal --jump`: the jumphost relay, mirroring upstream
//! `UserJumphostHandler`.
//!
//! The process registers with the local jumphost router as a terminal, waits
//! for the `JUMPHOST_INIT` payload the jumphost etserver forwards from the
//! client, opens its own ET client connection to the final destination with
//! the same id/passkey, and then relays packets verbatim in both directions.

use et_net::local::LocalStream;
use std::io::{self, Read};
use std::net::ToSocketAddrs;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::packet::Packet;
use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, FlowControlMode, InitialPayload, InitialResponse,
    TerminalPacketType,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::{client_request, MAX_HANDSHAKE_PROTO_LEN};
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
use prost::Message;
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};

use crate::terminal_credentials::CredentialInput;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_BUFFER: usize = 16 * 1024;
/// Upstream retries the destination connection three times before failing.
const CONNECT_ATTEMPTS: usize = 3;

pub fn run(
    mut router: LocalStream,
    input: &CredentialInput,
    destination_host: &str,
    destination_port: u16,
) -> Result<i32, String> {
    let payload = read_jumphost_init(&mut router)?;
    if !payload.jumphost.unwrap_or(false) {
        return Err("Jumphost should be set by the initial client".to_owned());
    }
    let flow_control = payload
        .flowcontrol
        .and_then(|value| FlowControlMode::try_from(value).ok())
        .unwrap_or(FlowControlMode::None);
    let bounded_output = match flow_control {
        FlowControlMode::None => false,
        FlowControlMode::Backpressure | FlowControlMode::Discard => true,
    };
    if bounded_output {
        // Destination output enters the jumphost router through this terminal-
        // side sender. Keep pressure in the server's bounded application lanes.
        et_net::local::minimize_terminal_output_buffering(&router)
            .map_err(|error| format!("could not bound jumphost output buffering: {error}"))?;
    }
    // The destination runs a real terminal, so the relayed payload must not
    // ask it to start another jumphost.
    let mut payload = payload;
    payload.jumphost = Some(false);

    let mut destination = connect_destination(input, destination_host, destination_port, &payload)?;
    write_local_packet(
        &mut router,
        &Packet::new(
            TerminalPacketType::JumphostInit as u8,
            destination.response_payload.clone(),
        ),
    )
    .map_err(|error| format!("could not relay destination INITIAL_RESPONSE: {error}"))?;
    if downstream_requires_ack(&destination.response_payload)? {
        let acknowledgement = et_net::local_packet::read_local_packet(&mut router)
            .map_err(|error| format!("could not read jumphost acknowledgement: {error}"))?;
        if !is_acknowledgement(&acknowledgement) {
            return Err("jumphost acknowledgement is malformed".to_owned());
        }
        destination
            .connection
            .write_packet(EtPacketType::Heartbeat as u8, &[])
            .map_err(|error| format!("could not acknowledge destination response: {error}"))?;
    }
    destination
        .connection
        .set_io_timeout(None)
        .map_err(|error| format!("could not clear the destination timeout: {error}"))?;
    relay(router, &mut destination.connection)
}

fn read_jumphost_init(router: &mut LocalStream) -> Result<InitialPayload, String> {
    let packet = et_net::local_packet::read_local_packet(router)
        .map_err(|error| format!("Cannot read jumphost init from router: {error}"))?;
    if packet.is_encrypted() || packet.header() != TerminalPacketType::JumphostInit as u8 {
        return Err(format!(
            "Invalid jumphost init packet header: {}",
            packet.header()
        ));
    }
    InitialPayload::decode(packet.payload())
        .map_err(|_| "JUMPHOST_INIT protobuf is malformed".to_owned())
}

struct DestinationHandshake {
    connection: Connection,
    response_payload: Vec<u8>,
}

fn connect_destination(
    input: &CredentialInput,
    host: &str,
    port: u16,
    payload: &InitialPayload,
) -> Result<DestinationHandshake, String> {
    let key = passkey_to_key(&input.passkey).ok_or_else(|| "invalid passkey".to_owned())?;
    let mut last_error = String::from("Connect Timeout");
    for _ in 0..CONNECT_ATTEMPTS {
        match try_connect_once(&input.id, &key, host, port, payload) {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = error,
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "Could not make initial connection to {host}:{port}: {last_error}"
    ))
}

fn try_connect_once(
    id: &str,
    key: &[u8; 32],
    host: &str,
    port: u16,
    payload: &InitialPayload,
) -> Result<DestinationHandshake, String> {
    try_connect_once_observed(id, key, host, port, payload, |_| Ok(()))
}

fn try_connect_once_observed<F>(
    id: &str,
    key: &[u8; 32],
    host: &str,
    port: u16,
    payload: &InitialPayload,
    observe_before_payload: F,
) -> Result<DestinationHandshake, String>
where
    F: FnOnce(&Connection) -> Result<(), String>,
{
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve {host}: {error}"))?;
    let mut stream = None;
    let mut last_error = None;
    for address in addresses {
        match std::net::TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        last_error.map_or_else(
            || "host resolved to no addresses".to_owned(),
            |error| error.to_string(),
        )
    })?;
    stream
        .set_read_timeout(Some(CONNECT_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CONNECT_TIMEOUT)))
        .map_err(|error| format!("could not configure the destination socket: {error}"))?;
    write_proto(&mut stream, &client_request(id))
        .map_err(|error| format!("could not send ConnectRequest: {error}"))?;
    let response: ConnectResponse = read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN)
        .map_err(|error| format!("could not read ConnectResponse: {error}"))?;
    match response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok())
    {
        Some(ConnectStatus::NewClient) => {}
        Some(status) => {
            return Err(format!(
                "destination rejected the session: {status:?}{}",
                response
                    .error
                    .map(|error| format!(": {error}"))
                    .unwrap_or_default()
            ))
        }
        None => return Err("destination sent an unknown connect status".to_owned()),
    }
    let mut connection = Connection::new_client(stream, key);
    match payload
        .flowcontrol
        .and_then(|value| FlowControlMode::try_from(value).ok())
        .unwrap_or(FlowControlMode::None)
    {
        FlowControlMode::None => {}
        FlowControlMode::Backpressure | FlowControlMode::Discard => connection
            .minimize_output_buffering()
            .map_err(|error| format!("could not bound destination output buffering: {error}"))?,
    }
    observe_before_payload(&connection)?;
    connection
        .write_packet(EtPacketType::InitialPayload as u8, &payload.encode_to_vec())
        .map_err(|error| format!("could not send INITIAL_PAYLOAD: {error}"))?;
    let packet = connection
        .read_packet()
        .map_err(|error| format!("could not read INITIAL_RESPONSE: {error}"))?;
    if packet.header() != EtPacketType::InitialResponse as u8 {
        return Err("Missing initial response!".to_owned());
    }
    Ok(DestinationHandshake {
        connection,
        response_payload: packet.payload().to_vec(),
    })
}

fn downstream_requires_ack(payload: &[u8]) -> Result<bool, String> {
    InitialResponse::decode(payload)
        .map(|response| response.error.is_some())
        .map_err(|_| "destination sent a malformed INITIAL_RESPONSE".to_owned())
}

fn is_acknowledgement(packet: &Packet) -> bool {
    !packet.is_encrypted()
        && packet.header() == EtPacketType::Heartbeat as u8
        && packet.payload().is_empty()
}

/// Relay packets verbatim between the local router and the destination.
fn relay(mut router: LocalStream, destination: &mut Connection) -> Result<i32, String> {
    router
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure the router socket: {error}"))?;
    let mut decoder = LocalPacketDecoder::new();
    // Windows cannot poll the router channel and the destination socket
    // together, so it walks both without blocking on upstream's 10ms cadence.
    #[cfg(windows)]
    loop {
        let mut progress = false;
        match read_router_packet(&mut router, &mut decoder)? {
            Some(packet) => {
                progress = true;
                decoder = LocalPacketDecoder::new();
                let packet = destination_packet(destination, packet);
                if destination
                    .write_packet(packet.header(), packet.payload())
                    .is_err()
                {
                    return Ok(0);
                }
            }
            None => {}
        }
        loop {
            match destination.try_read_packet() {
                Ok(Some(packet)) => {
                    progress = true;
                    let packet = router_packet(destination, packet);
                    if write_local_packet(&mut router, &packet).is_err() {
                        return Ok(0);
                    }
                }
                Ok(None) => break,
                Err(_) => return Ok(0),
            }
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(unix)]
    loop {
        let client = destination
            .try_clone_stream()
            .map_err(|error| format!("could not poll the destination: {error}"))?;
        let mut descriptors = [
            PollFd::new(&router, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
            PollFd::new(&client, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
        ];
        // poll() is never restarted by SA_RESTART; retry on EINTR so a stray
        // signal cannot kill the jump-host bridge.
        loop {
            match poll(&mut descriptors, None) {
                Ok(_) => break,
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(format!("poll failed: {error}")),
            }
        }
        let router_events = descriptors[0].revents();
        let client_events = descriptors[1].revents();
        drop(client);

        if router_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(0);
        }
        if router_events.contains(PollFlags::IN) {
            if let Some(packet) = read_router_packet(&mut router, &mut decoder)? {
                decoder = LocalPacketDecoder::new();
                let packet = destination_packet(destination, packet);
                if destination
                    .write_packet(packet.header(), packet.payload())
                    .is_err()
                {
                    return Ok(0);
                }
            }
        }
        if client_events.contains(PollFlags::IN) {
            loop {
                match destination.try_read_packet() {
                    Ok(Some(packet)) => {
                        let packet = router_packet(destination, packet);
                        if write_local_packet(&mut router, &packet).is_err() {
                            return Ok(0);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Ok(0),
                }
            }
        }
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(0);
        }
    }
}

/// Normalize a packet relayed towards the destination.
///
/// Keep-alive acknowledgements are per-hop: any payload the client attached
/// was already consumed by the jumphost etserver, so replace it with this
/// hop's own reader sequence, letting the destination trim its replay backup.
fn destination_packet(destination: &Connection, packet: Packet) -> Packet {
    if packet.header() != TerminalPacketType::KeepAlive as u8 {
        return packet;
    }
    Packet::new(
        TerminalPacketType::KeepAlive as u8,
        destination.keepalive_ack().to_vec(),
    )
}

/// Normalize a packet relayed towards the local router.
///
/// A keep-alive echo from the destination acknowledges this hop's writer;
/// consume it and relay a payload-less keep-alive (the jumphost etserver
/// attaches the client-facing acknowledgement).
fn router_packet(destination: &mut Connection, packet: Packet) -> Packet {
    if packet.header() != TerminalPacketType::KeepAlive as u8 {
        return packet;
    }
    if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
        destination.acknowledge_delivery(ack);
    }
    Packet::new(TerminalPacketType::KeepAlive as u8, Vec::new())
}

fn read_router_packet(
    router: &mut LocalStream,
    decoder: &mut LocalPacketDecoder,
) -> Result<Option<Packet>, String> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let wanted = decoder.required_bytes().min(buffer.len());
        match router.read(&mut buffer[..wanted]) {
            Ok(0) => return Err("jumphost router disconnected".to_owned()),
            Ok(count) => {
                if let Some(packet) = decoder
                    .feed(&buffer[..count])
                    .map_err(|error| format!("malformed router packet: {error}"))?
                {
                    return Ok(Some(packet));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("could not read the router: {error}")),
        }
    }
}

#[cfg(test)]
#[path = "terminal_jump_tests.rs"]
mod tests;
