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
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
    TerminalPacketType,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
use prost::Message;
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};

use crate::terminal_credentials::CredentialInput;

const MAX_HANDSHAKE_PROTO_LEN: i64 = 64 * 1024;
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
    // The destination runs a real terminal, so the relayed payload must not
    // ask it to start another jumphost.
    let mut payload = payload;
    payload.jumphost = Some(false);

    let mut destination = connect_destination(input, destination_host, destination_port, &payload)?;
    relay(router, &mut destination)
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

fn connect_destination(
    input: &CredentialInput,
    host: &str,
    port: u16,
    payload: &InitialPayload,
) -> Result<Connection, String> {
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
) -> Result<Connection, String> {
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
    connection
        .write_packet(EtPacketType::InitialPayload as u8, &payload.encode_to_vec())
        .map_err(|error| format!("could not send INITIAL_PAYLOAD: {error}"))?;
    let packet = connection
        .read_packet()
        .map_err(|error| format!("could not read INITIAL_RESPONSE: {error}"))?;
    if packet.header() != EtPacketType::InitialResponse as u8 {
        return Err("Missing initial response!".to_owned());
    }
    let response = InitialResponse::decode(packet.payload())
        .map_err(|_| "malformed INITIAL_RESPONSE".to_owned())?;
    if let Some(error) = response.error {
        return Err(format!("Error initializing connection: {error}"));
    }
    connection
        .set_io_timeout(None)
        .map_err(|error| format!("could not clear the destination timeout: {error}"))?;
    Ok(connection)
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
