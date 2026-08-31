use std::io;
use std::net::TcpStream;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::{client_request, MAX_HANDSHAKE_PROTO_LEN};
use prost::Message;

use crate::bootstrap::Credentials;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::resolver::EndpointResolver;

const MAX_ENDPOINT_ADDRESSES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[path = "reconnect.rs"]
mod reconnect_impl;

pub use reconnect_impl::reconnect;
#[cfg(test)]
use reconnect_impl::{accept_reconnect_response, ReconnectStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectOutcome {
    Recovered,
    SessionEnded,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

pub fn connect_initial(
    endpoint: &Endpoint,
    credentials: &Credentials,
    initial_payload: &InitialPayload,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<Connection, ClientError> {
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint, resolver, deadline)?;
    set_stream_timeout(&stream, deadline)?;

    ensure_deadline(deadline, "sending ConnectRequest")?;
    write_proto(&mut stream, &client_request(&credentials.id))
        .map_err(|source| connect_error(deadline, "sending ConnectRequest", source))?;
    set_stream_timeout(&stream, deadline)?;
    let response: ConnectResponse = read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN)
        .map_err(|source| connect_error(deadline, "reading ConnectResponse", source))?;
    accept_response(response)?;

    ensure_deadline(deadline, "sending INITIAL_PAYLOAD")?;
    let mut connection = Connection::new_client(stream, &key);
    connection
        .write_packet_live(
            EtPacketType::InitialPayload as u8,
            &initial_payload.encode_to_vec(),
        )
        .map_err(|error| transport_error(deadline, "sending INITIAL_PAYLOAD", error))?;
    ensure_deadline(deadline, "reading INITIAL_RESPONSE")?;
    let packet = connection
        .read_packet()
        .map_err(|error| transport_error(deadline, "reading INITIAL_RESPONSE", error))?;
    if packet.header() != EtPacketType::InitialResponse as u8 {
        return Err(ClientError::UnexpectedInitialPacket(packet.header()));
    }
    let response =
        InitialResponse::decode(packet.payload()).map_err(ClientError::MalformedInitialResponse)?;
    accept_initial_response(response)?;
    connection
        .set_io_timeout(None)
        .map_err(ClientError::Transport)?;
    Ok(connection)
}

fn connect_endpoint(
    endpoint: &Endpoint,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<TcpStream, ClientError> {
    let display = endpoint.to_string();
    let addresses = resolver.resolve(endpoint, deadline)?;
    let mut last_error = None;
    for address in addresses.into_iter().take(MAX_ENDPOINT_ADDRESSES) {
        let remaining = deadline.remaining().ok_or(ClientError::BootstrapTimeout(
            "connecting to the ET endpoint",
        ))?;
        match TcpStream::connect_timeout(&address, remaining.min(CONNECT_TIMEOUT)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(ClientError::UnreachableEndpoint {
        endpoint: display,
        source: last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "host resolved to no addresses",
            )
        }),
    })
}

fn set_stream_timeout(stream: &TcpStream, deadline: Deadline) -> Result<(), ClientError> {
    let remaining = deadline.remaining().ok_or(ClientError::BootstrapTimeout(
        "configuring the ET connection",
    ))?;
    let timeout = Some(remaining.min(IO_TIMEOUT));
    stream
        .set_read_timeout(timeout)
        .map_err(|source| ClientError::ConnectIo {
            operation: "setting the read timeout",
            source,
        })?;
    stream
        .set_write_timeout(timeout)
        .map_err(|source| ClientError::ConnectIo {
            operation: "setting the write timeout",
            source,
        })
}

fn ensure_deadline(deadline: Deadline, operation: &'static str) -> Result<(), ClientError> {
    match deadline.remaining() {
        Some(_) => Ok(()),
        None => Err(ClientError::BootstrapTimeout(operation)),
    }
}

fn connect_error(deadline: Deadline, operation: &'static str, source: io::Error) -> ClientError {
    match deadline.remaining() {
        Some(_) => ClientError::ConnectIo { operation, source },
        None => ClientError::BootstrapTimeout(operation),
    }
}

fn transport_error(
    deadline: Deadline,
    operation: &'static str,
    error: et_net::connection::ConnError,
) -> ClientError {
    match deadline.remaining() {
        Some(_) => ClientError::Transport(error),
        None => ClientError::BootstrapTimeout(operation),
    }
}

fn accept_initial_response(response: InitialResponse) -> Result<(), ClientError> {
    if let Some(message) = response.error {
        Err(ClientError::InitialResponseRejected(message))
    } else {
        Ok(())
    }
}

fn accept_response(response: ConnectResponse) -> Result<(), ClientError> {
    let status = response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok());
    match status {
        Some(ConnectStatus::NewClient) => Ok(()),
        Some(ConnectStatus::ReturningClient) => Err(ClientError::ReturningSessionRequiresRecovery),
        Some(ConnectStatus::InvalidKey) => Err(ClientError::ServerInvalidKey(response.error)),
        Some(ConnectStatus::MismatchedProtocol) => {
            Err(ClientError::ProtocolMismatch(response.error))
        }
        None => Err(ClientError::ServerRejected {
            status: response.status,
            message: response.error,
        }),
    }
}

#[cfg(test)]
#[path = "initial_connect_tests.rs"]
mod tests;
