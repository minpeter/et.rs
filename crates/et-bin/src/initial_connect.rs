use std::collections::HashMap;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use prost::Message;

use crate::bootstrap::Credentials;
use crate::error::ClientError;

const MAX_HANDSHAKE_PROTO_LEN: i64 = 64 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
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

pub fn connect_initial(endpoint: &Endpoint, credentials: &Credentials) -> Result<(), ClientError> {
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|source| ClientError::ConnectIo {
            operation: "setting the read timeout",
            source,
        })?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|source| ClientError::ConnectIo {
            operation: "setting the write timeout",
            source,
        })?;

    write_proto(&mut stream, &client_request(&credentials.id)).map_err(|source| {
        ClientError::ConnectIo {
            operation: "sending ConnectRequest",
            source,
        }
    })?;
    let response: ConnectResponse = read_proto_limited(&mut stream, MAX_HANDSHAKE_PROTO_LEN)
        .map_err(|source| ClientError::ConnectIo {
            operation: "reading ConnectResponse",
            source,
        })?;
    accept_response(response)?;

    let payload = InitialPayload {
        jumphost: Some(false),
        reversetunnels: Vec::new(),
        environmentvariables: HashMap::new(),
    };
    let mut connection = Connection::new_client(stream, &key);
    connection
        .write_packet(EtPacketType::InitialPayload as u8, &payload.encode_to_vec())
        .map_err(ClientError::Transport)?;
    let packet = connection.read_packet().map_err(ClientError::Transport)?;
    if packet.header() != EtPacketType::InitialResponse as u8 {
        return Err(ClientError::UnexpectedInitialPacket(packet.header()));
    }
    let response =
        InitialResponse::decode(packet.payload()).map_err(ClientError::MalformedInitialResponse)?;
    if let Some(message) = response.error {
        return Err(ClientError::InitialResponseRejected(message));
    }
    Ok(())
}

fn connect_endpoint(endpoint: &Endpoint) -> Result<TcpStream, ClientError> {
    let display = endpoint.to_string();
    let addresses = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|source| ClientError::UnreachableEndpoint {
            endpoint: display.clone(),
            source,
        })?;
    let mut last_error = None;
    for address in addresses.take(MAX_RESOLVED_ADDRESSES) {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
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

fn accept_response(response: ConnectResponse) -> Result<(), ClientError> {
    let status = response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok());
    match status {
        Some(ConnectStatus::NewClient | ConnectStatus::ReturningClient) => Ok(()),
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
