use std::io;
use std::net::TcpStream;
use std::time::Duration;

use et_core::crypto::EPOCH_SALT_BYTES;
use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
};
use et_net::connection::{Connection, RecoveryExchange};
use et_net::handshake::client_handshake;
use prost::Message;

use crate::bootstrap::Credentials;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::resolver::EndpointResolver;

const MAX_ENDPOINT_ADDRESSES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Upstream `et` retries the first TCP/handshake three times, then exits.
const INITIAL_CONNECT_ATTEMPTS: usize = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Server owns an eight-second absolute initialization budget. Do not admit a
/// connection unless the outer budget leaves an additional propagation margin.
const MIN_INITIALIZATION_BUDGET: Duration = Duration::from_secs(9);

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
    connect_initial_with_intent(
        endpoint,
        credentials,
        initial_payload,
        resolver,
        deadline,
        false,
    )
}

pub fn connect_initial_with_intent(
    endpoint: &Endpoint,
    credentials: &Credentials,
    initial_payload: &InitialPayload,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
    reset_intent: bool,
) -> Result<Connection, ClientError> {
    let mut last = String::from("Connect Timeout");
    for attempt in 0..INITIAL_CONNECT_ATTEMPTS {
        match connect_once(
            endpoint,
            credentials,
            initial_payload,
            resolver,
            deadline,
            reset_intent,
        ) {
            Ok(connection) => return Ok(connection),
            Err(error) if error.is_retryable_initial_connect() => {
                last = error.to_string();
                if attempt + 1 == INITIAL_CONNECT_ATTEMPTS {
                    break;
                }
                // Sleep only while the caller's deadline still has room. A
                // live socket that already sent INITIAL_PAYLOAD is not retried.
                if deadline
                    .remaining()
                    .is_some_and(|left| left > Duration::from_secs(1))
                {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(ClientError::InitialConnect {
        endpoint: endpoint.to_string(),
        message: last,
    })
}

fn connect_once(
    endpoint: &Endpoint,
    credentials: &Credentials,
    initial_payload: &InitialPayload,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
    reset_intent: bool,
) -> Result<Connection, ClientError> {
    let admission_deadline = initialization_admission_deadline(deadline)?;
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint, resolver, admission_deadline)?;
    set_stream_timeout(&stream, deadline)?;

    // Resolution/connect may consume their entire admission slice. Revalidate
    // the reserved server-response margin at the actual admission boundary.
    ensure_initialization_budget(deadline)?;
    let response = client_handshake(
        &mut stream,
        &credentials.id,
        &key,
        reset_intent,
        deadline.expires_at(),
    )
    .map_err(|source| classify_handshake_io(deadline, source))?;
    if let InitialStatus::Reset(salt) = accept_response(response)? {
        let mut connection = Connection::new_client(stream, &key);
        let remaining = deadline
            .remaining()
            .ok_or(ClientError::BootstrapTimeout("recovering ET session"))?;
        connection
            .establish_reset(remaining, RecoveryExchange::client(Some(salt)))
            .map_err(|error| transport_error(deadline, "recovering ET session", error))?;
        connection
            .set_io_timeout(None)
            .map_err(ClientError::Transport)?;
        return Ok(connection);
    }

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

fn classify_initial_response_error(message: String) -> ClientError {
    if et_net::forward::decode_forward_timeout(&message).is_some() {
        ClientError::BootstrapTimeout("setting up forwarding")
    } else {
        ClientError::InitialResponseRejected(message)
    }
}

fn ensure_initialization_budget(deadline: Deadline) -> Result<(), ClientError> {
    match deadline.remaining() {
        Some(remaining) if remaining >= MIN_INITIALIZATION_BUDGET => Ok(()),
        _ => Err(ClientError::BootstrapTimeout(
            "reserving the ET initialization budget",
        )),
    }
}

fn initialization_admission_deadline(deadline: Deadline) -> Result<Deadline, ClientError> {
    match deadline.remaining() {
        Some(remaining) if remaining > MIN_INITIALIZATION_BUDGET => {
            Ok(Deadline::after(remaining - MIN_INITIALIZATION_BUDGET))
        }
        _ => Err(ClientError::BootstrapTimeout(
            "reserving the ET initialization budget",
        )),
    }
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
        Err(classify_initial_response_error(message))
    } else {
        Ok(())
    }
}

enum InitialStatus {
    Fresh,
    Reset([u8; EPOCH_SALT_BYTES]),
}

fn classify_handshake_io(deadline: Deadline, source: io::Error) -> ClientError {
    if source.kind() == io::ErrorKind::InvalidData {
        return ClientError::ServerRejected {
            status: None,
            message: Some(source.to_string()),
        };
    }
    connect_error(deadline, "completing the ET handshake", source)
}

fn accept_response(response: ConnectResponse) -> Result<InitialStatus, ClientError> {
    let status = response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok());
    match status {
        Some(ConnectStatus::NewClient) => Ok(InitialStatus::Fresh),
        Some(ConnectStatus::ReturningClient) if response.reset_required.unwrap_or(false) => {
            let salt = response.reset_salt.unwrap_or_default();
            let salt: [u8; EPOCH_SALT_BYTES] =
                salt.try_into().map_err(|_| ClientError::ServerRejected {
                    status: response.status,
                    message: Some("invalid reset decision salt".to_owned()),
                })?;
            Ok(InitialStatus::Reset(salt))
        }
        Some(ConnectStatus::ReturningClient) => Err(ClientError::ReturningSessionRequiresRecovery),
        Some(ConnectStatus::InvalidKey) => Err(ClientError::ServerInvalidKey(response.error)),
        Some(ConnectStatus::MismatchedProtocol) => {
            Err(ClientError::ProtocolMismatch(response.error))
        }
        Some(ConnectStatus::RetryLater) => Err(ClientError::RetryLater),
        None => Err(ClientError::ServerRejected {
            status: response.status,
            message: response.error,
        }),
    }
}

#[cfg(test)]
#[path = "initial_connect_tests.rs"]
mod tests;
