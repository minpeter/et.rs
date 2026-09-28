use std::io;
use std::net::TcpStream;
use std::time::Duration;

use et_core::keys::passkey_to_key;
use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
};
use et_net::connection::Connection;
use et_net::handshake::{client_handshake, LEGACY_SERVER_REATTACH};
use prost::Message;

use crate::bootstrap::Credentials;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::resolver::EndpointResolver;

const MAX_ENDPOINT_ADDRESSES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Upstream #866: give up after failed initial connect attempts.
const CONNECT_ATTEMPTS: usize = 3;
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
    let mut last_error = ClientError::ConnectGaveUp;
    for attempt in 0..CONNECT_ATTEMPTS {
        match connect_initial_once(endpoint, credentials, initial_payload, resolver, deadline) {
            Ok(connection) => return Ok(connection),
            Err(error) if attempt + 1 < CONNECT_ATTEMPTS && retry_initial(&error) => {
                last_error = error;
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

/// Attach or kill a session that is already running. A fresh shell is not started.
pub fn connect_existing(
    endpoint: &Endpoint,
    credentials: &Credentials,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<Connection, ClientError> {
    let mut last_error = ClientError::ConnectGaveUp;
    for attempt in 0..CONNECT_ATTEMPTS {
        match connect_existing_once(endpoint, credentials, resolver, deadline) {
            Ok(connection) => return Ok(connection),
            Err(error) if attempt + 1 < CONNECT_ATTEMPTS && retry_initial(&error) => {
                last_error = error;
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

fn connect_existing_once(
    endpoint: &Endpoint,
    credentials: &Credentials,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<Connection, ClientError> {
    let admission_deadline = initialization_admission_deadline(deadline)?;
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint, resolver, admission_deadline)?;
    set_stream_timeout(&stream, deadline)?;
    ensure_initialization_budget(deadline)?;
    let handshake = client_handshake(
        &mut stream,
        &credentials.id,
        &key,
        true,
        deadline.expires_at(),
    )
    .map_err(|source| handshake_error(deadline, source))?;
    match handshake.status {
        ConnectStatus::RetryLater => Err(ClientError::RetryLater),
        ConnectStatus::InvalidKey => Err(ClientError::ServerInvalidKey(handshake.error)),
        ConnectStatus::MismatchedProtocol => Err(ClientError::ProtocolMismatch(handshake.error)),
        ConnectStatus::NewClient => Err(ClientError::Terminal("session is not running".to_owned())),
        ConnectStatus::ReturningClient => {
            let mut connection = Connection::new_client(stream, &key);
            let remaining = deadline
                .remaining()
                .ok_or(ClientError::BootstrapTimeout("resuming ET session"))?;
            if handshake.reset_required {
                connection
                    .reset_in_place(&handshake.reset_salt, remaining)
                    .map_err(|error| transport_error(deadline, "resuming ET session", error))?;
            } else {
                connection
                    .run_recovery_handshake(remaining)
                    .map_err(|error| transport_error(deadline, "resuming ET session", error))?;
            }
            connection
                .set_io_timeout(None)
                .map_err(ClientError::Transport)?;
            Ok(connection)
        }
    }
}

fn retry_initial(error: &ClientError) -> bool {
    // Retry TCP and `RETRY_LATER` only. Once the payload is on the wire a
    // second `connect()` would be a returning session and drop that payload.
    matches!(
        error,
        ClientError::RetryLater
            | ClientError::UnreachableEndpoint { .. }
            | ClientError::ConnectIo { .. }
            | ClientError::DnsTimeout(_)
            | ClientError::DnsWorker(_)
            | ClientError::DnsWorkerPanicked
    )
}

fn connect_initial_once(
    endpoint: &Endpoint,
    credentials: &Credentials,
    initial_payload: &InitialPayload,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<Connection, ClientError> {
    let admission_deadline = initialization_admission_deadline(deadline)?;
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint, resolver, admission_deadline)?;
    set_stream_timeout(&stream, deadline)?;

    // Resolution/connect may consume their entire admission slice. Revalidate
    // the reserved server-response margin at the actual admission boundary.
    ensure_initialization_budget(deadline)?;
    let handshake = client_handshake(
        &mut stream,
        &credentials.id,
        &key,
        true,
        deadline.expires_at(),
    )
    .map_err(|source| handshake_error(deadline, source))?;
    if handshake.status == ConnectStatus::RetryLater {
        return Err(ClientError::RetryLater);
    }
    accept_response(ConnectResponse {
        status: Some(handshake.status as i32),
        error: handshake.error.clone(),
        ..Default::default()
    })?;
    if handshake.reset_required {
        // Fresh process attaching to a live shell. Reset on this socket and
        // skip INITIAL_PAYLOAD; the remote pty is already running.
        let mut connection = Connection::new_client(stream, &key);
        let remaining = deadline
            .remaining()
            .ok_or(ClientError::BootstrapTimeout("resetting ET session"))?;
        connection
            .reset_in_place(&handshake.reset_salt, remaining)
            .map_err(|error| transport_error(deadline, "resetting ET session", error))?;
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

fn handshake_error(deadline: Deadline, source: io::Error) -> ClientError {
    if source.to_string() == LEGACY_SERVER_REATTACH {
        return ClientError::Terminal(LEGACY_SERVER_REATTACH.to_owned());
    }
    connect_error(deadline, "completing the ET handshake", source)
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
