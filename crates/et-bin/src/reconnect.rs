use et_core::crypto::EPOCH_SALT_BYTES;
use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectResponse, ConnectStatus, TerminalPacketType};
use et_net::connection::{Connection, RecoveryExchange};
use et_net::handshake::client_handshake;

use super::{
    classify_handshake_io, connect_endpoint, ensure_deadline, set_stream_timeout, transport_error,
    Endpoint, ReconnectOutcome,
};
use crate::bootstrap::Credentials;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::resolver::EndpointResolver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReconnectStatus {
    Recover {
        salt: Option<[u8; EPOCH_SALT_BYTES]>,
    },
    SessionEnded,
}

pub fn reconnect(
    connection: &mut Connection,
    endpoint: &Endpoint,
    credentials: &Credentials,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<ReconnectOutcome, ClientError> {
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    let mut stream = connect_endpoint(endpoint, resolver, deadline)?;
    set_stream_timeout(&stream, deadline)?;
    ensure_deadline(deadline, "sending reconnect ConnectRequest")?;
    let response = client_handshake(
        &mut stream,
        &credentials.id,
        &key,
        false,
        deadline.expires_at(),
    )
    .map_err(|source| classify_handshake_io(deadline, source))?;
    match accept_reconnect_response(response)? {
        ReconnectStatus::Recover { salt } => recover_connection(connection, stream, deadline, salt),
        ReconnectStatus::SessionEnded => Ok(ReconnectOutcome::SessionEnded),
    }
}

fn recover_connection(
    connection: &mut Connection,
    stream: std::net::TcpStream,
    deadline: Deadline,
    salt: Option<[u8; EPOCH_SALT_BYTES]>,
) -> Result<ReconnectOutcome, ClientError> {
    let remaining = remaining_time(deadline, "recovering ET session")?;
    // Read the peer catchup before writing ours. A second connect on this
    // same Connection keeps sequence state unless the server required reset.
    connection
        .recover_with_exchange(stream, remaining, RecoveryExchange::client(salt))
        .map_err(|error| transport_error(deadline, "recovering ET session", error))?;
    let remaining = remaining_time(deadline, "authenticating recovery")?;
    connection
        .set_io_timeout(Some(remaining))
        .map_err(ClientError::Transport)?;
    // The proof keep-alive carries a delivery acknowledgement so the server
    // trims its replay backup right after recovery; legacy servers ignore it.
    let ack = connection.keepalive_ack();
    connection
        .write_packet_live(TerminalPacketType::KeepAlive as u8, &ack)
        .map_err(|error| transport_error(deadline, "authenticating recovery", error))?;
    // Any packet that decrypts with the session key authenticates the server;
    // it is requeued and handled by the session loop. Upstream C++ servers
    // send regular traffic here (e.g. terminal output or a keep-alive echo),
    // not a dedicated proof packet.
    connection
        .authenticate_peer(remaining_time(deadline, "verifying recovery proof")?)
        .map_err(|error| transport_error(deadline, "verifying recovery proof", error))?;
    Ok(ReconnectOutcome::Recovered)
}

fn remaining_time(
    deadline: Deadline,
    operation: &'static str,
) -> Result<std::time::Duration, ClientError> {
    deadline
        .remaining()
        .ok_or(ClientError::BootstrapTimeout(operation))
}

pub(super) fn accept_reconnect_response(
    response: ConnectResponse,
) -> Result<ReconnectStatus, ClientError> {
    let status = response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok());
    match status {
        Some(ConnectStatus::ReturningClient) => {
            let salt = if response.reset_required.unwrap_or(false) {
                let bytes = response.reset_salt.unwrap_or_default();
                let salt: [u8; EPOCH_SALT_BYTES] =
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| ClientError::ServerRejected {
                            status: response.status,
                            message: Some("invalid reset decision salt".to_owned()),
                        })?;
                Some(salt)
            } else {
                None
            };
            Ok(ReconnectStatus::Recover { salt })
        }
        Some(ConnectStatus::InvalidKey) => Ok(ReconnectStatus::SessionEnded),
        Some(ConnectStatus::MismatchedProtocol) => {
            Err(ClientError::ProtocolMismatch(response.error))
        }
        Some(ConnectStatus::RetryLater) => Err(ClientError::RetryLater),
        _ => Err(ClientError::ServerRejected {
            status: response.status,
            message: response.error,
        }),
    }
}
