use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectResponse, ConnectStatus, TerminalPacketType};
use et_net::connection::Connection;
use et_net::handshake::{client_handshake, LEGACY_SERVER_REATTACH};

use super::{
    connect_endpoint, connect_error, ensure_deadline, set_stream_timeout, transport_error,
    Endpoint, ReconnectOutcome,
};
use crate::bootstrap::Credentials;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::resolver::EndpointResolver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReconnectStatus {
    Recover,
    SessionEnded,
}

pub fn reconnect(
    connection: &mut Connection,
    endpoint: &Endpoint,
    credentials: &Credentials,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<ReconnectOutcome, ClientError> {
    let mut stream = connect_endpoint(endpoint, resolver, deadline)?;
    set_stream_timeout(&stream, deadline)?;
    ensure_deadline(deadline, "sending reconnect ConnectRequest")?;
    let key = passkey_to_key(&credentials.passkey).ok_or(ClientError::InvalidPasskey)?;
    // Same-process reconnect keeps sequence history: resetIntent stays false
    // so the server runs recover instead of an epoch reset (#862).
    let handshake = client_handshake(
        &mut stream,
        &credentials.id,
        &key,
        false,
        deadline.expires_at(),
    )
    .map_err(|source| {
        if source.to_string() == LEGACY_SERVER_REATTACH {
            ClientError::Terminal(LEGACY_SERVER_REATTACH.to_owned())
        } else {
            connect_error(deadline, "completing the reconnect handshake", source)
        }
    })?;
    if handshake.status == ConnectStatus::RetryLater {
        return Err(ClientError::RetryLater);
    }
    let response = ConnectResponse {
        status: Some(handshake.status as i32),
        error: handshake.error,
        ..Default::default()
    };
    match accept_reconnect_response(response)? {
        ReconnectStatus::Recover if handshake.reset_required => {
            // The authenticated handshake selected reset. Rekey this socket
            // instead of replaying the previous epoch.
            let mut reset = Connection::new_client(stream, &key);
            let remaining = remaining_time(deadline, "resetting ET session")?;
            reset
                .reset_in_place(&handshake.reset_salt, remaining)
                .map_err(|error| transport_error(deadline, "resetting ET session", error))?;
            *connection = reset;
            Ok(ReconnectOutcome::Recovered)
        }
        ReconnectStatus::Recover => recover_connection(connection, stream, deadline),
        ReconnectStatus::SessionEnded => Ok(ReconnectOutcome::SessionEnded),
    }
}

fn recover_connection(
    connection: &mut Connection,
    stream: std::net::TcpStream,
    deadline: Deadline,
) -> Result<ReconnectOutcome, ClientError> {
    let remaining = remaining_time(deadline, "recovering ET session")?;
    connection
        .recover_with_timeout(stream, remaining)
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
        Some(ConnectStatus::ReturningClient) => Ok(ReconnectStatus::Recover),
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
