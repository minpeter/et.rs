use std::net::TcpStream;
use std::sync::Arc;

use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
};
use et_net::connection::Connection;
use et_net::handshake::{protocol_matches, read_request, write_response};
use prost::Message;

use crate::runtime_state::{RawSocketGuard, RuntimeCore};
use crate::session::ActiveSession;
use crate::session_table::SessionClaim;

pub(crate) fn handle(stream: TcpStream, core: Arc<RuntimeCore>, _guard: RawSocketGuard) {
    let mut stream = stream;
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(_) => {
            reject(
                &mut stream,
                ConnectStatus::InvalidKey,
                "malformed ConnectRequest",
            );
            return;
        }
    };
    if !protocol_matches(&request) {
        reject(
            &mut stream,
            ConnectStatus::MismatchedProtocol,
            "protocol version does not match server version 6",
        );
        return;
    }
    let Some(id) = request.client_id.filter(|id| valid_id(id)) else {
        reject(&mut stream, ConnectStatus::InvalidKey, "invalid client id");
        return;
    };
    let registration = match core.registry.get(&id) {
        Ok(Some(registration)) => registration,
        Ok(None) | Err(_) => {
            reject(
                &mut stream,
                ConnectStatus::InvalidKey,
                "client is not registered",
            );
            return;
        }
    };
    let claim = match core.sessions.claim(registration) {
        Ok(claim) => claim,
        Err(_) => return,
    };
    match claim {
        SessionClaim::New(start) => handle_new(stream, start),
        SessionClaim::Returning(session) => {
            if send_status(&mut stream, ConnectStatus::ReturningClient).is_ok() {
                let _ = session.recover(stream);
            }
        }
    }
}

fn handle_new(mut stream: TcpStream, start: crate::session_table::SessionStart) {
    if send_status(&mut stream, ConnectStatus::NewClient).is_err() {
        return;
    }
    let mut connection = Connection::new_server(stream, &start.registration().key);
    let packet = match connection.read_packet() {
        Ok(packet) => packet,
        Err(_) => return,
    };
    let payload = if packet.header() == EtPacketType::InitialPayload as u8 {
        InitialPayload::decode(packet.payload()).map_err(|_| "malformed InitialPayload")
    } else {
        Err("expected INITIAL_PAYLOAD header 253")
    };
    let payload = match payload {
        Ok(payload) => payload,
        Err(message) => {
            send_initial_error(&mut connection, message);
            return;
        }
    };
    if payload.jumphost.unwrap_or(false) {
        send_initial_error(&mut connection, "jumphost sessions are not implemented");
        return;
    }
    if !payload.reversetunnels.is_empty() {
        send_initial_error(&mut connection, "reverse tunnels are not implemented");
        return;
    }
    if connection
        .write_packet(
            EtPacketType::InitialResponse as u8,
            &InitialResponse { error: None }.encode_to_vec(),
        )
        .is_err()
    {
        return;
    }
    let _ = start.activate(ActiveSession::new(connection));
}

fn send_initial_error(connection: &mut Connection, message: &str) {
    let _ = connection.write_packet(
        EtPacketType::InitialResponse as u8,
        &InitialResponse {
            error: Some(message.to_owned()),
        }
        .encode_to_vec(),
    );
}

fn send_status(stream: &mut TcpStream, status: ConnectStatus) -> std::io::Result<()> {
    write_response(
        stream,
        &ConnectResponse {
            status: Some(status as i32),
            error: None,
        },
    )
}

fn reject(stream: &mut TcpStream, status: ConnectStatus, message: &str) {
    let _ = write_response(
        stream,
        &ConnectResponse {
            status: Some(status as i32),
            error: Some(message.to_owned()),
        },
    );
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
