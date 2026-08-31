use std::net::TcpStream;
use std::sync::Arc;

use et_core::proto::{
    ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse, TermInit,
    TerminalPacketType,
};
use et_net::connection::Connection;
use et_net::handshake::{
    protocol_matches, read_request_deadline, write_response, HANDSHAKE_TIMEOUT,
};
use et_net::local_packet::write_local_packet;
use prost::Message;

use crate::runtime_state::{PreAuthGuard, RawSocketGuard, RuntimeCore};
use crate::session::ActiveSession;
use crate::session_table::SessionClaim;

const JUMPHOST_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub(crate) fn handle(
    stream: TcpStream,
    core: Arc<RuntimeCore>,
    mut guard: RawSocketGuard,
    pre_auth_guard: PreAuthGuard,
) {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    crate::diag::verbose(1, format!("accepted TCP connection from {peer}"));
    let mut stream = stream;
    let request =
        match read_request_deadline(&mut stream, std::time::Instant::now() + HANDSHAKE_TIMEOUT) {
            Ok(request) => request,
            Err(error) => {
                crate::diag::verbose(1, format!("malformed ConnectRequest from {peer}: {error}"));
                reject(
                    &mut stream,
                    ConnectStatus::InvalidKey,
                    "malformed ConnectRequest",
                    &peer,
                    None,
                );
                return;
            }
        };
    drop(pre_auth_guard);
    if !protocol_matches(&request) {
        let client_id = request
            .client_id
            .as_deref()
            .filter(|id| valid_id(id))
            .map(crate::diag::sanitize_external_field);
        reject(
            &mut stream,
            ConnectStatus::MismatchedProtocol,
            "protocol version does not match server version 6",
            &peer,
            client_id.as_deref(),
        );
        return;
    }
    let Some(id) = request.client_id.filter(|id| valid_id(id)) else {
        reject(
            &mut stream,
            ConnectStatus::InvalidKey,
            "invalid client id",
            &peer,
            None,
        );
        return;
    };
    let registration = match core.registry.get(&id) {
        Ok(Some(registration)) => registration,
        Ok(None) | Err(_) => {
            reject(
                &mut stream,
                ConnectStatus::InvalidKey,
                "client is not registered",
                &peer,
                Some(&id),
            );
            return;
        }
    };
    if guard.assign(registration.identity()).is_err() {
        crate::diag::info(format!(
            "drop {peer} id={id}: could not track raw socket for registration"
        ));
        return;
    }
    let claim = match core.sessions.claim(registration, &stream, &core.registry) {
        Ok(claim) => claim,
        Err(crate::session_table::SessionTableError::ObsoleteRegistration) => {
            reject(
                &mut stream,
                ConnectStatus::InvalidKey,
                "client registration disconnected",
                &peer,
                Some(&id),
            );
            return;
        }
        Err(error) => {
            crate::diag::info(format!(
                "drop {peer} id={id}: session claim failed: {error}"
            ));
            return;
        }
    };
    match claim {
        SessionClaim::New { start, replaced } => {
            if replaced.is_some() {
                crate::diag::info(format!(
                    "id={id}: replacing existing session for new client from {peer}"
                ));
            }
            if replaced.is_some_and(|connection| connection.shutdown().is_err()) {
                crate::diag::info(format!(
                    "id={id}: failed to shut down replaced session; aborting new client"
                ));
                return;
            }
            crate::diag::info(format!("id={id}: new client session from {peer}"));
            handle_new(stream, start, &core, &id, &peer);
        }
        SessionClaim::Returning(session) => {
            crate::diag::info(format!("id={id}: returning client reconnect from {peer}"));
            // Take the single-flight permit *before* ReturningClient so a
            // concurrent recover does not commit the client to sequence
            // exchange and then fail with RecoverBusy / silent hang.
            let permit = match session.try_begin_recover() {
                Ok(permit) => permit,
                Err(crate::session::SessionError::RecoverBusy) => {
                    crate::diag::info(format!(
                        "id={id}: drop concurrent recover from {peer}: session recover busy"
                    ));
                    // No ConnectResponse: the client sees EOF/reset and
                    // retries without burning a recovery exchange timeout.
                    return;
                }
                Err(error) => {
                    crate::diag::info(format!(
                        "id={id}: drop recover from {peer}: could not begin recover: {error}"
                    ));
                    return;
                }
            };
            if send_status(&mut stream, ConnectStatus::ReturningClient).is_err() {
                crate::diag::info(format!(
                    "id={id}: failed to send ReturningClient status to {peer}"
                ));
                return;
            }
            match permit.complete(stream) {
                Ok(()) => {
                    crate::diag::info(format!("id={id}: session recover accepted from {peer}"))
                }
                Err(error) => crate::diag::info(format!(
                    "id={id}: session recover failed from {peer}: {error}"
                )),
            }
        }
    }
}

fn handle_new(
    mut stream: TcpStream,
    start: crate::session_slot::SessionStart,
    core: &RuntimeCore,
    id: &str,
    peer: &str,
) {
    let initialization_deadline = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    if send_status(&mut stream, ConnectStatus::NewClient).is_err() {
        crate::diag::info(format!(
            "id={id}: failed to send NewClient status to {peer}"
        ));
        return;
    }
    let mut connection = Connection::new_server(stream, &start.registration().key);
    let packet = match connection.read_packet_until(initialization_deadline) {
        Ok(packet) => packet,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: failed reading INITIAL_PAYLOAD from {peer}: {error}"
            ));
            return;
        }
    };
    let payload = if packet.header() == EtPacketType::InitialPayload as u8 {
        InitialPayload::decode(packet.payload()).map_err(|_| "malformed InitialPayload")
    } else {
        Err("expected INITIAL_PAYLOAD header 253")
    };
    let payload = match payload {
        Ok(payload) => payload,
        Err(message) => {
            crate::diag::info(format!(
                "id={id}: rejecting InitialPayload from {peer}: {message}"
            ));
            send_initial_error(&mut connection, message);
            return;
        }
    };
    if payload.jumphost.unwrap_or(false) {
        crate::diag::info(format!("id={id}: jumphost session from {peer}"));
        run_jumphost(connection, start, core, payload, id, peer);
        return;
    }
    if payload.reversetunnels.len() > et_net::forward::MAX_SESSION_LISTENERS {
        send_initial_error(&mut connection, "reverse listener limit exceeded");
        return;
    }
    let owner = {
        let registration = start.registration();
        (registration.uid, registration.gid)
    };
    let (forwarder, forward_environment) = match et_net::forward::Forwarder::start_with_user_until(
        payload.reversetunnels.clone(),
        owner,
        initialization_deadline,
    ) {
        Ok(started) => started,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: reverse-tunnel setup failed for {peer}: {error}"
            ));
            send_initial_error(&mut connection, &error.to_string());
            return;
        }
    };
    if connection
        .write_packet_live_until(
            EtPacketType::InitialResponse as u8,
            &InitialResponse { error: None }.encode_to_vec(),
            initialization_deadline,
        )
        .is_err()
    {
        crate::diag::info(format!(
            "id={id}: failed writing INITIAL_RESPONSE to {peer}"
        ));
        return;
    }
    let mut terminal = match core.registry.clone_stream(start.registration()) {
        Ok(terminal) => terminal,
        Err(error) => {
            crate::diag::info(format!("id={id}: could not clone terminal stream: {error}"));
            return;
        }
    };
    // Merge the client-supplied environment with variables created for
    // named-pipe forwards; upstream stores them in a sorted std::map.
    let mut environment: std::collections::BTreeMap<String, String> = payload
        .environmentvariables
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    environment.extend(forward_environment);
    let term_init = TermInit {
        environmentnames: environment.keys().cloned().collect(),
        environmentvalues: environment.values().cloned().collect(),
        flowcontrol: payload.flowcontrol,
    };
    let init_packet = et_core::packet::Packet::new(
        TerminalPacketType::TerminalInit as u8,
        term_init.encode_to_vec(),
    );
    if write_local_packet(&mut terminal, &init_packet).is_err() {
        return;
    }
    let active = match ActiveSession::new(connection, &terminal, payload.flowcontrol) {
        Ok(active) => active,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: could not create active session for {peer}: {error}"
            ));
            return;
        }
    };
    let active = Arc::new(active);
    active.start_flow_writer();
    if start.activate(active.clone()).is_err() {
        crate::diag::info(format!("id={id}: could not activate session for {peer}"));
        return;
    }
    crate::diag::info(format!("id={id}: terminal bridge running for {peer}"));
    let _ = crate::terminal_bridge::run(active.clone(), terminal, forwarder);
    crate::diag::info(format!("id={id}: terminal bridge ended for {peer}"));
    let _ = active.finish_terminal();
}

/// Upstream `TerminalServer::runJumpHost`: answer the initial response, hand
/// the payload to the registered `etterminal --jump` process through a
/// JUMPHOST_INIT packet, then relay packets verbatim in both directions.
fn run_jumphost(
    mut connection: Connection,
    start: crate::session_slot::SessionStart,
    core: &RuntimeCore,
    payload: InitialPayload,
    id: &str,
    peer: &str,
) {
    let mut terminal = match core.registry.clone_stream(start.registration()) {
        Ok(terminal) => terminal,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: jumphost could not clone terminal stream: {error}"
            ));
            return;
        }
    };
    let init_packet = et_core::packet::Packet::new(
        TerminalPacketType::JumphostInit as u8,
        payload.encode_to_vec(),
    );
    if terminal
        .set_nonblocking(false)
        .and_then(|()| terminal.set_read_timeout(Some(JUMPHOST_RESPONSE_TIMEOUT)))
        .and_then(|()| terminal.set_write_timeout(Some(JUMPHOST_RESPONSE_TIMEOUT)))
        .is_err()
        || write_local_packet(&mut terminal, &init_packet).is_err()
    {
        crate::diag::info(format!("id={id}: jumphost failed sending JUMPHOST_INIT"));
        return;
    }
    let response_packet = match et_net::local_packet::read_local_packet(&mut terminal) {
        Ok(packet)
            if !packet.is_encrypted()
                && packet.header() == TerminalPacketType::JumphostInit as u8 =>
        {
            packet
        }
        Ok(_) | Err(_) => {
            crate::diag::info(format!(
                "id={id}: jumphost received invalid destination response"
            ));
            return;
        }
    };
    let response = InitialResponse::decode(response_packet.payload()).ok();
    if connection
        .write_packet_live(
            EtPacketType::InitialResponse as u8,
            response_packet.payload(),
        )
        .is_err()
    {
        crate::diag::info(format!(
            "id={id}: jumphost failed writing destination INITIAL_RESPONSE to {peer}"
        ));
        return;
    }
    let Some(response) = response else {
        let _ = terminal.shutdown(std::net::Shutdown::Both);
        return;
    };
    if response.error.is_some() {
        if connection.set_io_timeout(Some(HANDSHAKE_TIMEOUT)).is_err() {
            return;
        }
        let acknowledged = connection.read_packet().is_ok_and(|packet| {
            packet.header() == EtPacketType::Heartbeat as u8 && packet.payload().is_empty()
        });
        if !acknowledged
            || write_local_packet(
                &mut terminal,
                &et_core::packet::Packet::new(EtPacketType::Heartbeat as u8, Vec::new()),
            )
            .is_err()
            || connection.set_io_timeout(None).is_err()
        {
            let _ = terminal.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
    if terminal.set_read_timeout(None).is_err()
        || terminal.set_write_timeout(None).is_err()
        || terminal.set_nonblocking(true).is_err()
    {
        return;
    }
    let active = match ActiveSession::new(connection, &terminal, payload.flowcontrol) {
        Ok(active) => active,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: jumphost could not create active session: {error}"
            ));
            return;
        }
    };
    let active = Arc::new(active);
    active.start_flow_writer();
    if start.activate(active.clone()).is_err() {
        crate::diag::info(format!("id={id}: jumphost could not activate session"));
        return;
    }
    // A jumphost session owns no local forwarding: the destination side does.
    let Ok(forwarder) = et_net::forward::Forwarder::start(Vec::new()) else {
        crate::diag::info(format!("id={id}: jumphost forwarder start failed"));
        let _ = active.shutdown();
        return;
    };
    crate::diag::info(format!("id={id}: jumphost bridge running for {peer}"));
    let _ = crate::terminal_bridge::run_mode(
        active.clone(),
        terminal,
        forwarder,
        crate::terminal_bridge::BridgeMode::Jumphost,
    );
    crate::diag::info(format!("id={id}: jumphost bridge ended for {peer}"));
    let _ = active.finish_terminal();
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

fn reject(
    stream: &mut TcpStream,
    status: ConnectStatus,
    message: &str,
    peer: &str,
    client_id: Option<&str>,
) {
    let id = client_id.unwrap_or("-");
    crate::diag::info(format!(
        "reject {peer} id={id} status={status:?}: {message}"
    ));
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
