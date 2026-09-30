use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use et_core::crypto::{
    random_bytes, reset_decision_proof, verify_connection_proof, AUTH_CHALLENGE_BYTES,
    EPOCH_SALT_BYTES, KEY_LEN,
};
use et_core::proto::{
    ConnectAuth, ConnectResponse, ConnectStatus, EtPacketType, InitialPayload, InitialResponse,
    TermInit, TerminalBuffer, TerminalPacketType,
};
use et_core::PROTOCOL_VERSION;
use et_net::connection::{Connection, RecoveryExchange, DEFAULT_RECOVERY_TIMEOUT};
use et_net::handshake::{
    protocol_matches, read_request_deadline, reset_intent, supports_challenge, write_response,
    HANDSHAKE_TIMEOUT, MAX_HANDSHAKE_PROTO_LEN,
};
use et_net::local_packet::{write_local_packet, write_local_packet_cancelled};
use prost::Message;

use crate::runtime_state::{PreAuthGuard, RawSocketGuard, RuntimeCore};
use crate::session::ActiveSession;
use crate::session_table::SessionClaim;

// The client caps an individual initialization read at ten seconds. The server
// owns one shorter absolute budget so authenticated failures arrive first.
const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(8);
const INITIALIZATION_RESPONSE_MARGIN: Duration = Duration::from_millis(500);

/// Build the local `TERMINAL_INIT` for etterminal.
///
/// `no_pty` and `command` use the EternalTerminal #854 field numbers. Flow
/// control stays on its relocated tag so it is not confused with `no_pty`.
pub(crate) fn terminal_init_from_payload(
    environment: &std::collections::BTreeMap<String, String>,
    payload: &InitialPayload,
) -> Result<TermInit, &'static str> {
    let pipe_mode = payload.no_pty.unwrap_or(false);
    let no_shell = payload.no_shell.unwrap_or(false);
    if pipe_mode && no_shell {
        return Err("no_pty and no_shell cannot both be set");
    }
    if pipe_mode && payload.command.as_deref().unwrap_or("").is_empty() {
        return Err("no_pty requires a non-empty command");
    }
    Ok(TermInit {
        environmentnames: environment.keys().cloned().collect(),
        environmentvalues: environment.values().cloned().collect(),
        no_pty: pipe_mode.then_some(true),
        command: pipe_mode.then(|| payload.command.clone().unwrap_or_default()),
        no_shell: no_shell.then_some(true),
        hadreversetunnels: (!payload.reversetunnels.is_empty()).then_some(true),
        disconnect_timeout_seconds: payload.disconnect_timeout_seconds,
        flowcontrol: payload.flowcontrol,
    })
}

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
    let initialization_deadline = Instant::now() + INITIALIZATION_TIMEOUT;
    let handshake_deadline = (Instant::now() + HANDSHAKE_TIMEOUT).min(initialization_deadline);
    let request = match read_request_deadline(&mut stream, handshake_deadline) {
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
    let remaining = initialization_deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero()
        || stream
            .set_read_timeout(Some(remaining))
            .and_then(|()| stream.set_write_timeout(Some(remaining)))
            .is_err()
    {
        crate::diag::info(format!("drop {peer}: initialization deadline expired"));
        return;
    }
    let legacy = !supports_challenge(&request);
    let wants_reset = reset_intent(&request);
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
    let mut registration = match core.registry.get(&id) {
        Ok(Some(registration)) => registration,
        Ok(None) | Err(_) => {
            let retry = !legacy
                && core.started.elapsed() < et_core::RECOVERY_GRACE
                && !core.registry.was_removed(&id).unwrap_or(true);
            reject(
                &mut stream,
                if retry {
                    ConnectStatus::RetryLater
                } else {
                    ConnectStatus::InvalidKey
                },
                "client is not registered",
                &peer,
                Some(&id),
            );
            return;
        }
    };
    let challenge = if legacy {
        None
    } else {
        match authenticate_client(
            &mut stream,
            &id,
            &registration.key,
            wants_reset,
            handshake_deadline,
        ) {
            Ok(challenge) => Some(challenge),
            Err(AuthError::Rejected) => {
                reject(
                    &mut stream,
                    ConnectStatus::InvalidKey,
                    "Client authentication failed",
                    &peer,
                    Some(&id),
                );
                return;
            }
            Err(AuthError::Io) => {
                crate::diag::info(format!(
                    "id={id}: authentication exchange failed for {peer}"
                ));
                return;
            }
        }
    };
    if !legacy {
        match core.registry.get(&id) {
            Ok(Some(current)) if current.key == registration.key => registration = current,
            _ => {
                reject(
                    &mut stream,
                    ConnectStatus::InvalidKey,
                    "Client authentication failed",
                    &peer,
                    Some(&id),
                );
                return;
            }
        }
    }
    let decision = challenge.map(|challenge| ConnectDecision {
        challenge,
        key: registration.key,
    });
    let registration_identity = registration.identity();
    #[cfg(test)]
    run_before_raw_assignment_hook(&registration_identity);
    if guard.assign(registration_identity.clone()).is_err() {
        crate::diag::info(format!(
            "drop {peer} id={id}: could not track raw socket for registration"
        ));
        return;
    }
    if !matches!(core.registry.contains(&registration_identity), Ok(true)) {
        crate::diag::info(format!(
            "drop {peer} id={id}: registration disconnected during raw socket assignment"
        ));
        return;
    }
    if !matches!(
        core.sessions.state(&id),
        Ok(Some(crate::session_table::SessionState::Active))
    ) {
        if registration.pty_active {
            if legacy {
                reject(
                    &mut stream,
                    ConnectStatus::InvalidKey,
                    "Client is not registered",
                    &peer,
                    Some(&id),
                );
                return;
            }
            crate::diag::info(format!("id={id}: resuming pty session from {peer}"));
            resume_pty_session(
                stream,
                registration,
                &core,
                &peer,
                pre_auth_guard,
                &mut guard,
                decision.as_ref(),
            );
            return;
        }
        crate::diag::info(format!("id={id}: new client session from {peer}"));
        handle_new(
            stream,
            registration,
            &core,
            &peer,
            pre_auth_guard,
            initialization_deadline,
            &mut guard,
            decision.as_ref(),
        );
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
        SessionClaim::New { .. } => {
            // The active session changed while this connection was being
            // classified. Roll back and let the client retry from a fresh
            // plaintext handshake rather than assigning the wrong status.
            crate::diag::info(format!("id={id}: session changed while classifying {peer}"));
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
            if guard.own_session().is_err() {
                crate::diag::info(format!(
                    "id={id}: drop recover from {peer}: could not protect returning socket"
                ));
                return;
            }
            let reset_salt = wants_reset.then(random_bytes::<EPOCH_SALT_BYTES>);
            let salt_bytes: &[u8] = reset_salt
                .as_ref()
                .map(|salt| salt.as_slice())
                .unwrap_or(&[]);
            if send_decision(
                &mut stream,
                ConnectStatus::ReturningClient,
                None,
                decision.as_ref(),
                &id,
                reset_salt.is_some(),
                salt_bytes,
            )
            .is_err()
            {
                crate::diag::info(format!(
                    "id={id}: failed to send ReturningClient status to {peer}"
                ));
                return;
            }
            #[cfg(test)]
            run_after_returning_status_hook(&id);
            let recovered = if let Some(salt) = reset_salt {
                permit.complete_with(
                    stream,
                    RecoveryExchange {
                        read_peer_catchup_first: false,
                        reset_salt: Some(salt),
                    },
                )
            } else {
                permit.complete(stream)
            };
            match recovered {
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

#[allow(clippy::too_many_arguments)]
fn handle_new(
    mut stream: TcpStream,
    registration: crate::registry::Registration,
    core: &RuntimeCore,
    peer: &str,
    pre_auth_guard: PreAuthGuard,
    initialization_deadline: Instant,
    raw_guard: &mut RawSocketGuard,
    decision: Option<&ConnectDecision>,
) {
    let id = registration.id.clone();
    if send_decision(
        &mut stream,
        ConnectStatus::NewClient,
        None,
        decision,
        &id,
        false,
        &[],
    )
    .is_err()
    {
        crate::diag::info(format!(
            "id={id}: failed to send NewClient status to {peer}"
        ));
        return;
    }
    let remaining = initialization_deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero()
        || stream
            .set_read_timeout(Some(remaining))
            .and_then(|()| stream.set_write_timeout(Some(remaining)))
            .is_err()
    {
        crate::diag::info(format!(
            "id={id}: initialization deadline expired for {peer}"
        ));
        return;
    }
    let claim_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: could not clone initialization socket: {error}"
            ));
            return;
        }
    };
    let mut connection = Connection::new_server(stream, &registration.key);
    let packet = match connection.read_packet_deadline(initialization_deadline) {
        Ok(packet) => packet,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: failed reading INITIAL_PAYLOAD from {peer}: {error}"
            ));
            return;
        }
    };
    // Successfully decrypting this packet is the first cryptographic proof of
    // possession of the registration key. Keep admission occupied until now.
    if raw_guard.authenticate().is_err() {
        crate::diag::info(format!("id={id}: could not mark authenticated socket"));
        return;
    }
    drop(pre_auth_guard);
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
    let start = match core
        .sessions
        .claim(registration, &claim_stream, &core.registry)
    {
        Ok(SessionClaim::New {
            start,
            replaced: None,
        }) => start,
        Ok(SessionClaim::New {
            replaced: Some(replaced),
            ..
        }) => {
            let _ = replaced.shutdown();
            send_initial_error(&mut connection, "session changed during authentication");
            return;
        }
        Ok(SessionClaim::Returning(_)) => {
            send_initial_error(
                &mut connection,
                "session became active during authentication",
            );
            return;
        }
        Err(error) => {
            send_initial_error(&mut connection, &format!("session claim failed: {error}"));
            return;
        }
    };
    // This raw connection now owns the Starting/Active session slot. Lifecycle
    // teardown closes Starting through the slot while preserving an Active
    // transport long enough to drain terminal bytes buffered before HUP.
    if raw_guard.own_session().is_err() {
        send_initial_error(&mut connection, "could not track session owner");
        return;
    }
    if payload.jumphost.unwrap_or(false) {
        crate::diag::info(format!("id={id}: jumphost session from {peer}"));
        run_jumphost(
            connection,
            start,
            core,
            payload,
            &id,
            peer,
            initialization_deadline,
        );
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
    let (forwarder, forward_environment) =
        match et_net::forward::Forwarder::start_with_user_deadline(
            payload.reversetunnels.clone(),
            Some(owner),
            initialization_deadline - INITIALIZATION_RESPONSE_MARGIN,
            core.forward_resolver.clone(),
        ) {
            Ok(started) => started,
            Err(error) => {
                crate::diag::info(format!(
                    "id={id}: reverse-tunnel setup failed for {peer}: {error}"
                ));
                let message = error.to_string();
                if error.is_timeout() {
                    send_initial_error(
                        &mut connection,
                        &et_net::forward::encode_forward_timeout(&message),
                    );
                } else {
                    send_initial_error(&mut connection, &message);
                }
                return;
            }
        };
    if Instant::now() >= initialization_deadline {
        send_initial_error(
            &mut connection,
            "initialization deadline elapsed during forwarding",
        );
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
    let term_init = match terminal_init_from_payload(&environment, &payload) {
        Ok(term_init) => term_init,
        Err(message) => {
            send_initial_error(&mut connection, message);
            return;
        }
    };
    let init_packet = et_core::packet::Packet::new(
        TerminalPacketType::TerminalInit as u8,
        term_init.encode_to_vec(),
    );
    if write_initial_local_packet(&mut terminal, &init_packet, initialization_deadline).is_err() {
        send_initial_error(
            &mut connection,
            "terminal disconnected during initialization",
        );
        return;
    }
    if start.registration().startup_ack {
        if let Err(error) = wait_for_terminal_startup(
            &core.registry,
            start.registration(),
            initialization_deadline,
        ) {
            crate::diag::info(format!("id={id}: terminal startup failed: {error}"));
            send_initial_error(&mut connection, &error);
            let _ = terminal.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
    if Instant::now() >= initialization_deadline {
        send_initial_error(
            &mut connection,
            "initialization deadline elapsed before response",
        );
        return;
    }
    if connection
        .write_packet_strict(
            EtPacketType::InitialResponse as u8,
            &InitialResponse { error: None }.encode_to_vec(),
        )
        .is_err()
    {
        crate::diag::info(format!(
            "id={id}: failed writing INITIAL_RESPONSE to {peer}"
        ));
        return;
    }
    let active = match ActiveSession::new_with_pipe(
        connection,
        &terminal,
        payload.flowcontrol,
        payload.no_pty.unwrap_or(false),
    ) {
        Ok(active) => active,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: could not create active session for {peer}: {error}"
            ));
            return;
        }
    };
    let active = Arc::new(active);
    active.set_forward_exit_status(payload.supports_exit_status.unwrap_or(false));
    active.set_disconnect_timeout(Some(
        payload
            .disconnect_timeout_seconds
            .unwrap_or(core.disconnect_timeout_seconds),
    ));
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
    initialization_deadline: Instant,
) {
    if Instant::now() >= initialization_deadline {
        send_initial_error(&mut connection, "jumphost initialization deadline elapsed");
        return;
    }
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
    if terminal.set_nonblocking(true).is_err()
        || write_initial_local_packet(&mut terminal, &init_packet, initialization_deadline).is_err()
    {
        crate::diag::info(format!("id={id}: jumphost failed sending JUMPHOST_INIT"));
        send_initial_error(
            &mut connection,
            "jumphost disconnected during initialization",
        );
        return;
    }
    if start.registration().startup_ack {
        if let Err(error) = wait_for_terminal_startup(
            &core.registry,
            start.registration(),
            initialization_deadline,
        ) {
            crate::diag::info(format!("id={id}: jumphost startup failed: {error}"));
            send_initial_error(&mut connection, &error);
            let _ = terminal.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
    let remaining = match initialization_deadline.checked_duration_since(Instant::now()) {
        Some(remaining) => remaining,
        None => {
            send_initial_error(&mut connection, "jumphost initialization deadline elapsed");
            return;
        }
    };
    if terminal
        .set_nonblocking(false)
        .and_then(|()| terminal.set_read_timeout(Some(remaining)))
        .and_then(|()| terminal.set_write_timeout(Some(remaining)))
        .is_err()
    {
        send_initial_error(&mut connection, "jumphost initialization deadline elapsed");
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
    if Instant::now() >= initialization_deadline {
        send_initial_error(
            &mut connection,
            "initialization deadline elapsed before response",
        );
        return;
    }
    if connection
        .write_packet_strict(
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
    active.set_forward_exit_status(payload.supports_exit_status.unwrap_or(false));
    active.set_disconnect_timeout(payload.disconnect_timeout_seconds);
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

fn wait_for_terminal_startup(
    registry: &crate::registry::Registry,
    registration: &crate::registry::Registration,
    deadline: Instant,
) -> Result<(), String> {
    registry
        .wait_for_startup(registration, deadline)
        .map_err(|error| format!("terminal startup acknowledgement failed: {error}"))
}

fn write_initial_local_packet(
    stream: &mut et_net::local::LocalStream,
    packet: &et_core::packet::Packet,
    deadline: Instant,
) -> std::io::Result<()> {
    let result = write_local_packet_cancelled(stream, packet, &AtomicBool::new(false), deadline);
    if result.is_err() {
        // A cancelled framed write may have emitted only a prefix. Poison this
        // registration generation so the router retires it instead of letting
        // a later initialization append to and reuse the partial frame.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    result
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

struct ConnectDecision {
    challenge: Vec<u8>,
    key: [u8; KEY_LEN],
}

enum AuthError {
    Rejected,
    Io,
}

fn authenticate_client(
    stream: &mut TcpStream,
    id: &str,
    key: &[u8; KEY_LEN],
    reset_intent: bool,
    deadline: Instant,
) -> Result<Vec<u8>, AuthError> {
    let challenge = random_bytes::<AUTH_CHALLENGE_BYTES>().to_vec();
    write_response(
        stream,
        &ConnectResponse {
            status: None,
            error: None,
            auth_challenge: Some(challenge.clone()),
            reset_required: None,
            reset_proof: None,
            reset_salt: None,
        },
    )
    .map_err(|_| AuthError::Io)?;
    let auth: ConnectAuth =
        et_net::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)
            .map_err(|_| AuthError::Io)?;
    let proof = auth.proof.unwrap_or_default();
    if verify_connection_proof(&proof, key, id, PROTOCOL_VERSION, &challenge, reset_intent) {
        Ok(challenge)
    } else {
        Err(AuthError::Rejected)
    }
}

fn send_decision(
    stream: &mut TcpStream,
    status: ConnectStatus,
    error: Option<String>,
    decision: Option<&ConnectDecision>,
    id: &str,
    reset_required: bool,
    salt: &[u8],
) -> std::io::Result<()> {
    let mut response = ConnectResponse {
        status: Some(status as i32),
        error,
        auth_challenge: None,
        reset_required: None,
        reset_proof: None,
        reset_salt: None,
    };
    if let Some(decision) = decision {
        let proof = reset_decision_proof(
            &decision.key,
            id,
            PROTOCOL_VERSION,
            &decision.challenge,
            status as i32,
            reset_required,
            salt,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        response.reset_required = Some(reset_required);
        if !salt.is_empty() {
            response.reset_salt = Some(salt.to_vec());
        }
        response.reset_proof = Some(proof.to_vec());
    }
    write_response(stream, &response)
}

fn resume_pty_session(
    mut stream: TcpStream,
    registration: crate::registry::Registration,
    core: &RuntimeCore,
    peer: &str,
    pre_auth_guard: PreAuthGuard,
    raw_guard: &mut RawSocketGuard,
    decision: Option<&ConnectDecision>,
) {
    let id = registration.id.clone();
    let salt = random_bytes::<EPOCH_SALT_BYTES>();
    if send_decision(
        &mut stream,
        ConnectStatus::ReturningClient,
        None,
        decision,
        &id,
        true,
        &salt,
    )
    .is_err()
    {
        crate::diag::info(format!("id={id}: failed to send resume status to {peer}"));
        return;
    }
    if raw_guard.authenticate().is_err() {
        return;
    }
    drop(pre_auth_guard);
    let claim_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(error) => {
            crate::diag::info(format!("id={id}: could not clone resume socket: {error}"));
            return;
        }
    };
    let mut connection = Connection::new_server(stream, &registration.key);
    if let Err(error) = connection.establish_reset(
        DEFAULT_RECOVERY_TIMEOUT,
        RecoveryExchange {
            read_peer_catchup_first: false,
            reset_salt: Some(salt),
        },
    ) {
        crate::diag::info(format!("id={id}: resume reset failed for {peer}: {error}"));
        return;
    }
    if registration.had_reverse_tunnels {
        let notice = TerminalBuffer {
            buffer: Some(
                b"et: port forwards were not restored across the server restart; reconnect to re-establish\r\n"
                    .to_vec(),
            ),
            is_stderr: None,
        };
        if connection
            .write_packet(
                TerminalPacketType::TerminalBuffer as u8,
                &notice.encode_to_vec(),
            )
            .is_err()
        {
            crate::diag::info(format!("id={id}: could not write restart forward notice"));
        }
    }
    let start = match core
        .sessions
        .claim(registration.clone(), &claim_stream, &core.registry)
    {
        Ok(SessionClaim::New {
            start,
            replaced: None,
        }) => start,
        Ok(_) => {
            crate::diag::info(format!("id={id}: session changed during resume"));
            return;
        }
        Err(error) => {
            crate::diag::info(format!("id={id}: resume claim failed: {error}"));
            return;
        }
    };
    if raw_guard.own_session().is_err() {
        return;
    }
    let terminal = match core.registry.clone_stream(&registration) {
        Ok(terminal) => terminal,
        Err(error) => {
            crate::diag::info(format!(
                "id={id}: could not clone resumed terminal: {error}"
            ));
            return;
        }
    };
    let active = match ActiveSession::new(connection, &terminal, None) {
        Ok(active) => active,
        Err(error) => {
            crate::diag::info(format!("id={id}: could not resume session: {error}"));
            return;
        }
    };
    let active = Arc::new(active);
    active.set_disconnect_timeout(Some(
        registration
            .disconnect_timeout_seconds
            .unwrap_or(core.disconnect_timeout_seconds),
    ));
    active.start_flow_writer();
    if start.activate(active.clone()).is_err() {
        return;
    }
    let Ok(forwarder) = et_net::forward::Forwarder::start(Vec::new()) else {
        let _ = active.shutdown();
        return;
    };
    crate::diag::info(format!(
        "id={id}: resumed terminal bridge running for {peer}"
    ));
    let _ = crate::terminal_bridge::run(active.clone(), terminal, forwarder);
    let _ = active.finish_terminal();
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
            auth_challenge: None,
            reset_required: None,
            reset_proof: None,
            reset_salt: None,
        },
    );
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
struct RawAssignmentHook {
    identity: crate::registry::RegistrationIdentity,
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
fn raw_assignment_hook() -> &'static std::sync::Mutex<Option<RawAssignmentHook>> {
    static HOOK: std::sync::OnceLock<std::sync::Mutex<Option<RawAssignmentHook>>> =
        std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn install_raw_assignment_hook(
    identity: crate::registry::RegistrationIdentity,
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
) {
    *raw_assignment_hook().lock().unwrap() = Some(RawAssignmentHook {
        identity,
        reached,
        release,
    });
}

#[cfg(test)]
fn run_before_raw_assignment_hook(identity: &crate::registry::RegistrationIdentity) {
    let hook = {
        let mut installed = raw_assignment_hook().lock().unwrap();
        if installed
            .as_ref()
            .is_some_and(|hook| hook.identity.same_generation(identity))
        {
            installed.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook.reached.send(()).unwrap();
        hook.release.recv().unwrap();
    }
}

#[cfg(test)]
struct ReturningStatusHook {
    id: String,
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
fn returning_status_hook() -> &'static std::sync::Mutex<Option<ReturningStatusHook>> {
    static HOOK: std::sync::OnceLock<std::sync::Mutex<Option<ReturningStatusHook>>> =
        std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn install_returning_status_hook(
    id: &str,
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
) {
    *returning_status_hook().lock().unwrap() = Some(ReturningStatusHook {
        id: id.to_owned(),
        reached,
        release,
    });
}

#[cfg(test)]
fn run_after_returning_status_hook(id: &str) {
    let hook = {
        let mut installed = returning_status_hook().lock().unwrap();
        if installed.as_ref().is_some_and(|hook| hook.id == id) {
            installed.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook.reached.send(()).unwrap();
        hook.release.recv().unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::router::{Router, RouterEvent};
    use et_core::proto::TerminalUserInfo;
    use prost::Message;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    const TEST_ID: &str = "initialframe0001";
    const TEST_KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

    fn register(path: &Path) -> UnixStream {
        let mut terminal = UnixStream::connect(path).unwrap();
        let packet = et_core::packet::Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            TerminalUserInfo {
                id: Some(TEST_ID.to_owned()),
                passkey: Some(TEST_KEY.to_owned()),
                uid: Some(i64::from(rustix::process::getuid().as_raw())),
                gid: Some(i64::from(rustix::process::getgid().as_raw())),
                fd: None,
                ptyactive: None,
                hadreversetunnels: None,
                disconnect_timeout_seconds: None,
            }
            .encode_to_vec(),
        );
        et_net::local_packet::write_local_packet(&mut terminal, &packet).unwrap();
        terminal
    }

    fn interrupted_initial_write_retires_registration(header: TerminalPacketType) {
        let directory = std::env::temp_dir().join(format!(
            "et-interrupted-init-{}-{}",
            std::process::id(),
            header as i32
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("router.sock");
        let selected = crate::path::select_router_path_for(
            rustix::process::getuid().as_raw(),
            Some(&path),
            None,
            None,
        )
        .unwrap();
        let registry = crate::registry::Registry::new();
        let mut router = Router::start(selected, registry.clone()).unwrap();
        let mut terminal = register(&path);
        assert_eq!(
            router.recv_event_timeout(Duration::from_secs(1)).unwrap(),
            RouterEvent::Registered {
                id: TEST_ID.to_owned()
            }
        );

        let registration = registry.get(TEST_ID).unwrap().unwrap();
        let mut writer = registry.clone_stream(&registration).unwrap();
        writer.set_nonblocking(true).unwrap();
        let fill = [0u8; 8192];
        loop {
            match writer.write(&fill) {
                Ok(0) => panic!("local stream closed while being saturated"),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not saturate local stream: {error}"),
            }
        }
        let packet = et_core::packet::Packet::new(header as u8, vec![1; 1024]);
        let error = write_initial_local_packet(
            &mut writer,
            &packet,
            Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        assert_eq!(
            router.recv_event_timeout(Duration::from_secs(1)).unwrap(),
            RouterEvent::Disconnected {
                id: TEST_ID.to_owned()
            }
        );
        assert!(registry.get(TEST_ID).unwrap().is_none());

        terminal
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0u8; 8192];
        loop {
            match terminal.read(&mut bytes) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    panic!("poisoned local stream remained open: {error}")
                }
                Err(error) => panic!("unexpected local stream error: {error}"),
            }
        }

        let _fresh_terminal = register(&path);
        assert_eq!(
            router.recv_event_timeout(Duration::from_secs(1)).unwrap(),
            RouterEvent::Registered {
                id: TEST_ID.to_owned()
            }
        );
        assert!(registry.get(TEST_ID).unwrap().is_some());
        router.shutdown().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn interrupted_terminal_init_retires_registration_generation() {
        interrupted_initial_write_retires_registration(TerminalPacketType::TerminalInit);
    }

    #[test]
    fn interrupted_jumphost_init_retires_registration_generation() {
        interrupted_initial_write_retires_registration(TerminalPacketType::JumphostInit);
    }
}
