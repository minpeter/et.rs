use et_net::local::LocalStream;
use std::io::{self, Read};
use std::sync::Arc;

use et_core::packet::Packet;
use et_core::proto::TerminalPacketType;
use et_net::connection::ConnError;
use et_net::forward::{is_forward_packet, Forwarder};
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::time::Timespec;

use crate::session::{ActiveSession, SessionError, SessionWriteError};

const READ_BUFFER: usize = 16 * 1024;
const CLIENT_READ_BATCH: usize = 64;

/// Which upstream server loop this bridge reproduces.
///
/// `Terminal` mirrors `TerminalServer::runTerminal`: terminal output must be
/// TERMINAL_BUFFER, client packets are dispatched by type, and port
/// forwarding is handled locally. `Jumphost` mirrors
/// `TerminalServer::runJumpHost`: both directions are relayed verbatim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeMode {
    Terminal,
    Jumphost,
}

pub(crate) fn run(
    session: Arc<ActiveSession>,
    terminal: LocalStream,
    forwarder: Forwarder,
) -> Result<(), SessionError> {
    run_mode(session, terminal, forwarder, BridgeMode::Terminal)
}

pub(crate) fn run_mode(
    session: Arc<ActiveSession>,
    terminal: LocalStream,
    forwarder: Forwarder,
    mode: BridgeMode,
) -> Result<(), SessionError> {
    #[cfg(unix)]
    return run_mode_poll(session, terminal, forwarder, mode);
    #[cfg(windows)]
    return run_mode_windows(session, terminal, forwarder, mode);
}

/// Readiness-driven bridge, mirroring upstream's `select()` loop.
///
/// Client TCP loss (sleep, Wi-Fi flap, NAT drop) must **not** end the bridge.
/// The terminal stays registered and the session stays Active so a returning
/// client can recover. Only terminal EOF/error or an explicit session shutdown
/// tears the loop down.
#[cfg(unix)]
fn run_mode_poll(
    session: Arc<ActiveSession>,
    mut terminal: LocalStream,
    forwarder: Forwarder,
    mode: BridgeMode,
) -> Result<(), SessionError> {
    terminal.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut wake = session.take_wake_reader()?;
    wake.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut decoder = LocalPacketDecoder::new();
    let (mut connected, mut connection_generation) = session.connection_state()?;
    session.note_bridge_generation(connection_generation)?;
    // A forwarding packet the worker had no room for. While it is held, no
    // further client packets are read (ordering) and the client socket is not
    // watched for readability (it would busy-loop the poll).
    let mut pending_forward: Option<Packet> = None;
    // An outbound forwarding packet that could not fit in the disconnected
    // replay buffer. Keep ownership until recovery restores write capacity.
    let mut pending_outbound: Option<Packet> = None;
    // A complete terminal packet already read from the local stream. Retain
    // ownership across backpressure instead of dropping it or reading ahead.
    let mut pending_terminal: Option<Packet> = None;
    let mut terminal_closing = false;
    let mut terminal_eof = false;
    let mut client_buffered = false;
    loop {
        let mut resume_outbound_drain = false;
        if session.is_shutting_down() {
            return Ok(());
        }
        // Retry the held packet first: draining the forwarder's outbound
        // queue below is what frees worker capacity, so this makes progress
        // every iteration instead of deadlocking on a blocking send.
        if let Some(packet) = pending_forward.take() {
            pending_forward = forwarder.try_receive(packet).map_err(forward_error)?;
        }
        if let Some(packet) = pending_outbound.take() {
            pending_outbound =
                send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
            resume_outbound_drain = pending_outbound.is_none();
        }
        if let Some(packet) = pending_terminal.take() {
            pending_terminal =
                send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
        }
        let (client, polled_generation) = if connected {
            match session.try_clone_stream() {
                Ok((stream, generation)) => (Some(stream), Some(generation)),
                // Cloning a dead socket is a soft disconnect, not session death.
                Err(_) => {
                    let observed_generation = connection_generation;
                    note_client_drop(
                        &session,
                        &mut connected,
                        &mut connection_generation,
                        observed_generation,
                    )?;
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        let accept_terminal =
            pending_terminal.is_none() && session.can_buffer_write((READ_BUFFER * 2) as i64)?;
        // When the client is down, poll with a short timeout so recovery wakes
        // (via the wake pipe) are still processed promptly and we re-check
        // `session.connected()` after recover installs a new stream.
        let (terminal_events, wake_events, forward_events, client_events) = wait(
            &terminal,
            &wake,
            forwarder.wake().map_err(forward_error)?,
            client.as_ref(),
            accept_terminal,
            pending_forward.is_some() || pending_outbound.is_some() || !connected,
            client_buffered,
        )?;
        let client_events_are_stale = wake_events.intersects(PollFlags::IN | PollFlags::HUP);
        if client_events_are_stale {
            drain(&mut wake)?;
            if session.is_shutting_down() {
                return Ok(());
            }
            (connected, connection_generation) = session.connection_state()?;
            session.note_bridge_generation(connection_generation)?;
        }
        terminal_closing |= terminal_events.intersects(PollFlags::HUP | PollFlags::ERR);
        if pending_terminal.is_none()
            && !terminal_eof
            && (terminal_closing || terminal_events.contains(PollFlags::IN))
        {
            match read_terminal_packet(&mut terminal, &mut decoder) {
                Ok(Some(packet)) => {
                    let packet = if mode == BridgeMode::Terminal {
                        validate_terminal_output(&packet)?;
                        packet
                    } else {
                        jumphost_terminal_packet(&session, packet)?
                    };
                    decoder = LocalPacketDecoder::new();
                    pending_terminal =
                        send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
                }
                Ok(None) => {}
                Err(SessionError::Io(error))
                    if terminal_closing && error.kind() == io::ErrorKind::UnexpectedEof =>
                {
                    terminal_eof = true;
                }
                Err(error) => return Err(error),
            }
        }
        if terminal_eof && pending_terminal.is_none() {
            return Ok(());
        }
        // Recovery authentication may read more than its proof packet into
        // BackedReader. Drain it after the wake even when the new socket no
        // longer has kernel-level readability.
        let client_data_ready = connected
            && (client_buffered
                || client_events_are_stale
                || client_events.contains(PollFlags::IN));
        if client_data_ready && pending_forward.is_none() && pending_outbound.is_none() {
            client_buffered = false;
            for index in 0..CLIENT_READ_BATCH {
                let read_packet = match session.try_read_packet() {
                    // Jumphost relays every packet verbatim to the jump
                    // terminal, which owns the destination connection.
                    Ok(Some(packet)) if mode == BridgeMode::Jumphost => {
                        let packet = jumphost_client_packet(&session, packet)?;
                        write_local_packet(&mut terminal, &packet).map_err(SessionError::Io)?;
                        true
                    }
                    Ok(Some(packet)) if is_forward_packet(packet.header()) => {
                        pending_forward = forwarder.try_receive(packet).map_err(forward_error)?;
                        true
                    }
                    Ok(Some(packet)) => {
                        if let Some(control) =
                            forward_client_packet(&session, &mut terminal, packet)?
                        {
                            pending_outbound = send_or_hold(
                                &session,
                                control,
                                &mut connected,
                                &mut connection_generation,
                            )?;
                        }
                        true
                    }
                    Ok(None) => false,
                    Err(error) => {
                        if client_transport_error(
                            &error,
                            &session,
                            &mut connected,
                            &mut connection_generation,
                        )? {
                            false
                        } else {
                            return Err(error);
                        }
                    }
                };
                if !read_packet {
                    break;
                }
                if pending_forward.is_some() || pending_outbound.is_some() {
                    client_buffered = true;
                    break;
                }
                if index + 1 == CLIENT_READ_BATCH {
                    // `try_read_packet` can leave complete packets in its
                    // userspace decoder after the kernel socket is drained.
                    client_buffered = true;
                }
            }
        }
        if !client_events_are_stale && client_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            let observed_generation = polled_generation.unwrap_or(connection_generation);
            note_client_drop(
                &session,
                &mut connected,
                &mut connection_generation,
                observed_generation,
            )?;
        }
        if pending_outbound.is_none()
            && (resume_outbound_drain || forward_events.intersects(PollFlags::IN | PollFlags::HUP))
        {
            while let Some(packet) = forwarder.try_outbound().map_err(forward_error)? {
                pending_outbound =
                    send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
                if pending_outbound.is_some() {
                    break;
                }
            }
        }
    }
}

/// Windows bridge.
///
/// Windows cannot poll the terminal channel, the client socket, and the
/// forwarder wake handle together, so this walks every source with
/// non-blocking reads and idles on the same 10ms cadence upstream's `select()`
/// timeout uses. Behaviour (backpressure, packet validation, disconnect
/// handling) matches the readiness-driven loop above.
#[cfg(windows)]
fn run_mode_windows(
    session: Arc<ActiveSession>,
    mut terminal: LocalStream,
    forwarder: Forwarder,
    mode: BridgeMode,
) -> Result<(), SessionError> {
    const IDLE: std::time::Duration = std::time::Duration::from_millis(10);
    terminal.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut wake = session.take_wake_reader()?;
    wake.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut decoder = LocalPacketDecoder::new();
    let (mut connected, mut connection_generation) = session.connection_state()?;
    session.note_bridge_generation(connection_generation)?;
    // A forwarding packet the worker had no room for; while it is held, no
    // further client packets are read so forwarding data stays ordered.
    let mut pending_forward: Option<Packet> = None;
    let mut pending_outbound: Option<Packet> = None;
    let mut pending_terminal: Option<Packet> = None;
    loop {
        if session.is_shutting_down() {
            return Ok(());
        }
        let mut progress = false;

        // Retry the held packet first: draining the forwarder's outbound
        // queue below is what frees worker capacity, so this makes progress
        // every 10ms tick instead of deadlocking on a blocking send.
        if let Some(packet) = pending_forward.take() {
            match forwarder.try_receive(packet).map_err(forward_error)? {
                Some(held) => pending_forward = Some(held),
                None => progress = true,
            }
        }
        if let Some(packet) = pending_outbound.take() {
            pending_outbound =
                send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
            progress |= pending_outbound.is_none();
        }
        if let Some(packet) = pending_terminal.take() {
            pending_terminal =
                send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
            progress |= pending_terminal.is_none();
        }

        // Connection state changes are announced through the wake channel.
        if drain_available(&mut wake)? {
            if session.is_shutting_down() {
                return Ok(());
            }
            (connected, connection_generation) = session.connection_state()?;
            session.note_bridge_generation(connection_generation)?;
            progress = true;
        }

        // Terminal -> client, honouring the same write-buffer backpressure.
        if pending_terminal.is_none() && session.can_buffer_write((READ_BUFFER * 2) as i64)? {
            match read_terminal_packet(&mut terminal, &mut decoder) {
                Ok(Some(packet)) => {
                    progress = true;
                    let packet = if mode == BridgeMode::Terminal {
                        validate_terminal_output(&packet)?;
                        packet
                    } else {
                        jumphost_terminal_packet(&session, packet)?
                    };
                    decoder = LocalPacketDecoder::new();
                    pending_terminal =
                        send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }

        // Client -> terminal / forwarder.
        if connected {
            for _ in 0..CLIENT_READ_BATCH {
                if pending_forward.is_some() || pending_outbound.is_some() {
                    break;
                }
                match session.try_read_packet() {
                    Ok(Some(packet)) => {
                        progress = true;
                        if mode == BridgeMode::Jumphost {
                            let packet = jumphost_client_packet(&session, packet)?;
                            write_local_packet(&mut terminal, &packet).map_err(SessionError::Io)?;
                        } else if is_forward_packet(packet.header()) {
                            pending_forward =
                                forwarder.try_receive(packet).map_err(forward_error)?;
                        } else if let Some(control) =
                            forward_client_packet(&session, &mut terminal, packet)?
                        {
                            pending_outbound = send_or_hold(
                                &session,
                                control,
                                &mut connected,
                                &mut connection_generation,
                            )?;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        if client_transport_error(
                            &error,
                            &session,
                            &mut connected,
                            &mut connection_generation,
                        )? {
                            break;
                        }
                        return Err(error);
                    }
                }
            }
        }

        // Forwarding -> client.
        while pending_outbound.is_none() {
            let Some(packet) = forwarder.try_outbound().map_err(forward_error)? else {
                break;
            };
            progress = true;
            pending_outbound =
                send_or_hold(&session, packet, &mut connected, &mut connection_generation)?;
            if pending_outbound.is_some() {
                break;
            }
        }

        if !progress {
            std::thread::sleep(IDLE);
        }
    }
}

/// Drain a wake channel, reporting whether anything was pending.
#[cfg(windows)]
fn drain_available(wake: &mut LocalStream) -> Result<bool, SessionError> {
    let mut buffer = [0u8; 64];
    let mut signalled = false;
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(signalled),
            Ok(_) => signalled = true,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(signalled),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SessionError::Io(error)),
        }
    }
}

fn send_or_hold(
    session: &ActiveSession,
    packet: Packet,
    connected: &mut bool,
    connection_generation: &mut u64,
) -> Result<Option<Packet>, SessionError> {
    match session.send_packet_owned(packet.header(), packet.payload()) {
        Ok(()) => Ok(None),
        Err(SessionWriteError::BeforeReplay(SessionError::Connection(ConnError::Backpressure))) => {
            Ok(Some(packet))
        }
        Err(SessionWriteError::BeforeReplay(error)) => {
            if client_transport_error(&error, session, connected, connection_generation)? {
                Ok(Some(packet))
            } else {
                Err(error)
            }
        }
        Err(SessionWriteError::ReplayOwned(error)) => {
            if client_transport_error(&error, session, connected, connection_generation)? {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

/// Client-side transport failures are soft: keep the terminal alive so a
/// returning client can recover. Terminal / local I/O errors stay fatal.
fn client_transport_error(
    error: &SessionError,
    session: &ActiveSession,
    connected: &mut bool,
    connection_generation: &mut u64,
) -> Result<bool, SessionError> {
    let observed_generation = *connection_generation;
    match error {
        SessionError::Connection(ConnError::Io(io_error)) if connection_ended(io_error) => {
            note_client_drop(
                session,
                connected,
                connection_generation,
                observed_generation,
            )?;
            Ok(true)
        }
        SessionError::Connection(ConnError::Io(_))
        | SessionError::Connection(ConnError::Read(_)) => {
            note_client_drop(
                session,
                connected,
                connection_generation,
                observed_generation,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn note_client_drop(
    session: &ActiveSession,
    connected: &mut bool,
    connection_generation: &mut u64,
    observed_generation: u64,
) -> Result<(), SessionError> {
    if session.mark_client_disconnected(observed_generation)? {
        if *connected {
            crate::diag::info("client transport lost; buffering for reconnect");
        }
        *connected = false;
    } else {
        (*connected, *connection_generation) = session.connection_state()?;
    }
    Ok(())
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

#[cfg(unix)]
fn wait(
    terminal: &LocalStream,
    wake: &LocalStream,
    forward_wake: &LocalStream,
    client: Option<&std::net::TcpStream>,
    accept_terminal: bool,
    forward_blocked: bool,
    client_buffered: bool,
) -> Result<(PollFlags, PollFlags, PollFlags, PollFlags), SessionError> {
    let terminal_flags = if accept_terminal {
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR
    } else {
        PollFlags::HUP | PollFlags::ERR
    };
    // While a forwarding packet is held for worker capacity the client is not
    // read, so do not watch it for readability, and wake on a 10ms cadence to
    // retry the held packet even when nothing else becomes ready.
    let client_flags = if forward_blocked {
        PollFlags::HUP | PollFlags::ERR
    } else {
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR
    };
    let timeout = if client_buffered && !forward_blocked {
        Some(Timespec::try_from(std::time::Duration::ZERO).expect("zero fits timespec"))
    } else if forward_blocked {
        Some(Timespec::try_from(std::time::Duration::from_millis(10)).expect("10ms fits timespec"))
    } else {
        None
    };
    let mut descriptors = vec![
        PollFd::new(terminal, terminal_flags),
        PollFd::new(wake, PollFlags::IN | PollFlags::HUP),
        PollFd::new(forward_wake, PollFlags::IN | PollFlags::HUP),
    ];
    if let Some(client) = client {
        descriptors.push(PollFd::new(client, client_flags));
    }
    // poll() is never restarted by SA_RESTART; retry on EINTR instead of
    // tearing the session down when a signal interrupts the wait.
    loop {
        match poll(&mut descriptors, timeout.as_ref()) {
            Ok(_) => break,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(SessionError::Io(io::Error::from(error))),
        }
    }
    Ok((
        descriptors[0].revents(),
        descriptors[1].revents(),
        descriptors[2].revents(),
        descriptors
            .get(3)
            .map(PollFd::revents)
            .unwrap_or(PollFlags::empty()),
    ))
}

fn forward_error(error: et_net::forward::ForwardError) -> SessionError {
    SessionError::Io(io::Error::other(error))
}

fn read_terminal_packet(
    terminal: &mut LocalStream,
    decoder: &mut LocalPacketDecoder,
) -> Result<Option<Packet>, SessionError> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let wanted = decoder.required_bytes().min(buffer.len());
        match terminal.read(&mut buffer[..wanted]) {
            Ok(0) => return Err(SessionError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(count) => match decoder.feed(&buffer[..count]) {
                Ok(Some(packet)) => return Ok(Some(packet)),
                Ok(None) => {}
                Err(error) => {
                    return Err(SessionError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error,
                    )));
                }
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SessionError::Io(error)),
        }
    }
}

fn validate_terminal_output(packet: &Packet) -> Result<(), SessionError> {
    if packet.is_encrypted() || packet.header() != TerminalPacketType::TerminalBuffer as u8 {
        return Err(SessionError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "terminal emitted an invalid packet",
        )));
    }
    Ok(())
}

/// Normalize a client packet relayed towards the jump terminal.
///
/// Keep-alive acknowledgements are per-hop: the payload the client sent
/// refers to this hop's connection, so apply it here and relay a payload-less
/// keep-alive. The next hop (`etterminal --jump`) attaches its own sequence
/// for the destination, and a foreign sequence never crosses a hop.
fn jumphost_client_packet(session: &ActiveSession, packet: Packet) -> Result<Packet, SessionError> {
    if packet.header() != TerminalPacketType::KeepAlive as u8 {
        return Ok(packet);
    }
    if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
        session.acknowledge_delivery(ack)?;
    }
    Ok(Packet::new(TerminalPacketType::KeepAlive as u8, Vec::new()))
}

/// Normalize a jump-terminal packet relayed towards the client.
///
/// A keep-alive echo returning from the destination acknowledges the previous
/// hop; replace its payload with this hop's reader sequence so the client can
/// trim its own replay backup.
fn jumphost_terminal_packet(
    session: &ActiveSession,
    packet: Packet,
) -> Result<Packet, SessionError> {
    if packet.header() != TerminalPacketType::KeepAlive as u8 {
        return Ok(packet);
    }
    Ok(Packet::new(
        TerminalPacketType::KeepAlive as u8,
        session.keepalive_ack()?.to_vec(),
    ))
}

fn forward_client_packet(
    session: &ActiveSession,
    terminal: &mut LocalStream,
    packet: Packet,
) -> Result<Option<Packet>, SessionError> {
    match packet.header() {
        value
            if value == TerminalPacketType::TerminalBuffer as u8
                || value == TerminalPacketType::TerminalInfo as u8 =>
        {
            write_local_packet(terminal, &packet)
                .map_err(SessionError::Io)
                .map(|()| None)
        }
        header if header == TerminalPacketType::KeepAlive as u8 => {
            if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
                session.acknowledge_delivery(ack)?;
            }
            // The echo acknowledges everything read from the client, letting
            // an et.rs client trim its own replay backup. Legacy peers
            // (upstream C++, released et.rs) ignore the payload.
            Ok(Some(Packet::new(
                TerminalPacketType::KeepAlive as u8,
                session.keepalive_ack()?.to_vec(),
            )))
        }
        _ => Err(SessionError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "client sent an unsupported terminal packet",
        ))),
    }
}

#[cfg(unix)]
fn drain(wake: &mut LocalStream) -> Result<(), SessionError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SessionError::Io(error)),
        }
    }
}
