use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use et_core::packet::Packet;
use et_core::proto::TerminalPacketType;
use et_net::connection::ConnError;
use et_net::forward::{is_forward_packet, Forwarder};
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
use rustix::event::{poll, PollFd, PollFlags};

use crate::session::{ActiveSession, SessionError};

const READ_BUFFER: usize = 16 * 1024;

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
    terminal: UnixStream,
    forwarder: Forwarder,
) -> Result<(), SessionError> {
    run_mode(session, terminal, forwarder, BridgeMode::Terminal)
}

pub(crate) fn run_mode(
    session: Arc<ActiveSession>,
    mut terminal: UnixStream,
    forwarder: Forwarder,
    mode: BridgeMode,
) -> Result<(), SessionError> {
    terminal.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut wake = session.take_wake_reader()?;
    wake.set_nonblocking(true).map_err(SessionError::Io)?;
    let mut decoder = LocalPacketDecoder::new();
    let mut connected = session.connected()?;
    loop {
        if session.is_shutting_down() {
            return Ok(());
        }
        let client = connected.then(|| session.try_clone_stream()).transpose()?;
        let accept_terminal = session.can_buffer_write((READ_BUFFER * 2) as i64)?;
        let (terminal_events, wake_events, forward_events, client_events) = wait(
            &terminal,
            &wake,
            forwarder.wake().map_err(forward_error)?,
            client.as_ref(),
            accept_terminal,
        )?;
        let client_events_are_stale = wake_events.intersects(PollFlags::IN | PollFlags::HUP);
        if client_events_are_stale {
            drain(&mut wake)?;
            if session.is_shutting_down() {
                return Ok(());
            }
            connected = session.connected()?;
        }
        if terminal_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Err(SessionError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        if terminal_events.contains(PollFlags::IN) {
            if let Some(packet) = read_terminal_packet(&mut terminal, &mut decoder)? {
                if mode == BridgeMode::Terminal {
                    validate_terminal_output(&packet)?;
                }
                decoder = LocalPacketDecoder::new();
                match session.send_packet(packet.header(), packet.payload()) {
                    Ok(()) => {}
                    Err(SessionError::Connection(ConnError::Io(error)))
                        if connection_ended(&error) =>
                    {
                        connected = false;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        if !client_events_are_stale && client_events.contains(PollFlags::IN) {
            loop {
                match session.try_read_packet() {
                    // Jumphost relays every packet verbatim to the jump
                    // terminal, which owns the destination connection.
                    Ok(Some(packet)) if mode == BridgeMode::Jumphost => {
                        write_local_packet(&mut terminal, &packet).map_err(SessionError::Io)?;
                    }
                    Ok(Some(packet)) if is_forward_packet(packet.header()) => {
                        forwarder.receive(packet).map_err(forward_error)?;
                    }
                    Ok(Some(packet)) => forward_client_packet(&session, &mut terminal, packet)?,
                    Ok(None) => break,
                    Err(SessionError::Connection(_)) => {
                        connected = false;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        if !client_events_are_stale && client_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            connected = false;
        }
        if forward_events.intersects(PollFlags::IN | PollFlags::HUP) {
            while let Some(packet) = forwarder.try_outbound().map_err(forward_error)? {
                match session.send_packet(packet.header(), packet.payload()) {
                    Ok(()) => {}
                    Err(SessionError::Connection(ConnError::Io(error)))
                        if connection_ended(&error) =>
                    {
                        connected = false;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

fn wait(
    terminal: &UnixStream,
    wake: &UnixStream,
    forward_wake: &UnixStream,
    client: Option<&std::net::TcpStream>,
    accept_terminal: bool,
) -> Result<(PollFlags, PollFlags, PollFlags, PollFlags), SessionError> {
    let terminal_flags = if accept_terminal {
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR
    } else {
        PollFlags::HUP | PollFlags::ERR
    };
    let mut descriptors = vec![
        PollFd::new(terminal, terminal_flags),
        PollFd::new(wake, PollFlags::IN | PollFlags::HUP),
        PollFd::new(forward_wake, PollFlags::IN | PollFlags::HUP),
    ];
    if let Some(client) = client {
        descriptors.push(PollFd::new(
            client,
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
        ));
    }
    poll(&mut descriptors, None).map_err(|error| SessionError::Io(io::Error::from(error)))?;
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
    terminal: &mut UnixStream,
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

fn forward_client_packet(
    session: &ActiveSession,
    terminal: &mut UnixStream,
    packet: Packet,
) -> Result<(), SessionError> {
    match packet.header() {
        value
            if value == TerminalPacketType::TerminalBuffer as u8
                || value == TerminalPacketType::TerminalInfo as u8 =>
        {
            write_local_packet(terminal, &packet).map_err(SessionError::Io)
        }
        header if header == TerminalPacketType::KeepAlive as u8 => {
            session.send_packet(TerminalPacketType::KeepAlive as u8, &[])
        }
        _ => Err(SessionError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "client sent an unsupported terminal packet",
        ))),
    }
}

fn drain(wake: &mut UnixStream) -> Result<(), SessionError> {
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
