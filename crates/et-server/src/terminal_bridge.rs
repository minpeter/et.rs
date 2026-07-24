use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use et_core::packet::Packet;
use et_core::proto::TerminalPacketType;
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
use rustix::event::{poll, PollFd, PollFlags};

use crate::session::{ActiveSession, SessionError};

const READ_BUFFER: usize = 16 * 1024;

pub(crate) fn run(
    session: Arc<ActiveSession>,
    mut terminal: UnixStream,
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
        let (terminal_events, wake_events, client_events) =
            wait(&terminal, &wake, client.as_ref())?;
        if wake_events.intersects(PollFlags::IN | PollFlags::HUP) {
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
                validate_terminal_output(&packet)?;
                session.send_packet(packet.header(), packet.payload())?;
                decoder = LocalPacketDecoder::new();
            }
        }
        if client_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            connected = false;
        } else if client_events.contains(PollFlags::IN) {
            match session.try_read_packet() {
                Ok(Some(packet)) => forward_client_packet(&session, &mut terminal, packet)?,
                Ok(None) => {}
                Err(SessionError::Connection(_)) => connected = false,
                Err(error) => return Err(error),
            }
        }
    }
}

fn wait(
    terminal: &UnixStream,
    wake: &UnixStream,
    client: Option<&std::net::TcpStream>,
) -> Result<(PollFlags, PollFlags, PollFlags), SessionError> {
    let mut descriptors = vec![
        PollFd::new(terminal, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
        PollFd::new(wake, PollFlags::IN | PollFlags::HUP),
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
        descriptors
            .get(2)
            .map(PollFd::revents)
            .unwrap_or(PollFlags::empty()),
    ))
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
