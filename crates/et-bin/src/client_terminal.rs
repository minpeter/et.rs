use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use et_core::proto::{TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::connection::{ConnError, Connection};
use prost::Message;
use rustix::event::{poll, PollFd, PollFlags};
use signal_hook::consts::SIGWINCH;
use signal_hook::iterator::Signals;

use crate::error::ClientError;

const INPUT_CHUNK: usize = 16 * 1024;

pub fn run(
    mut connection: Connection,
    command: Option<&str>,
    no_exit: bool,
) -> Result<(), ClientError> {
    let raw_mode = RawMode::enter()?;
    send_size(&mut connection)?;
    if let Some(command) = command {
        send_command(&mut connection, command, no_exit)?;
    }
    let stream = connection.try_clone_stream().map_err(terminal_error)?;
    let (mut wake_reader, wake_writer) =
        UnixStream::pair().map_err(|error| terminal_io("creating resize wakeup", error))?;
    wake_reader
        .set_nonblocking(true)
        .map_err(|error| terminal_io("configuring resize wakeup", error))?;
    let mut signals = Signals::new([SIGWINCH])
        .map_err(|error| terminal_io("installing resize signal handler", error))?;
    let signal_handle = signals.handle();
    let signal_worker = thread::Builder::new()
        .name("et-client-resize".to_owned())
        .spawn(move || {
            for _ in signals.forever() {
                if (&wake_writer).write_all(&[1]).is_err() {
                    break;
                }
            }
        })
        .map_err(|error| terminal_io("starting resize signal worker", error))?;
    let read_stdin = command.is_none() || io::stdin().is_terminal();
    let result = pump(&mut connection, &stream, &mut wake_reader, read_stdin);
    signal_handle.close();
    let _ = signal_worker.join();
    drop(raw_mode);
    result
}

fn pump(
    connection: &mut Connection,
    stream: &std::net::TcpStream,
    wake: &mut UnixStream,
    read_stdin: bool,
) -> Result<(), ClientError> {
    let stdin = io::stdin();
    loop {
        let mut descriptors = vec![
            PollFd::new(stream, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
            PollFd::new(&*wake, PollFlags::IN | PollFlags::HUP),
        ];
        if read_stdin {
            descriptors.push(PollFd::new(
                &stdin,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            ));
        }
        poll(&mut descriptors, None)
            .map_err(|error| terminal_io("polling terminal streams", io::Error::from(error)))?;
        let network = descriptors[0].revents();
        let resize = descriptors[1].revents();
        let input = descriptors
            .get(2)
            .map(PollFd::revents)
            .unwrap_or(PollFlags::empty());
        drop(descriptors);
        if resize.intersects(PollFlags::IN | PollFlags::HUP) {
            drain(wake)?;
            send_size(connection)?;
        }
        if network.contains(PollFlags::IN) {
            loop {
                match connection.try_read_packet() {
                    Ok(Some(packet)) => display_packet(packet)?,
                    Ok(None) => break,
                    Err(error) if connection_ended(&error) => return Ok(()),
                    Err(error) => return Err(terminal_error(error)),
                }
            }
        }
        if network.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
        if input.contains(PollFlags::IN) {
            let mut bytes = [0u8; INPUT_CHUNK];
            let count = stdin
                .lock()
                .read(&mut bytes)
                .map_err(|error| terminal_io("reading terminal input", error))?;
            if count == 0 {
                return Ok(());
            }
            send_buffer(connection, &bytes[..count])?;
        }
        if input.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
    }
}

fn display_packet(packet: et_core::packet::Packet) -> Result<(), ClientError> {
    match packet.header() {
        value if value == TerminalPacketType::TerminalBuffer as u8 => {
            let message = TerminalBuffer::decode(packet.payload())
                .map_err(|error| terminal_message("decoding terminal output", error))?;
            let bytes = message
                .buffer
                .ok_or_else(|| terminal_text("terminal output is missing bytes"))?;
            io::stdout()
                .lock()
                .write_all(&bytes)
                .and_then(|()| io::stdout().lock().flush())
                .map_err(|error| terminal_io("writing terminal output", error))
        }
        value if value == TerminalPacketType::KeepAlive as u8 => Ok(()),
        _ => Err(terminal_text("server sent an unsupported terminal packet")),
    }
}

fn send_command(
    connection: &mut Connection,
    command: &str,
    no_exit: bool,
) -> Result<(), ClientError> {
    if command.contains('\0') || command.len() > 64 * 1024 {
        return Err(terminal_text("remote command is invalid or too large"));
    }
    let suffix = if no_exit { "\n" } else { "; exit\n" };
    let mut bytes = Vec::with_capacity(command.len() + suffix.len());
    bytes.extend_from_slice(command.as_bytes());
    bytes.extend_from_slice(suffix.as_bytes());
    send_buffer(connection, &bytes)
}

fn send_buffer(connection: &mut Connection, bytes: &[u8]) -> Result<(), ClientError> {
    let message = TerminalBuffer {
        buffer: Some(bytes.to_vec()),
    };
    connection
        .write_packet(
            TerminalPacketType::TerminalBuffer as u8,
            &message.encode_to_vec(),
        )
        .map_err(terminal_error)
}

fn send_size(connection: &mut Connection) -> Result<(), ClientError> {
    if !io::stdout().is_terminal() {
        return Ok(());
    }
    let (columns, rows) = size().map_err(|error| terminal_io("reading terminal size", error))?;
    let message = TerminalInfo {
        id: None,
        row: Some(i32::from(rows)),
        column: Some(i32::from(columns)),
        width: Some(0),
        height: Some(0),
    };
    connection
        .write_packet(
            TerminalPacketType::TerminalInfo as u8,
            &message.encode_to_vec(),
        )
        .map_err(terminal_error)
}

fn drain(wake: &mut UnixStream) -> Result<(), ClientError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(terminal_io("draining resize wakeup", error)),
        }
    }
}

fn connection_ended(error: &ConnError) -> bool {
    matches!(
        error,
        ConnError::Io(source)
            if matches!(
                source.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            )
    )
}

struct RawMode {
    enabled: bool,
}

impl RawMode {
    fn enter() -> Result<Self, ClientError> {
        let enabled = io::stdin().is_terminal() && io::stdout().is_terminal();
        if enabled {
            enable_raw_mode().map_err(|error| terminal_io("enabling raw terminal mode", error))?;
        }
        Ok(Self { enabled })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.enabled {
            let _ = disable_raw_mode();
        }
    }
}

fn terminal_error(error: ConnError) -> ClientError {
    terminal_text(format!("terminal transport: {error}"))
}

fn terminal_io(operation: &str, error: io::Error) -> ClientError {
    terminal_text(format!("{operation}: {error}"))
}

fn terminal_message(operation: &str, error: impl std::fmt::Display) -> ClientError {
    terminal_text(format!("{operation}: {error}"))
}

fn terminal_text(message: impl Into<String>) -> ClientError {
    ClientError::Terminal(message.into())
}

#[cfg(test)]
#[path = "client_terminal_tests.rs"]
mod tests;
