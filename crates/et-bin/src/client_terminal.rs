use std::io::{self, IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use et_core::proto::{TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::connection::{ConnError, Connection};
use et_net::forward::Forwarder;
use prost::Message;
use signal_hook::consts::SIGWINCH;
use signal_hook::iterator::Signals;

use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

pub fn run<F>(
    mut connection: Connection,
    command: Option<&str>,
    no_exit: bool,
    keepalive: u32,
    forwarder: Forwarder,
    terminal_enabled: bool,
    reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let raw_mode = if terminal_enabled {
        RawMode::enter()?
    } else {
        RawMode { enabled: false }
    };
    if terminal_enabled {
        send_size(&mut connection)?;
    }
    if terminal_enabled {
        if let Some(command) = command {
            send_command(&mut connection, command, no_exit)?;
        }
    }
    let (mut wake_reader, mut wake_writer) =
        UnixStream::pair().map_err(|error| terminal_io("creating resize wakeup", error))?;
    wake_reader
        .set_nonblocking(true)
        .map_err(|error| terminal_io("configuring resize wakeup", error))?;
    wake_writer
        .set_nonblocking(true)
        .map_err(|error| terminal_io("configuring resize signal wakeup", error))?;
    let mut signals = Signals::new([SIGWINCH])
        .map_err(|error| terminal_io("installing resize signal handler", error))?;
    let signal_handle = signals.handle();
    let signal_worker = thread::Builder::new()
        .name("et-client-resize".to_owned())
        .spawn(move || {
            for _ in signals.forever() {
                match wake_writer.write(&[1]) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        })
        .map_err(|error| terminal_io("starting resize signal worker", error))?;
    let read_stdin = terminal_enabled && (command.is_none() || io::stdin().is_terminal());
    let result = crate::client_terminal_loop::pump(
        &mut connection,
        &mut wake_reader,
        read_stdin,
        keepalive,
        &forwarder,
        terminal_enabled,
        reconnect,
    );
    signal_handle.close();
    drop(raw_mode);
    let _ = signal_worker.join();
    result
}

pub(crate) fn display_packet(packet: et_core::packet::Packet) -> Result<(), ClientError> {
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
    send_buffer_checked(connection, &bytes)
}

pub(crate) fn send_buffer(connection: &mut Connection, bytes: &[u8]) -> Result<(), ConnError> {
    let message = TerminalBuffer {
        buffer: Some(bytes.to_vec()),
    };
    connection.write_packet(
        TerminalPacketType::TerminalBuffer as u8,
        &message.encode_to_vec(),
    )
}

fn send_buffer_checked(connection: &mut Connection, bytes: &[u8]) -> Result<(), ClientError> {
    send_buffer(connection, bytes).map_err(terminal_error)
}

pub(crate) fn send_size(connection: &mut Connection) -> Result<(), ClientError> {
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

pub(crate) fn terminal_error(error: ConnError) -> ClientError {
    terminal_text(format!("terminal transport: {error}"))
}

pub(crate) fn terminal_io(operation: &str, error: io::Error) -> ClientError {
    terminal_text(format!("{operation}: {error}"))
}

fn terminal_message(operation: &str, error: impl std::fmt::Display) -> ClientError {
    terminal_text(format!("{operation}: {error}"))
}

pub(crate) fn terminal_text(message: impl Into<String>) -> ClientError {
    ClientError::Terminal(message.into())
}

#[cfg(test)]
#[path = "client_terminal_tests.rs"]
mod tests;
