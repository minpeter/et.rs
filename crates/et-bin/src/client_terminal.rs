use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::thread;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use et_core::proto::{TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::connection::{ConnError, Connection};
use et_net::forward::Forwarder;
use prost::Message;
#[cfg(unix)]
use signal_hook::consts::SIGWINCH;
#[cfg(unix)]
use signal_hook::iterator::Signals;

use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

/// Line grammar of the shell on the far side of the session.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum RemoteLines {
    /// POSIX shell: `<cmd>; exit\n`.
    #[default]
    Posix,
    /// `cmd.exe`: commands are separated with `&` and lines end with CRLF.
    Cmd,
    /// PowerShell: `;` separator, CRLF line ending.
    Powershell,
}

impl From<et_cli::client::RemoteShellKind> for RemoteLines {
    fn from(kind: et_cli::client::RemoteShellKind) -> Self {
        match kind {
            et_cli::client::RemoteShellKind::Posix => Self::Posix,
            et_cli::client::RemoteShellKind::Cmd => Self::Cmd,
            et_cli::client::RemoteShellKind::Powershell => Self::Powershell,
        }
    }
}

/// Everything the terminal loop needs besides the connection itself.
pub struct TerminalOptions<'a> {
    pub command: Option<&'a str>,
    pub no_exit: bool,
    pub keepalive: u32,
    pub terminal_enabled: bool,
    pub lines: RemoteLines,
}

pub fn run<F>(
    mut connection: Connection,
    options: TerminalOptions<'_>,
    forwarder: Forwarder,
    reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let TerminalOptions {
        command,
        no_exit,
        keepalive,
        terminal_enabled,
        lines,
    } = options;
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
            send_command(&mut connection, command, no_exit, lines)?;
        }
    }
    let read_stdin = terminal_enabled && (command.is_none() || io::stdin().is_terminal());
    // With `--command` (or without a real console) nothing will answer a
    // ConPTY cursor-position request, so the client answers it itself.
    let auto_cursor_report =
        command.is_some() || !io::stdout().is_terminal() || !io::stdin().is_terminal();

    // Unix reacts to SIGWINCH and polls stdin, the socket, and the forwarder
    // together. Windows has no SIGWINCH and cannot select() a console handle,
    // so resize arrives as a console event inside the Windows loop.
    #[cfg(unix)]
    let result = {
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
        let result = crate::client_terminal_loop::pump(
            &mut connection,
            &mut wake_reader,
            crate::client_terminal_loop::PumpOptions {
                read_stdin,
                keepalive_seconds: keepalive,
                terminal_enabled,
                auto_cursor_report,
            },
            &forwarder,
            reconnect,
        );
        signal_handle.close();
        let _ = signal_worker.join();
        result
    };
    #[cfg(windows)]
    let result = crate::client_terminal_windows::pump(
        &mut connection,
        crate::client_terminal_loop::PumpOptions {
            read_stdin,
            keepalive_seconds: keepalive,
            terminal_enabled,
            auto_cursor_report,
        },
        &forwarder,
        reconnect,
    );
    drop(raw_mode);
    result
}

/// Device Status Report request (`ESC [ 6 n`).
const CURSOR_REPORT_REQUEST: &[u8] = b"\x1b[6n";
/// Minimal reply: cursor at row 1, column 1.
pub(crate) const CURSOR_REPORT_REPLY: &[u8] = b"\x1b[1;1R";

/// Write one server packet to the console.
///
/// Returns `true` when the remote asked for a cursor position report. ConPTY
/// emits that request on startup and waits for the answer, which an interactive
/// terminal emulator provides. Non-interactive sessions have no emulator to
/// answer, so the caller replies on their behalf (see `auto_cursor_report`).
pub(crate) fn display_packet(packet: et_core::packet::Packet) -> Result<bool, ClientError> {
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
                .map_err(|error| terminal_io("writing terminal output", error))?;
            Ok(contains_cursor_report_request(&bytes))
        }
        value if value == TerminalPacketType::KeepAlive as u8 => Ok(false),
        _ => Err(terminal_text("server sent an unsupported terminal packet")),
    }
}

fn contains_cursor_report_request(bytes: &[u8]) -> bool {
    bytes
        .windows(CURSOR_REPORT_REQUEST.len())
        .any(|window| window == CURSOR_REPORT_REQUEST)
}

fn send_command(
    connection: &mut Connection,
    command: &str,
    no_exit: bool,
    lines: RemoteLines,
) -> Result<(), ClientError> {
    if command.contains('\0') || command.len() > 64 * 1024 {
        return Err(terminal_text("remote command is invalid or too large"));
    }
    // `cmd.exe` only accepts a line terminated with CRLF and separates
    // commands with `&` instead of `;`.
    let suffix = match (lines, no_exit) {
        (RemoteLines::Posix, true) => "\n",
        (RemoteLines::Posix, false) => "; exit\n",
        (RemoteLines::Cmd, true) => "\r\n",
        (RemoteLines::Cmd, false) => " & exit\r\n",
        (RemoteLines::Powershell, true) => "\r\n",
        (RemoteLines::Powershell, false) => "; exit\r\n",
    };
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

/// Errors that mean the session must reconnect rather than fail.
pub(crate) fn connection_ended(error: &ConnError) -> bool {
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
