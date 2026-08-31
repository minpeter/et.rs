use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::thread;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use et_core::proto::{TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::connection::{ConnError, Connection, WritePacketError};
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
    pub flow_control: et_cli::client::FlowControlMode,
    pub terminal_enabled: bool,
    pub lines: RemoteLines,
    pub connection_name: &'a str,
}

pub fn run<F>(
    mut connection: Connection,
    options: TerminalOptions<'_>,
    forwarder: Forwarder,
    mut reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let TerminalOptions {
        command,
        no_exit,
        keepalive,
        flow_control,
        terminal_enabled,
        lines,
        connection_name,
    } = options;
    let raw_mode = if terminal_enabled {
        RawMode::enter()?
    } else {
        RawMode {
            enabled: false,
            reset: TerminalReset::LeaveAlternate,
        }
    };
    let close_message = (raw_mode.enabled && command.is_none()).then_some(connection_name);
    let mut terminal_modes = TerminalModeState::default();
    // The network can disappear immediately after the initial handshake (a
    // laptop waking up is particularly prone to this).  These writes are
    // replay-buffered by `Connection`. Retry plaintext only when admission
    // failed before replay ownership; after admission, recover and let the
    // buffered packet replay instead of duplicating a `--command`.
    if terminal_enabled {
        if let Some(initial_size) = terminal_size_payload()? {
            if matches!(
                write_owned_recovering(
                    &mut connection,
                    TerminalPacketType::TerminalInfo as u8,
                    &initial_size,
                    &mut reconnect,
                    terminal_enabled,
                )?,
                OwnedWriteOutcome::SessionEnded
            ) {
                return raw_mode.finish(Ok(()), close_message, terminal_modes.alternate_screen());
            }
        }
    }
    if terminal_enabled {
        if let Some(command) = command {
            let initial_command = command_payload(command, no_exit, lines)?;
            if matches!(
                write_owned_recovering(
                    &mut connection,
                    TerminalPacketType::TerminalBuffer as u8,
                    &initial_command,
                    &mut reconnect,
                    terminal_enabled,
                )?,
                OwnedWriteOutcome::SessionEnded
            ) {
                return raw_mode.finish(Ok(()), close_message, terminal_modes.alternate_screen());
            }
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
                flow_control,
                terminal_enabled,
                auto_cursor_report,
                terminal_modes: &mut terminal_modes,
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
            flow_control,
            terminal_enabled,
            auto_cursor_report,
            terminal_modes: &mut terminal_modes,
        },
        &forwarder,
        reconnect,
    );
    raw_mode.finish(result, close_message, terminal_modes.alternate_screen())
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
pub(crate) enum DisplayOutcome {
    Displayed { cursor_report: bool },
    Pending(et_core::packet::Packet),
}

pub(crate) fn display_packet_with<F>(
    packet: et_core::packet::Packet,
    mut output: F,
) -> Result<DisplayOutcome, ClientError>
where
    F: FnMut(&[u8]) -> Result<bool, ClientError>,
{
    match packet.header() {
        value if value == TerminalPacketType::TerminalBuffer as u8 => {
            let message = TerminalBuffer::decode(packet.payload())
                .map_err(|error| terminal_message("decoding terminal output", error))?;
            let bytes = message
                .buffer
                .ok_or_else(|| terminal_text("terminal output is missing bytes"))?;
            if !output(&bytes)? {
                return Ok(DisplayOutcome::Pending(packet));
            }
            Ok(DisplayOutcome::Displayed {
                cursor_report: contains_cursor_report_request(&bytes),
            })
        }
        value if value == TerminalPacketType::KeepAlive as u8 => Ok(DisplayOutcome::Displayed {
            cursor_report: false,
        }),
        _ => Err(terminal_text("server sent an unsupported terminal packet")),
    }
}

pub(crate) fn contains_cursor_report_request(bytes: &[u8]) -> bool {
    bytes
        .windows(CURSOR_REPORT_REQUEST.len())
        .any(|window| window == CURSOR_REPORT_REQUEST)
}

fn command_payload(
    command: &str,
    no_exit: bool,
    lines: RemoteLines,
) -> Result<Vec<u8>, ClientError> {
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
    Ok(encoded_buffer(&bytes))
}

pub(crate) fn encoded_buffer(bytes: &[u8]) -> Vec<u8> {
    TerminalBuffer {
        buffer: Some(bytes.to_vec()),
    }
    .encode_to_vec()
}

#[cfg(test)]
pub(crate) fn send_buffer(connection: &mut Connection, bytes: &[u8]) -> Result<(), ConnError> {
    connection.write_packet(
        TerminalPacketType::TerminalBuffer as u8,
        &encoded_buffer(bytes),
    )
}

pub(crate) enum OwnedWriteOutcome {
    Written,
    Recovered,
    SessionEnded,
}

pub(crate) fn write_owned_recovering<F>(
    connection: &mut Connection,
    header: u8,
    payload: &[u8],
    reconnect: &mut F,
    send_terminal_size: bool,
) -> Result<OwnedWriteOutcome, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    write_owned_recovering_with(
        connection,
        header,
        payload,
        reconnect,
        send_terminal_size,
        |connection, header, payload| connection.write_packet_owned(header, payload),
    )
}

fn write_owned_recovering_with<F, W>(
    connection: &mut Connection,
    header: u8,
    payload: &[u8],
    reconnect: &mut F,
    send_terminal_size: bool,
    mut write: W,
) -> Result<OwnedWriteOutcome, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
    W: FnMut(&mut Connection, u8, &[u8]) -> Result<(), WritePacketError>,
{
    let mut recovered = false;
    loop {
        match write(connection, header, payload) {
            Ok(()) => {
                return Ok(if recovered {
                    OwnedWriteOutcome::Recovered
                } else {
                    OwnedWriteOutcome::Written
                });
            }
            Err(WritePacketError::BeforeReplay(error)) if connection_ended(&error) => {
                connection.disconnect();
                if !recover_transport(connection, reconnect, send_terminal_size)? {
                    return Ok(OwnedWriteOutcome::SessionEnded);
                }
                recovered = true;
            }
            Err(WritePacketError::ReplayOwned(error)) if connection_ended(&error) => {
                return Ok(
                    if recover_transport(connection, reconnect, send_terminal_size)? {
                        OwnedWriteOutcome::Recovered
                    } else {
                        OwnedWriteOutcome::SessionEnded
                    },
                );
            }
            Err(error) => return Err(terminal_error(error.into_inner())),
        }
    }
}

pub(crate) fn terminal_size_payload() -> Result<Option<Vec<u8>>, ClientError> {
    if !io::stdout().is_terminal() {
        return Ok(None);
    }
    let (columns, rows) = size().map_err(|error| terminal_io("reading terminal size", error))?;
    let message = TerminalInfo {
        id: None,
        row: Some(i32::from(rows)),
        column: Some(i32::from(columns)),
        width: Some(0),
        height: Some(0),
    };
    Ok(Some(message.encode_to_vec()))
}

/// Finish an initial client write without losing a session to a race between
/// the handshake and the first terminal packet.
///
/// `Connection` has already retained a packet whose socket write failed.
/// Recovery replays that exact packet, so this deliberately does not retry
/// `result` after reconnecting (retrying a command could execute it twice).
#[cfg(test)]
fn recover_initial_transport<F>(
    connection: &mut Connection,
    reconnect: &mut F,
    send_terminal_size: bool,
    result: Result<(), ClientError>,
) -> Result<bool, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    match result {
        Ok(()) => Ok(true),
        Err(ClientError::Transport(error)) if connection_ended(&error) => {
            recover_transport(connection, reconnect, send_terminal_size)
        }
        Err(error) => Err(error),
    }
}

/// Recover a broken live transport, including a connection that fails again
/// while its post-recovery terminal-size packet is being sent.
///
/// The latter race is common after laptop wake: Wi-Fi can become routable long
/// enough for TCP recovery and then lose the first application packet.  Keep
/// recovery inside the reconnect loop until a live terminal-size update has
/// been sent, just as upstream reconnects after every socket read/write
/// error.
pub(crate) fn recover_transport<F>(
    connection: &mut Connection,
    reconnect: &mut F,
    send_terminal_size: bool,
) -> Result<bool, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let mut replay_owns_size = false;
    loop {
        match reconnect(connection)? {
            ReconnectOutcome::SessionEnded => return Ok(false),
            ReconnectOutcome::Recovered if !send_terminal_size || replay_owns_size => {
                return Ok(true);
            }
            ReconnectOutcome::Recovered => {
                let Some(payload) = terminal_size_payload()? else {
                    return Ok(true);
                };
                match connection
                    .write_packet_owned(TerminalPacketType::TerminalInfo as u8, &payload)
                {
                    Ok(()) => return Ok(true),
                    Err(WritePacketError::BeforeReplay(error)) if connection_ended(&error) => {
                        connection.disconnect();
                    }
                    Err(WritePacketError::ReplayOwned(error)) if connection_ended(&error) => {
                        replay_owns_size = true;
                    }
                    Err(error) => return Err(terminal_error(error.into_inner())),
                }
            }
        }
    }
}

/// Reset sequences for terminal modes a remote application may have enabled
/// in the local emulator. The session can end while the remote side has no
/// chance to restore them (connection lost, reconnect given up), which
/// otherwise leaves the shell prompt receiving kitty keyboard reports
/// (`CSI … u`, seen as garbage like `2618;9u`), mouse reports, or bracketed
/// paste markers as literal text. Terminals ignore sequences they do not
/// support, and every reset is a no-op when the mode is already off.
///
/// In order: pop and zero the kitty keyboard flags on the current (possibly
/// alternate) screen, leave the alternate screen, pop and zero the kitty
/// flags again on the main screen (the stacks are per-screen), disable
/// xterm modifyOtherKeys, bracketed paste, focus reporting and all mouse
/// modes, and show the cursor.
const TERMINAL_MODE_RESET: &[u8] = b"\x1b[<64u\x1b[=0;1u\x1b[?1049l\x1b[<64u\x1b[=0;1u\
\x1b[>4;0m\x1b[?2004l\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h";

/// Cleanup when the remote byte stream left no alternate screen active.
/// Sending an unmatched alternate-screen leave would restore an unrelated
/// saved cursor in the local emulator, so only the idempotent input-mode
/// cleanup runs on the current main screen.
const GRACEFUL_TERMINAL_MODE_RESET: &[u8] = b"\x1b[<64u\x1b[=0;1u\
\x1b[>4;0m\x1b[?2004l\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h";

#[derive(Default)]
struct TerminalModeInner {
    alternate_prefix_len: usize,
    alternate_screen: bool,
}

#[derive(Clone, Default)]
pub(crate) struct TerminalModeState(std::sync::Arc<std::sync::Mutex<TerminalModeInner>>);

impl TerminalModeState {
    pub(crate) fn observe(&self, bytes: &[u8]) {
        const PREFIX: &[u8] = b"\x1b[?1049";
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        for &byte in bytes {
            if state.alternate_prefix_len == PREFIX.len() {
                match byte {
                    b'h' => state.alternate_screen = true,
                    b'l' => state.alternate_screen = false,
                    _ => {}
                }
                state.alternate_prefix_len = usize::from(byte == PREFIX[0]);
            } else if byte == PREFIX[state.alternate_prefix_len] {
                state.alternate_prefix_len += 1;
            } else {
                state.alternate_prefix_len = usize::from(byte == PREFIX[0]);
            }
        }
    }

    pub(crate) fn alternate_screen(&self) -> bool {
        self.0.lock().is_ok_and(|state| state.alternate_screen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalReset {
    LeaveAlternate,
    KeepCurrentScreen,
}

impl TerminalReset {
    const fn for_alternate_screen(alternate_screen: bool) -> Self {
        if alternate_screen {
            Self::LeaveAlternate
        } else {
            Self::KeepCurrentScreen
        }
    }

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::LeaveAlternate => TERMINAL_MODE_RESET,
            Self::KeepCurrentScreen => GRACEFUL_TERMINAL_MODE_RESET,
        }
    }
}

struct RawMode {
    enabled: bool,
    reset: TerminalReset,
}

impl RawMode {
    fn enter() -> Result<Self, ClientError> {
        let enabled = io::stdin().is_terminal() && io::stdout().is_terminal();
        if enabled {
            enable_raw_mode().map_err(|error| terminal_io("enabling raw terminal mode", error))?;
        }
        Ok(Self {
            enabled,
            reset: TerminalReset::LeaveAlternate,
        })
    }

    fn finish(
        mut self,
        result: Result<(), ClientError>,
        connection_name: Option<&str>,
        alternate_screen: bool,
    ) -> Result<(), ClientError> {
        self.reset = TerminalReset::for_alternate_screen(alternate_screen);
        drop(self);
        if result.is_ok() {
            if let Some(connection_name) = connection_name {
                let _ = writeln!(
                    io::stderr().lock(),
                    "Connection to {connection_name} closed."
                );
            }
        }
        result
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.enabled {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(self.reset.bytes());
            let _ = stdout.flush();
            let _ = disable_raw_mode();
        }
    }
}

/// Errors that mean the TCP transport is no longer usable and the session
/// must reconnect rather than exit.
///
/// In particular, macOS reports a stale TCP flow after sleep as `ETIMEDOUT`
/// (`io::ErrorKind::TimedOut`), not necessarily as EOF or reset.  There is no
/// actionable socket I/O failure for the terminal loop: the connection state
/// is preserved in the backed reader/writer, so every socket I/O error enters
/// recovery.  Protocol, crypto, framing, backpressure, and local-terminal
/// errors use other `ConnError` variants and still remain fatal.
///
/// This matches upstream `Connection::read`/`write`, which closes and starts
/// its reconnect loop for both skippable and "serious" socket errors.
pub(crate) fn connection_ended(error: &ConnError) -> bool {
    matches!(error, ConnError::Io(_))
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
