use et_net::local::LocalStream;
use std::io::{self, Write};

use et_core::packet::Packet;
use et_core::proto::{
    FlowControlMode, TermInit, TerminalBuffer, TerminalExitStatus, TerminalInfo, TerminalPacketType,
};
use et_net::local_packet::{read_local_packet, write_local_packet, RouterStreamDecoder};
use portable_pty::{MasterPty, PtySize};
use prost::Message;

#[derive(Debug)]
pub struct TerminalInitialization {
    pub environment: Vec<(String, String)>,
    pub flow_control: FlowControlMode,
    /// `TermInit.no_pty`: run `command` on pipes instead of a login pty.
    pub no_pty: bool,
    pub command: Option<String>,
    /// `TermInit.no_shell`: session without a pty or a shell (`et -W`).
    pub no_shell: bool,
    /// The originating session had reverse tunnels before an etserver restart.
    pub had_reverse_tunnels: bool,
    /// Per-session disconnect timeout, in seconds, preserved across restart.
    pub disconnect_timeout_seconds: Option<i32>,
}

/// OpenSSH-style status: the exit code, or `128 + signal` when signaled.
///
/// Windows pipe status has no signal number, so only the Unix path calls this.
#[cfg(unix)]
pub(crate) fn openssh_exit_code(exited: Option<i32>, signal: Option<i32>) -> i32 {
    if let Some(code) = exited {
        return code;
    }
    if let Some(signal) = signal {
        return 128i32.saturating_add(signal);
    }
    0
}

pub fn read_initialization(router: &mut LocalStream) -> Result<TerminalInitialization, String> {
    let packet = read_local_packet(router)
        .map_err(|error| format!("could not read terminal initialization: {error}"))?;
    if packet.is_encrypted() || packet.header() != TerminalPacketType::TerminalInit as u8 {
        return Err("expected plaintext TERMINAL_INIT packet".to_owned());
    }
    let init = TermInit::decode(packet.payload())
        .map_err(|_| "TERMINAL_INIT protobuf is malformed".to_owned())?;
    if init.environmentnames.len() != init.environmentvalues.len() {
        return Err("TERMINAL_INIT environment lists are invalid".to_owned());
    }
    let flow_control = init
        .flowcontrol
        .and_then(|value| FlowControlMode::try_from(value).ok())
        .unwrap_or(FlowControlMode::None);
    // Upstream `UserTerminalHandler::run` calls setenv(3) for each entry and
    // ignores failures: no count, size or portable-name limit applies beyond
    // the local message cap. Skip only what setenv rejects, on every platform.
    let environment = init
        .environmentnames
        .into_iter()
        .zip(init.environmentvalues)
        .filter(|(name, value)| {
            let applicable = setenv_accepts(name, value);
            if !applicable {
                et_cli::logging::info(format!(
                    "skipping TERMINAL_INIT environment entry {name:?}: setenv rejects it"
                ));
            }
            applicable
        })
        .collect();
    let no_pty = init.no_pty.unwrap_or(false);
    let no_shell = init.no_shell.unwrap_or(false);
    if no_pty && no_shell {
        return Err("no_pty and no_shell cannot both be set".to_owned());
    }
    Ok(TerminalInitialization {
        environment,
        flow_control,
        no_pty,
        command: init.command,
        no_shell,
        had_reverse_tunnels: init.hadreversetunnels.unwrap_or(false),
        disconnect_timeout_seconds: init.disconnect_timeout_seconds,
    })
}

/// Send `TERMINAL_EXIT_STATUS` once, before the terminal router closes.
///
/// A write failure is returned to the caller, which logs it and still exits.
/// The packet must not be dropped on the floor when the write itself succeeds.
pub(crate) fn write_terminal_exit_status(
    router: &mut LocalStream,
    code: i32,
) -> Result<(), String> {
    let payload = TerminalExitStatus {
        exitcode: Some(code),
    }
    .encode_to_vec();
    let packet = Packet::new(TerminalPacketType::TerminalExitStatus as u8, payload);
    write_local_packet(router, &packet)
        .map_err(|error| format!("could not write terminal exit status: {error}"))
}

/// Read one message of the router stream that follows `TERMINAL_INIT` (or a
/// live pty's re-registration). `Ok(None)` means the router would block.
pub fn read_ready_packet(
    router: &mut LocalStream,
    decoder: &mut RouterStreamDecoder,
) -> Result<Option<Packet>, String> {
    match decoder.read_from(router) {
        Ok(packet) => Ok(packet),
        Err(et_net::local_packet::LocalPacketError::Io(error))
            if error.kind() == io::ErrorKind::UnexpectedEof =>
        {
            Err("terminal router disconnected".to_owned())
        }
        Err(et_net::local_packet::LocalPacketError::Io(error)) => {
            Err(format!("could not read terminal router: {error}"))
        }
        Err(error) => Err(format!("malformed terminal packet: {error}")),
    }
}

/// What a router message asks `etterminal` to do.
///
/// `Close` is the success path for upstream `TERMINAL_CLOSE`: stop the PTY
/// session without reporting an unsupported-packet error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalPacketEffect {
    Continue,
    Close,
}

pub(crate) fn local_packet_effect(packet: &Packet) -> Result<LocalPacketEffect, String> {
    if packet.is_encrypted() {
        return Err("encrypted local terminal packet rejected".to_owned());
    }
    match packet.header() {
        header
            if header == TerminalPacketType::TerminalBuffer as u8
                || header == TerminalPacketType::TerminalInfo as u8 =>
        {
            Ok(LocalPacketEffect::Continue)
        }
        header if header == TerminalPacketType::TerminalClose as u8 => Ok(LocalPacketEffect::Close),
        _ => Err("unsupported local terminal packet type".to_owned()),
    }
}

/// Protocol mistakes stay fatal. A dead pty is not: the child may already
/// have exited, and `TERMINAL_EXIT_STATUS` still has to be written.
#[derive(Debug)]
pub(crate) enum TerminalPacketError {
    Protocol(String),
    Pty(io::Error),
}

impl std::fmt::Display for TerminalPacketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => formatter.write_str(error),
            Self::Pty(error) => write!(formatter, "could not apply PTY input: {error}"),
        }
    }
}

/// What a router packet asks the PTY runtime to do, decoded without touching
/// the PTY so readiness-driven runtimes can own their non-blocking writes.
pub(crate) enum TerminalCommand<'a> {
    /// Keystrokes for the PTY. Canonical `TERMINAL_BUFFER` payloads borrow
    /// straight from the packet.
    Input(std::borrow::Cow<'a, [u8]>),
    Resize(PtySize),
    Close,
}

pub(crate) fn terminal_command(
    packet: &Packet,
) -> Result<TerminalCommand<'_>, TerminalPacketError> {
    if local_packet_effect(packet).map_err(TerminalPacketError::Protocol)?
        == LocalPacketEffect::Close
    {
        return Ok(TerminalCommand::Close);
    }
    match packet.header() {
        header if header == TerminalPacketType::TerminalBuffer as u8 => {
            if let Some((bytes, _)) = et_core::packet::decode_terminal_buffer(packet.payload()) {
                return Ok(TerminalCommand::Input(std::borrow::Cow::Borrowed(bytes)));
            }
            let message = TerminalBuffer::decode(packet.payload()).map_err(|_| {
                TerminalPacketError::Protocol("TERMINAL_BUFFER protobuf is malformed".to_owned())
            })?;
            let bytes = message.buffer.ok_or_else(|| {
                TerminalPacketError::Protocol("TERMINAL_BUFFER is missing bytes".to_owned())
            })?;
            Ok(TerminalCommand::Input(std::borrow::Cow::Owned(bytes)))
        }
        header if header == TerminalPacketType::TerminalInfo as u8 => {
            let info = TerminalInfo::decode(packet.payload()).map_err(|_| {
                TerminalPacketError::Protocol("TERMINAL_INFO protobuf is malformed".to_owned())
            })?;
            if info.command == Some(et_core::proto::terminal_info::Command::KillSession as i32)
                && info.commandversion == Some(et_core::SESSION_KILL_COMMAND_VERSION)
            {
                return Ok(TerminalCommand::Close);
            }
            // An unsupported command version is ignored. Resize still applies.
            Ok(TerminalCommand::Resize(terminal_size(&info)))
        }
        _ => Err(TerminalPacketError::Protocol(
            "unsupported local terminal packet type".to_owned(),
        )),
    }
}

pub fn handle_packet(
    packet: Packet,
    master: &dyn MasterPty,
    writer: &mut dyn Write,
) -> Result<LocalPacketEffect, TerminalPacketError> {
    match terminal_command(&packet)? {
        TerminalCommand::Close => Ok(LocalPacketEffect::Close),
        TerminalCommand::Input(bytes) => {
            writer
                .write_all(&bytes)
                .and_then(|()| writer.flush())
                .map_err(TerminalPacketError::Pty)?;
            Ok(LocalPacketEffect::Continue)
        }
        TerminalCommand::Resize(size) => {
            master
                .resize(size)
                .map_err(|error| TerminalPacketError::Pty(io::Error::other(error)))?;
            Ok(LocalPacketEffect::Continue)
        }
    }
}

/// POSIX setenv(3) fails with EINVAL for an empty name or one containing `=`;
/// a C string cannot carry NUL in either the name or the value.
fn setenv_accepts(name: &str, value: &str) -> bool {
    !name.is_empty() && !name.contains(['=', '\0']) && !value.contains('\0')
}

/// Convert a `TERMINAL_INFO` payload into a PTY size with upstream semantics.
///
/// Upstream (`UserTerminalHandler.cpp`) assigns the int32 protobuf fields
/// straight into a `winsize` struct (`unsigned short` members) and calls
/// `TIOCSWINSZ` without validation. That means missing fields become 0,
/// zero sizes are accepted (terminals report 0x0 when no real TTY backs
/// them, e.g. under `script` or CI), and out-of-range values truncate.
fn terminal_size(info: &TerminalInfo) -> PtySize {
    fn dimension(value: Option<i32>) -> u16 {
        (value.unwrap_or(0) as u32 & 0xFFFF) as u16
    }
    PtySize {
        rows: dimension(info.row),
        cols: dimension(info.column),
        pixel_width: dimension(info.width),
        pixel_height: dimension(info.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::packet::Packet;
    use et_net::local_packet::write_local_packet;

    #[test]
    fn resize_accepts_zero_and_truncates_like_upstream_winsize() {
        // Upstream copies int32 fields into `winsize` (unsigned short) without
        // validation; 0x0 windows (script/CI/emacs shells) must not error.
        let zero = terminal_size(&TerminalInfo {
            row: Some(0),
            column: Some(0),
            ..Default::default()
        });
        assert_eq!((zero.rows, zero.cols), (0, 0));
        assert_eq!((zero.pixel_width, zero.pixel_height), (0, 0));

        let truncated = terminal_size(&TerminalInfo {
            row: Some(65536 + 24),
            column: Some(-1),
            width: Some(70_000),
            height: None,
            ..Default::default()
        });
        assert_eq!(truncated.rows, 24);
        assert_eq!(truncated.cols, 65535);
        assert_eq!(truncated.pixel_width, (70_000u32 & 0xFFFF) as u16);
        assert_eq!(truncated.pixel_height, 0);
    }

    #[test]
    fn resize_accepts_upstream_terminal_geometry() {
        let size = terminal_size(&TerminalInfo {
            row: Some(40),
            column: Some(100),
            width: Some(800),
            height: Some(600),
            ..Default::default()
        });
        assert_eq!(size.rows, 40);
        assert_eq!(size.cols, 100);
        assert_eq!(size.pixel_width, 800);
        assert_eq!(size.pixel_height, 600);
    }

    #[test]
    fn initialization_rejects_wrong_type_malformed_and_mismatched_environment() {
        let wrong_type = Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            TerminalBuffer {
                buffer: Some(Vec::new()),

                is_stderr: None,
            }
            .encode_to_vec(),
        );
        assert!(read_environment_packet(wrong_type).is_err());
        assert!(read_environment_packet(Packet::new(
            TerminalPacketType::TerminalInit as u8,
            vec![0xff]
        ))
        .is_err());
        let mismatched = TermInit {
            environmentnames: vec!["A".to_owned()],
            environmentvalues: Vec::new(),
            ..TermInit::default()
        };
        let packet = Packet::new(
            TerminalPacketType::TerminalInit as u8,
            mismatched.encode_to_vec(),
        );
        assert!(read_environment_packet(packet).is_err());
    }

    #[test]
    fn initialization_applies_any_environment_and_skips_only_what_setenv_rejects() {
        // Upstream calls setenv(3) for every entry and ignores failures: no
        // count, value-size or portable-name limit (et.rs 0.0.43 had all three).
        let mut expected: Vec<(String, String)> = (0..200)
            .map(|index| (format!("E_{index:03}"), format!("v{index}")))
            .collect();
        expected.extend([
            ("BIG".to_owned(), "x".repeat(5000)),
            ("MY-VAR".to_owned(), "dash".to_owned()),
            ("1ABC".to_owned(), "digit".to_owned()),
            ("UNICODE_\u{e9}".to_owned(), "\u{1f600}".to_owned()),
        ]);
        let mut entries = expected.clone();
        entries.extend([
            ("BROKEN=NAME".to_owned(), "skipped".to_owned()),
            (String::new(), "skipped".to_owned()),
            ("NUL\0NAME".to_owned(), "skipped".to_owned()),
            ("NUL_VALUE".to_owned(), "bad\0value".to_owned()),
        ]);
        let init = TermInit {
            environmentnames: entries.iter().map(|(name, _)| name.clone()).collect(),
            environmentvalues: entries.into_iter().map(|(_, value)| value).collect(),
            ..TermInit::default()
        };
        let packet = Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec());
        assert_eq!(read_environment_packet(packet).unwrap(), expected);
    }

    fn read_environment_packet(packet: Packet) -> Result<Vec<(String, String)>, String> {
        let (mut reader, mut writer) = et_net::local::wake_pair().unwrap();
        write_local_packet(&mut writer, &packet).unwrap();
        read_initialization(&mut reader).map(|initialization| initialization.environment)
    }

    #[test]
    fn terminal_close_is_a_clean_effect_and_unknown_types_stay_errors() {
        assert_eq!(TerminalPacketType::TerminalClose as u8, 11);
        assert_eq!(et_core::PROTOCOL_VERSION, 6);
        let close = Packet::new(TerminalPacketType::TerminalClose as u8, Vec::new());
        assert_eq!(
            local_packet_effect(&close).unwrap(),
            LocalPacketEffect::Close
        );
        let buffer = Packet::new(TerminalPacketType::TerminalBuffer as u8, Vec::new());
        assert_eq!(
            local_packet_effect(&buffer).unwrap(),
            LocalPacketEffect::Continue
        );
        let unknown = Packet::new(4, Vec::new());
        let error = local_packet_effect(&unknown).unwrap_err();
        assert!(error.contains("unsupported"));
        let encrypted = Packet::raw(true, TerminalPacketType::TerminalClose as u8, Vec::new());
        assert!(local_packet_effect(&encrypted).is_err());
    }

    #[test]
    fn initialization_retains_the_typed_flow_control_mode() {
        let (mut terminal, mut server) = et_net::local::wake_pair().unwrap();
        let init = TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: Some(FlowControlMode::Discard as i32),

            no_pty: None,
            command: None,
            no_shell: None,
            disconnect_timeout_seconds: None,
            hadreversetunnels: None,
        };
        write_local_packet(
            &mut server,
            &Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec()),
        )
        .unwrap();

        let initialization = read_initialization(&mut terminal).unwrap();
        assert_eq!(initialization.flow_control, FlowControlMode::Discard);
        assert!(!initialization.no_shell);
    }

    #[cfg(unix)]
    #[test]
    fn openssh_exit_code_prefers_exit_status_then_signal() {
        assert_eq!(openssh_exit_code(Some(0), None), 0);
        assert_eq!(openssh_exit_code(Some(2), Some(15)), 2);
        assert_eq!(openssh_exit_code(None, Some(15)), 143);
        assert_eq!(openssh_exit_code(None, None), 0);
    }

    #[test]
    fn no_shell_and_no_pty_together_are_rejected() {
        let (mut terminal, mut server) = et_net::local::wake_pair().unwrap();
        let init = TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
            no_pty: Some(true),
            command: Some("true".to_owned()),
            no_shell: Some(true),
            disconnect_timeout_seconds: None,
            hadreversetunnels: None,
        };
        write_local_packet(
            &mut server,
            &Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec()),
        )
        .unwrap();
        let error = read_initialization(&mut terminal).unwrap_err();
        assert!(error.contains("no_pty and no_shell"));
    }
}
