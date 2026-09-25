use et_net::local::LocalStream;
use std::io::{self, Read, Write};

use et_core::packet::Packet;
use et_core::proto::{
    FlowControlMode, TermInit, TerminalBuffer, TerminalExitStatus, TerminalInfo, TerminalPacketType,
};
use et_net::local_packet::{read_local_packet, write_local_packet, LocalPacketDecoder};
use portable_pty::{MasterPty, PtySize};
use prost::Message;

pub(crate) const MAX_ENVIRONMENT: usize = 128;
pub(crate) const MAX_ENV_VALUE: usize = 4096;
const READ_BUFFER: usize = 16 * 1024;

#[derive(Debug)]
pub struct TerminalInitialization {
    pub environment: Vec<(String, String)>,
    pub flow_control: FlowControlMode,
    /// `TermInit.no_pty`: run `command` on pipes instead of a login pty.
    pub no_pty: bool,
    pub command: Option<String>,
    /// `TermInit.no_shell`: session without a pty or a shell (`et -W`).
    pub no_shell: bool,
}

/// OpenSSH-style status: the exit code, or `128 + signal` when signaled.
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
    if init.environmentnames.len() != init.environmentvalues.len()
        || init.environmentnames.len() > MAX_ENVIRONMENT
    {
        return Err("TERMINAL_INIT environment lists are invalid".to_owned());
    }
    let flow_control = init
        .flowcontrol
        .and_then(|value| FlowControlMode::try_from(value).ok())
        .unwrap_or(FlowControlMode::None);
    let environment = init
        .environmentnames
        .into_iter()
        .zip(init.environmentvalues)
        .map(|(name, value)| {
            if !valid_environment_name(&name) || value.len() > MAX_ENV_VALUE || value.contains('\0')
            {
                return Err("TERMINAL_INIT contains an invalid environment entry".to_owned());
            }
            Ok((name, value))
        })
        .collect::<Result<_, _>>()?;
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

pub fn read_ready_packet(
    router: &mut LocalStream,
    decoder: &mut LocalPacketDecoder,
) -> Result<Option<Packet>, String> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let wanted = decoder.required_bytes().min(buffer.len());
        match router.read(&mut buffer[..wanted]) {
            Ok(0) => return Err("terminal router disconnected".to_owned()),
            Ok(count) => {
                if let Some(packet) = decoder
                    .feed(&buffer[..count])
                    .map_err(|error| format!("malformed terminal packet: {error}"))?
                {
                    return Ok(Some(packet));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("could not read terminal router: {error}")),
        }
    }
}

/// What a framed local packet asks `etterminal` to do.
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

pub fn handle_packet(
    packet: Packet,
    master: &dyn MasterPty,
    writer: &mut dyn Write,
) -> Result<LocalPacketEffect, TerminalPacketError> {
    if local_packet_effect(&packet).map_err(TerminalPacketError::Protocol)?
        == LocalPacketEffect::Close
    {
        return Ok(LocalPacketEffect::Close);
    }
    match packet.header() {
        header if header == TerminalPacketType::TerminalBuffer as u8 => {
            let message = TerminalBuffer::decode(packet.payload()).map_err(|_| {
                TerminalPacketError::Protocol("TERMINAL_BUFFER protobuf is malformed".to_owned())
            })?;
            let bytes = message.buffer.ok_or_else(|| {
                TerminalPacketError::Protocol("TERMINAL_BUFFER is missing bytes".to_owned())
            })?;
            writer
                .write_all(&bytes)
                .and_then(|()| writer.flush())
                .map_err(TerminalPacketError::Pty)?;
            Ok(LocalPacketEffect::Continue)
        }
        header if header == TerminalPacketType::TerminalInfo as u8 => {
            let info = TerminalInfo::decode(packet.payload()).map_err(|_| {
                TerminalPacketError::Protocol("TERMINAL_INFO protobuf is malformed".to_owned())
            })?;
            master
                .resize(terminal_size(&info))
                .map_err(|error| TerminalPacketError::Pty(io::Error::other(error)))?;
            Ok(LocalPacketEffect::Continue)
        }
        _ => Err(TerminalPacketError::Protocol(
            "unsupported local terminal packet type".to_owned(),
        )),
    }
}

pub(crate) fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
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
    fn initialization_rejects_wrong_type_malformed_and_invalid_environment() {
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
        for init in [
            TermInit {
                environmentnames: vec!["A".to_owned()],
                environmentvalues: Vec::new(),
                flowcontrol: None,

                no_pty: None,
                command: None,
                no_shell: None,
            },
            TermInit {
                environmentnames: vec!["BAD-NAME".to_owned()],
                environmentvalues: vec!["value".to_owned()],
                flowcontrol: None,

                no_pty: None,
                command: None,
                no_shell: None,
            },
            TermInit {
                environmentnames: vec!["VALID".to_owned()],
                environmentvalues: vec!["bad\0value".to_owned()],
                flowcontrol: None,

                no_pty: None,
                command: None,
                no_shell: None,
            },
            TermInit {
                environmentnames: vec!["VALID".to_owned()],
                environmentvalues: vec!["x".repeat(MAX_ENV_VALUE + 1)],
                flowcontrol: None,

                no_pty: None,
                command: None,
                no_shell: None,
            },
        ] {
            let packet = Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec());
            assert!(read_environment_packet(packet).is_err());
        }
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
