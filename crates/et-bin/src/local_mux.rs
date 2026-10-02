//! OpenSSH PROTOCOL.mux v4 passenger and request codecs (#853).
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use crate::local_ipc::{self as ipc, Decoder};
use et_cli::client::{ClientArgs, ControlMasterMode};
use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};

pub const HELLO: u32 = 1;
pub const NEW_SESSION: u32 = 0x10000002;
pub const ALIVE: u32 = 0x10000004;
pub const TERMINATE: u32 = 0x10000005;
pub const OPEN_FWD: u32 = 0x10000006;
pub const CLOSE_FWD: u32 = 0x10000007;
pub const STOP: u32 = 0x10000009;
pub const OK: u32 = 0x80000001;
pub const FAILURE: u32 = 0x80000003;
pub const EXIT: u32 = 0x80000004;
pub const ALIVE_REPLY: u32 = 0x80000005;
pub const OPENED: u32 = 0x80000006;

pub fn socket_exists(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
}
pub fn passenger(args: &ClientArgs) -> bool {
    args.control_command.is_some()
        || (args.control_master != Some(ControlMasterMode::Yes)
            && args.control_path.as_deref().is_some_and(socket_exists))
}
pub fn master(args: &ClientArgs) -> bool {
    matches!(
        args.control_master,
        Some(ControlMasterMode::Yes | ControlMasterMode::Auto)
    ) && args.control_path.is_some()
}
pub fn failure(request: u32, message: &str) -> Vec<u8> {
    let mut reply = ipc::words(&[FAILURE, request]);
    ipc::string(&mut reply, message.as_bytes());
    ipc::mux_frame(&reply)
}
pub fn forward(decoder: &mut Decoder<'_>) -> io::Result<PortForwardSourceRequest> {
    if decoder.u32()? != 1 {
        return Err(ipc::invalid("only local mux forwards are supported"));
    }
    fn endpoint(decoder: &mut Decoder<'_>, destination: bool) -> io::Result<SocketEndpoint> {
        let name = decoder.text()?;
        let port = decoder.u32()?;
        let port = if port == u32::MAX - 1 {
            None
        } else {
            Some(u16::try_from(port).map_err(|_| ipc::invalid("invalid mux forward port"))? as i32)
        };
        Ok(SocketEndpoint {
            name: if destination && name.is_empty() {
                None
            } else {
                Some(name)
            },
            port,
        })
    }
    let source = endpoint(decoder, false)?;
    let destination = endpoint(decoder, true)?;
    if !decoder.0.is_empty() {
        return Err(ipc::invalid("trailing forward data"));
    }
    Ok(PortForwardSourceRequest {
        source: Some(source),
        destination: Some(destination),
        environmentvariable: None,
    })
}
fn forward_body(kind: u32, id: u32, request: &PortForwardSourceRequest) -> io::Result<Vec<u8>> {
    let mut body = ipc::words(&[kind, id, 1]);
    for endpoint in [&request.source, &request.destination] {
        let endpoint = endpoint
            .as_ref()
            .ok_or_else(|| ipc::invalid("missing forward endpoint"))?;
        ipc::string(&mut body, endpoint.name.as_deref().unwrap_or("").as_bytes());
        body.extend_from_slice(
            &endpoint
                .port
                .map_or(u32::MAX - 1, |p| p as u32)
                .to_be_bytes(),
        );
    }
    Ok(body)
}

pub fn try_run(args: &ClientArgs) -> io::Result<Option<i32>> {
    let path = args
        .control_path
        .as_deref()
        .ok_or_else(|| ipc::invalid("-O requires ControlPath/-S"))?;
    let socket = match ipc::connect(Path::new(path)) {
        Ok(socket) => socket,
        Err(error)
            if args.control_command.is_none()
                && matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    run(args, socket).map(Some)
}

fn run(args: &ClientArgs, mut socket: std::os::unix::net::UnixStream) -> io::Result<i32> {
    if !args.reverse_tunnel.is_empty() || !args.dynamic.is_empty() || args.stdio_forward.is_some() {
        return Err(ipc::invalid(
            "mux remote/dynamic/stdio forwarding is unsupported",
        ));
    }
    socket.write_all(&ipc::mux_frame(&ipc::words(&[HELLO, 4])))?;
    let hello = ipc::read_mux(&mut socket)?;
    let mut hello = Decoder(&hello);
    if hello.u32()? != HELLO || hello.u32()? != 4 {
        return Err(ipc::invalid("unsupported mux version"));
    }
    while !hello.0.is_empty() {
        hello.string()?;
        hello.string()?;
    }
    let command = args
        .control_command
        .as_deref()
        .or((!args.tunnel.is_empty()).then_some("forward"));
    if let Some(command) = command {
        let kind = match command {
            "check" => ALIVE,
            "exit" => TERMINATE,
            "stop" => STOP,
            "forward" => OPEN_FWD,
            "cancel" => CLOSE_FWD,
            _ => return Err(ipc::invalid("unknown mux control command")),
        };
        let requests = if matches!(kind, OPEN_FWD | CLOSE_FWD) {
            let forwards = et_cli::tunnel::parse_tunnels(&args.tunnel)
                .map_err(|e| ipc::invalid(&e.to_string()))?;
            if forwards.is_empty() {
                return Err(ipc::invalid("forward/cancel requires -L or --tunnel"));
            }
            forwards
                .iter()
                .enumerate()
                .map(|(id, f)| forward_body(kind, id as u32, f))
                .collect::<io::Result<Vec<_>>>()?
        } else {
            vec![ipc::words(&[kind, 0])]
        };
        for (id, request) in requests.iter().enumerate() {
            socket.write_all(&ipc::mux_frame(request))?;
            let reply = ipc::read_mux(&mut socket)?;
            let mut reply = Decoder(&reply);
            let response = reply.u32()?;
            if reply.u32()? != id as u32 {
                return Err(ipc::invalid("mux request id mismatch"));
            }
            match response {
                OK => {}
                ALIVE_REPLY if kind == ALIVE => println!("Master running (pid={})", reply.u32()?),
                FAILURE => return Err(ipc::invalid(&reply.text()?)),
                _ => return Err(ipc::invalid("unexpected mux reply")),
            }
        }
        if args.control_command.is_some() {
            crate::local_daemon::ready()?;
            return Ok(0);
        }
    }
    if args.no_remote_command {
        crate::local_daemon::ready()?;
        return Ok(0);
    }
    if args.no_pty {
        return Err(ipc::invalid("raw -T mux passengers are unsupported"));
    }
    crate::local_daemon::detach()?;
    let tty = io::stdin().is_terminal();
    let mut request = ipc::words(&[NEW_SESSION, 0]);
    ipc::string(&mut request, b"");
    // The shared remote shell is always PTY-backed, including redirected
    // local input. Only local raw-mode handling depends on is_terminal().
    request.extend(ipc::words(&[1, 0, 0, 0, u32::MAX]));
    ipc::string(
        &mut request,
        std::env::var("TERM")
            .unwrap_or_else(|_| "xterm".to_owned())
            .as_bytes(),
    );
    ipc::string(
        &mut request,
        args.command.as_deref().unwrap_or("").as_bytes(),
    );
    socket.write_all(&ipc::mux_frame(&request))?;
    ipc::send_fd(&socket, io::stdin())?;
    ipc::send_fd(&socket, io::stdout())?;
    ipc::send_fd(&socket, io::stderr())?;
    let reply = ipc::read_mux(&mut socket)?;
    let mut reply = Decoder(&reply);
    let kind = reply.u32()?;
    if reply.u32()? != 0 {
        return Err(ipc::invalid("mux request id mismatch"));
    }
    if kind == FAILURE {
        return Err(ipc::invalid(&reply.text()?));
    }
    if kind != OPENED {
        return Err(ipc::invalid("expected session opened"));
    }
    let id = reply.u32()?;
    crate::local_daemon::ready()?;
    struct Raw(bool);
    impl Drop for Raw {
        fn drop(&mut self) {
            if self.0 {
                let _ = crossterm::terminal::disable_raw_mode();
            }
        }
    }
    let _raw = Raw(tty && crossterm::terminal::enable_raw_mode().is_ok());
    socket.set_read_timeout(None)?;
    let reply = ipc::read_mux(&mut socket)?;
    let mut reply = Decoder(&reply);
    if reply.u32()? != EXIT || reply.u32()? != id {
        return Err(ipc::invalid("expected session exit"));
    }
    Ok(reply.u32()?.min(255) as i32)
}

/// Strip the status sentinel across arbitrary packet boundaries. Commands run
/// in a subshell so `exit` never tears down the master's shared remote shell.
#[cfg_attr(test, derive(Clone))]
pub struct ExitMarker {
    carry: Vec<u8>,
    marker: String,
}
impl ExitMarker {
    pub fn new() -> Self {
        Self {
            carry: Vec::new(),
            marker: format!(
                "__ET_PASSENGER_EXIT_{}__:",
                et_core::keys::gen_id_passkey().1
            ),
        }
    }
    pub fn command(&self, command: &str) -> String {
        format!("({command}); printf '\\n{}%d\\n' $?\n", self.marker)
    }
    pub fn consume(&mut self, bytes: &[u8]) -> (Vec<u8>, Option<u32>) {
        let marker = self.marker.as_bytes();
        self.carry.extend_from_slice(bytes);
        // The echoed printf command contains the marker followed by %d, so
        // accept only a complete numeric status followed by a line ending.
        let mut scan = 0;
        while scan + marker.len() <= self.carry.len() {
            let Some(offset) = self.carry[scan..]
                .windows(marker.len())
                .position(|s| s == marker)
            else {
                break;
            };
            let start = scan + offset;
            let digits = start + marker.len();
            if let Some(end) = self.carry[digits..].iter().position(|b| *b == b'\n') {
                let number = &self.carry[digits..digits + end];
                let number = number.strip_suffix(b"\r").unwrap_or(number);
                if !number.is_empty() && number.len() <= 3 && number.iter().all(u8::is_ascii_digit)
                {
                    let code = std::str::from_utf8(number)
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok())
                        .filter(|c| *c <= 255);
                    if let Some(code) = code {
                        let output = self.carry[..start].to_vec();
                        self.carry.clear();
                        return (output, Some(code));
                    }
                }
                scan = digits;
            } else {
                if self.carry.len() - digits <= 4 {
                    let output = self.carry.drain(..start).collect();
                    return (output, None);
                }
                scan = digits;
            }
        }
        let retain = (1..marker.len())
            .rev()
            .find(|&n| self.carry.ends_with(&marker[..n]))
            .unwrap_or(0);
        let output = self.carry.drain(..self.carry.len() - retain).collect();
        (output, None)
    }
}
