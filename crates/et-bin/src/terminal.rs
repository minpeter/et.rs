use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::Parser;
use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use et_net::local_packet::write_local_packet;
use et_server::path::select_router_path;
use prost::Message;

use crate::terminal_credentials::{parse_credential_input, CredentialInput};
use crate::terminal_pty;

const MAX_CREDENTIAL_INPUT: u64 = 4096;

#[derive(Debug, Parser)]
#[command(name = "etterminal")]
struct TerminalArgs {
    #[arg(long)]
    serverfifo: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    verbose: u8,
    #[arg(long, conflicts_with = "idpasskeyfile")]
    idpasskey: Option<String>,
    #[arg(long)]
    idpasskeyfile: Option<PathBuf>,
    #[arg(long, hide = true)]
    session_child: bool,
    #[arg(long, hide = true, requires = "session_child")]
    ready_socket: Option<PathBuf>,
}

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = TerminalArgs::try_parse_from(
        ["etterminal"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
    let input = load_credentials(&parsed).map_err(clap_error)?;
    let router_path = select_router_path(parsed.serverfifo.as_deref())
        .map_err(|error| clap_error(error.to_string()))?;
    if !parsed.session_child {
        crate::terminal_daemon::spawn(router_path.path(), &input, parsed.verbose)
            .map_err(clap_error)?;
        return print_marker(&input);
    }
    let mut router = UnixStream::connect(router_path.path())
        .map_err(|error| clap_error(format!("could not connect terminal router: {error}")))?;
    register(&mut router, &input).map_err(clap_error)?;
    let ready_socket = parsed
        .ready_socket
        .as_deref()
        .ok_or_else(|| clap_error("terminal session child has no readiness socket"))?;
    crate::terminal_daemon::signal(ready_socket).map_err(clap_error)?;
    terminal_pty::run(router, &input.term).map_err(clap_error)
}

fn print_marker(input: &CredentialInput) -> Result<i32, clap::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "IDPASSKEY:{}/{}", input.id, input.passkey)
        .and_then(|()| output.flush())
        .map_err(|error| clap_error(format!("could not write bootstrap marker: {error}")))?;
    Ok(0)
}

fn load_credentials(args: &TerminalArgs) -> Result<CredentialInput, String> {
    if let Some(path) = args.idpasskeyfile.as_deref() {
        let mut value = String::new();
        fs::File::open(path)
            .map_err(|error| format!("could not open id/passkey file: {error}"))?
            .take(MAX_CREDENTIAL_INPUT + 1)
            .read_to_string(&mut value)
            .map_err(|error| format!("could not read id/passkey file: {error}"))?;
        if value.len() > MAX_CREDENTIAL_INPUT as usize {
            return Err("id/passkey file exceeds 4096 bytes".to_owned());
        }
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        return parse_credential_input(&format!("{}_{}", value.trim(), term));
    }
    if let Some(value) = args.idpasskey.as_deref() {
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        return parse_credential_input(&format!("{value}_{term}"));
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_CREDENTIAL_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read id/passkey from stdin: {error}"))?;
    if bytes.len() > MAX_CREDENTIAL_INPUT as usize {
        return Err("id/passkey input exceeds 4096 bytes".to_owned());
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "id/passkey input is not UTF-8".to_owned())?;
    parse_credential_input(text.trim())
}

fn register(router: &mut UnixStream, input: &CredentialInput) -> Result<(), String> {
    let uid = i64::from(rustix::process::getuid().as_raw());
    let gid = i64::from(rustix::process::getgid().as_raw());
    let user = TerminalUserInfo {
        id: Some(input.id.clone()),
        passkey: Some(input.passkey.clone()),
        uid: Some(uid),
        gid: Some(gid),
        fd: None,
    };
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        user.encode_to_vec(),
    );
    write_local_packet(router, &packet)
        .map_err(|error| format!("could not register terminal: {error}"))
}

fn clap_error(message: impl Into<String>) -> clap::Error {
    clap::Error::raw(ErrorKind::Io, message.into())
}
