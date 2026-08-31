use et_net::local::LocalStream;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
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
#[command(
    name = "etterminal",
    version = et_cli::VERSION,
    long_version = et_cli::LONG_VERSION
)]
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
    #[arg(short = 'l', long = "logdir", help = "Base directory for log files.")]
    logdir: Option<PathBuf>,
    #[arg(long = "logtostdout", help = "Write log to stdout")]
    logtostdout: bool,
    #[arg(long, help = "Run as a jumphost relay to --dsthost/--dstport")]
    jump: bool,
    #[arg(long, help = "Must be set if jump is set to true")]
    dsthost: Option<String>,
    #[arg(
        long,
        default_value_t = 2022,
        help = "Must be set if jump is set to true"
    )]
    dstport: u16,
}

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let mut parsed = TerminalArgs::try_parse_from(
        ["etterminal"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
    parsed.verbose = et_cli::logging::effective_verbose(parsed.verbose);
    let log_directory = et_cli::logging::effective_log_directory(parsed.logdir.clone());
    let input = load_credentials(&parsed).map_err(clap_error)?;
    // Upstream names these logs `etterminal-<user>-<id>` (or `etjump-...`).
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned());
    et_cli::logging::init(et_cli::logging::LogOptions {
        directory: log_directory,
        prefix: format!(
            "{}-{user}-{}",
            if parsed.jump { "etjump" } else { "etterminal" },
            input.id
        ),
        to_stdout: parsed.logtostdout,
        silent: false,
        append_pid: true,
        verbose: parsed.verbose,
        max_size: et_cli::logging::DEFAULT_MAX_LOG_SIZE,
    });
    let router_path = select_router_path(parsed.serverfifo.as_deref())
        .map_err(|error| clap_error(error.to_string()))?;
    if parsed.jump {
        return run_jump(&parsed, router_path.path(), &input);
    }
    if !parsed.session_child {
        crate::terminal_daemon::spawn(router_path.path(), &input, parsed.verbose)
            .map_err(clap_error)?;
        return print_marker(&input);
    }
    let mut router = et_net::local::connect(router_path.path())
        .map_err(|error| clap_error(format!("could not connect terminal router: {error}")))?;
    register(&mut router, &input).map_err(clap_error)?;
    let ready_socket = parsed
        .ready_socket
        .as_deref()
        .ok_or_else(|| clap_error("terminal session child has no readiness socket"))?;
    crate::terminal_daemon::signal(ready_socket).map_err(clap_error)?;
    terminal_pty::run(router, &input.term).map_err(clap_error)
}

/// `etterminal --jump`: print the marker the client scrapes, then relay the
/// session between the local jumphost router and the final destination,
/// mirroring upstream `TerminalMain.cpp`'s `--jump` branch.
fn run_jump(
    args: &TerminalArgs,
    router_path: &std::path::Path,
    input: &CredentialInput,
) -> Result<i32, clap::Error> {
    let destination_host = args
        .dsthost
        .as_deref()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| clap_error("--dsthost must be set when --jump is used"))?
        .to_owned();
    if !args.session_child {
        // Upstream calls `DaemonCreator::createSessionLeader()` here so the
        // bootstrap ssh can return while the relay keeps running.
        crate::terminal_daemon::spawn_with_args(
            router_path,
            input,
            args.verbose,
            &[
                "--jump".to_owned(),
                format!("--dsthost={destination_host}"),
                format!("--dstport={}", args.dstport),
            ],
        )
        .map_err(clap_error)?;
        return print_marker(input);
    }
    let mut router = et_net::local::connect(router_path)
        .map_err(|error| clap_error(format!("could not connect terminal router: {error}")))?;
    register(&mut router, input).map_err(clap_error)?;
    let ready_socket = parsed_ready_socket(args)?;
    crate::terminal_daemon::signal(ready_socket).map_err(clap_error)?;
    crate::terminal_jump::run(router, input, &destination_host, args.dstport).map_err(clap_error)
}

fn parsed_ready_socket(args: &TerminalArgs) -> Result<&std::path::Path, clap::Error> {
    args.ready_socket
        .as_deref()
        .ok_or_else(|| clap_error("terminal session child has no readiness socket"))
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

fn register(router: &mut LocalStream, input: &CredentialInput) -> Result<(), String> {
    // Upstream uses these to chown forwarded named pipes; Windows has no
    // POSIX ids, so the session reports zero there.
    let (uid, gid) = registration_identity();
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

#[cfg(unix)]
fn registration_identity() -> (i64, i64) {
    (
        i64::from(rustix::process::geteuid().as_raw()),
        i64::from(rustix::process::getegid().as_raw()),
    )
}

#[cfg(windows)]
fn registration_identity() -> (i64, i64) {
    (0, 0)
}

fn clap_error(message: impl Into<String>) -> clap::Error {
    clap::Error::raw(ErrorKind::Io, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn terminal_registration_identity_matches_effective_peer_credentials() {
        assert_eq!(
            registration_identity(),
            (
                i64::from(rustix::process::geteuid().as_raw()),
                i64::from(rustix::process::getegid().as_raw()),
            )
        );
    }
}
