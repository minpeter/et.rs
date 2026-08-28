use std::ffi::OsString;
use std::time::Duration;

use clap::Parser;
use et_cli::client::{ClientArgs, RemoteShellKind};
use et_cli::host::parse_positional_host;

use et_net::connection::Connection;

use crate::bootstrap::{
    build_invocation, build_jump_invocation, build_shell_probe, cmd_safe, provisional_credentials,
    validate_ssh_destination, BootstrapRequest, Credentials, JumpBootstrapRequest, RemoteShell,
};
use crate::client_environment::{
    bound_jumphost_locale_environment, bounded_locale_environment, ghostty_colorterm,
    normalize_terminal_type, reserved_environment_value_lengths, ssh_locale_environment,
};
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::initial_connect::{connect_initial, reconnect, Endpoint, ReconnectOutcome};
use crate::resolver::{EndpointResolver, SystemResolver};
use crate::ssh_config::resolve_ssh_config;
use crate::ssh_process::{run_bootstrap, run_shell_probe, SshRunner, SystemSsh};

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteMode {
    bootstrap_shell: RemoteShell,
    terminal_shell: RemoteShellKind,
    terminal_path: Option<String>,
}

fn resolve_remote_mode(args: &ClientArgs, detected_shell: Option<RemoteShell>) -> RemoteMode {
    let bootstrap_shell = if args.remote_is_windows() {
        RemoteShell::Cmd
    } else {
        detected_shell.unwrap_or(RemoteShell::Posix)
    };
    let terminal_shell = if args.remote_shell.is_some() || args.winserver {
        args.effective_remote_shell()
    } else {
        match bootstrap_shell {
            RemoteShell::Posix => RemoteShellKind::Posix,
            RemoteShell::Cmd => RemoteShellKind::Cmd,
        }
    };
    RemoteMode {
        bootstrap_shell,
        terminal_shell,
        terminal_path: args
            .effective_terminal_path()
            .or_else(|| (bootstrap_shell == RemoteShell::Cmd).then(|| "et.exe".to_owned())),
    }
}

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let mut parsed = ClientArgs::try_parse_from(
        ["et"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
    parsed.verbose = et_cli::logging::effective_verbose(parsed.verbose);
    parsed.silent = et_cli::logging::effective_silent(parsed.silent);
    // `--telemetry` is accepted for upstream compatibility and ignored:
    // et.rs never collects telemetry, and upstream prints nothing here.
    init_logging(&parsed);
    let runner = SystemSsh::default();
    let resolver = SystemResolver;
    let deadline = runner.deadline();
    match run_client(&parsed, &runner, &resolver, deadline) {
        Ok(()) => Ok(0),
        Err(error) => {
            eprintln!("et: {error}");
            Ok(error.exit_code())
        }
    }
}

fn run_client(
    args: &ClientArgs,
    runner: &dyn SshRunner,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<(), ClientError> {
    let destination = parse_positional_host(&args.host, args.port)?;
    validate_bootstrap_mode(args)?;
    let forward_config =
        crate::forward_config::build(args, std::env::var("SSH_AUTH_SOCK").ok().as_deref())?;
    let has_forwarding = !forward_config.local_sources.is_empty()
        || !forward_config.initial_payload.reversetunnels.is_empty();
    // Bind local sources only after the encrypted session exists so accepted
    // tunnels can be multiplexed immediately (avoids pre-handshake accept races).
    let local_sources = forward_config.local_sources;
    let mut initial_payload = forward_config.initial_payload;
    let local_term = std::env::var("TERM").ok();
    let local_colorterm = std::env::var("COLORTERM").ok();
    let term = normalize_terminal_type(local_term.as_deref());
    let colorterm = ghostty_colorterm(local_term.as_deref(), local_colorterm.as_deref());
    let reserved_environment = reserved_environment_value_lengths(
        initial_payload
            .environmentvariables
            .iter()
            .map(|(name, value)| (name.as_str(), value.len())),
        colorterm,
        initial_payload
            .reversetunnels
            .iter()
            .filter_map(|request| request.environmentvariable.as_deref()),
    );
    if reserved_environment.len() > crate::terminal_protocol::MAX_ENVIRONMENT {
        return Err(
            crate::forward_config::ForwardConfigError::TooManyEnvironmentNames(
                reserved_environment.len(),
            )
            .into(),
        );
    }
    let mut locale_environment =
        bounded_locale_environment(ssh_locale_environment(), &reserved_environment)
            .map_err(crate::forward_config::ForwardConfigError::EnvironmentPacketTooLarge)?;
    if args.jumphost.is_some() {
        bound_jumphost_locale_environment(&initial_payload, &mut locale_environment, colorterm)
            .map_err(crate::forward_config::ForwardConfigError::JumphostPacketTooLarge)?;
    }

    let requested_user = command_user(destination.user, args.username.clone());
    validate_ssh_destination(&destination.host, requested_user.as_deref())?;
    let resolved = resolve_ssh_config(
        runner,
        &destination.host,
        requested_user.as_deref(),
        &args.ssh_option,
        deadline,
    )?;
    let user = requested_user.or(resolved.user);
    validate_ssh_destination(&destination.host, user.as_deref())?;
    let probe_request = BootstrapRequest {
        user: user.clone(),
        host_alias: destination.host.clone(),
        jumphost: args.jumphost.clone(),
        terminal_path: None,
        server_fifo: None,
        kill_other_sessions: false,
        verbose: args.verbose,
        ssh_options: args.ssh_option.clone(),
        term: term.clone(),
        remote_shell: RemoteShell::Posix,
        session_shell: None,
    };
    let detected_shell = if args.remote_shell.is_some() || args.winserver {
        None
    } else {
        let probe = build_shell_probe(&probe_request);
        Some(run_shell_probe(runner, &probe, deadline)?)
    };
    let remote_mode = resolve_remote_mode(args, detected_shell);
    let provisional = provisional_credentials()?;

    let request = BootstrapRequest {
        user,
        host_alias: destination.host,
        jumphost: args.jumphost.clone(),
        terminal_path: remote_mode.terminal_path.clone(),
        server_fifo: args.serverfifo.clone(),
        kill_other_sessions: args.kill_other_sessions,
        verbose: args.verbose,
        ssh_options: args.ssh_option.clone(),
        term,
        remote_shell: remote_mode.bootstrap_shell,
        session_shell: (remote_mode.terminal_shell == RemoteShellKind::Powershell)
            .then(|| "powershell.exe".to_owned()),
    };
    if remote_mode.bootstrap_shell == RemoteShell::Cmd {
        // cmd.exe cannot quote the credential line, so anything unusual in
        // TERM or the paths must be rejected before it reaches the remote.
        for value in [
            request.term.as_str(),
            provisional.id.as_str(),
            provisional.passkey.as_str(),
        ] {
            if !cmd_safe(value) {
                return Err(ClientError::Unsupported(
                    "Windows bootstrap requires alphanumeric TERM and credentials",
                ));
            }
        }
    }
    let invocation = build_invocation(&request, &provisional);
    et_cli::logging::verbose(1, bootstrap_log_message(&request));
    let mut credentials = run_bootstrap(runner, &invocation, deadline)?;
    et_cli::logging::info("etserver started");
    // Without a jumphost the ET connection goes straight to the destination.
    // With one, upstream starts a second `etterminal --jump` on the jumphost
    // and the ET session is established against the jumphost's etserver,
    // which relays to the destination.
    let mut endpoint = Endpoint {
        host: resolved.hostname,
        port: destination.port,
    };
    if let Some(jumphost) = args.jumphost.as_deref() {
        let parsed_jump = et_cli::host::parse_host_string(jumphost);
        let jump_host = parsed_jump
            .host
            .trim_matches(|c| c == '[' || c == ']')
            .to_owned();
        let jump_user = Some(parsed_jump.user.as_str()).filter(|user| !user.is_empty());
        validate_ssh_destination(&jump_host, jump_user)?;
        let jump_resolved =
            resolve_ssh_config(runner, &jump_host, jump_user, &args.ssh_option, deadline)?;
        let jump_request = JumpBootstrapRequest {
            jumphost: jumphost.to_owned(),
            destination_host: endpoint.host.clone(),
            destination_port: endpoint.port,
            jump_server_fifo: args.jserverfifo.clone(),
            terminal_path: args.terminal_path.clone(),
            kill_other_sessions: args.kill_other_sessions,
            verbose: args.verbose,
            ssh_options: args.ssh_option.clone(),
            term: request.term.clone(),
        };
        let jump_invocation = build_jump_invocation(&jump_request, &provisional);
        credentials = run_bootstrap(runner, &jump_invocation, deadline)?;
        endpoint = Endpoint {
            host: jump_resolved.hostname,
            port: args.jport,
        };
        // The jumphost etserver dispatches on this flag and hands the payload
        // to the jump terminal instead of starting a shell.
        initial_payload.jumphost = Some(true);
    }
    if remote_mode.terminal_shell == RemoteShellKind::Posix {
        initial_payload
            .environmentvariables
            .extend(locale_environment);
        if let Some(value) = colorterm {
            initial_payload
                .environmentvariables
                .insert("COLORTERM".to_owned(), value.to_owned());
        }
    }
    et_cli::logging::info(format!("Connecting to {endpoint}"));
    let connection = connect_initial(
        &endpoint,
        &credentials,
        &initial_payload,
        resolver,
        deadline,
    )?;
    et_cli::logging::verbose(1, format!("Client created with id: {}", credentials.id));
    if args.no_terminal && !has_forwarding {
        return Ok(());
    }
    let forwarder = et_net::forward::Forwarder::start(local_sources)
        .map_err(|error| ClientError::Terminal(error.to_string()))?;
    crate::client_terminal::run(
        connection,
        crate::client_terminal::TerminalOptions {
            command: args.command.as_deref(),
            no_exit: args.no_exit,
            keepalive: args.keepalive,
            terminal_enabled: !args.no_terminal,
            lines: crate::client_terminal::RemoteLines::from(remote_mode.terminal_shell),
            connection_name: &request.host_alias,
        },
        forwarder,
        |connection| reconnect_with_retry(connection, &endpoint, &credentials, resolver),
    )
}

/// Reconnect, retrying transient network failures until the link returns.
///
/// A laptop that slept through a Wi-Fi drop wakes with no route to the
/// server for several seconds; a single failed attempt must not kill the
/// session (upstream ET retries until the server ends the session). Raw
/// mode turns off ISIG, so Ctrl-C arrives as the 0x03 byte on stdin and is
/// honoured as "give up now" while waiting between attempts.
fn reconnect_with_retry(
    connection: &mut Connection,
    endpoint: &Endpoint,
    credentials: &Credentials,
    resolver: &dyn EndpointResolver,
) -> Result<ReconnectOutcome, ClientError> {
    let mut announced = false;
    retry_transient(
        || {
            reconnect(
                connection,
                endpoint,
                credentials,
                resolver,
                Deadline::after(RECONNECT_TIMEOUT),
            )
        },
        |error| {
            if !announced {
                announced = true;
                // Raw mode is active: lines need explicit carriage returns.
                eprint!("\r\net: connection lost, reconnecting... (press Ctrl-C to give up)\r\n");
            }
            et_cli::logging::info(format!("reconnect attempt failed, retrying: {error}"));
            reconnect_wait_aborted(RECONNECT_RETRY_DELAY)
        },
    )
}

/// Run `attempt` until it succeeds, retrying transient network errors.
/// `wait` runs between attempts and returns `true` to give up with the
/// last error; non-transient errors propagate immediately.
fn retry_transient<T>(
    mut attempt: impl FnMut() -> Result<T, ClientError>,
    mut wait: impl FnMut(&ClientError) -> bool,
) -> Result<T, ClientError> {
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) if error.is_transient_reconnect() => {
                if wait(&error) {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Wait out the retry delay. Returns `true` when the user pressed Ctrl-C.
///
/// Stdin is in raw mode, so the byte must be read to be seen. Other input
/// typed while the link is down cannot reach the server and is dropped,
/// which is also what a dead TCP connection would have done with it.
#[cfg(unix)]
fn reconnect_wait_aborted(delay: Duration) -> bool {
    use std::io::{IsTerminal, Read};

    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::time::Timespec;

    const CTRL_C: u8 = 0x03;
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        std::thread::sleep(delay);
        return false;
    }
    let deadline = std::time::Instant::now() + delay;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let Ok(timeout) = Timespec::try_from(remaining) else {
            return false;
        };
        let mut descriptors = [PollFd::new(&stdin, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return false,
            Ok(_) => {
                if !descriptors[0].revents().contains(PollFlags::IN) {
                    return false;
                }
                let mut bytes = [0u8; 256];
                match stdin.lock().read(&mut bytes) {
                    // EOF: stdin is gone, nothing to poll for any more.
                    Ok(0) => {
                        std::thread::sleep(remaining);
                        return false;
                    }
                    Ok(count) if bytes[..count].contains(&CTRL_C) => return true,
                    Ok(_) => {}
                    Err(_) => return false,
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return false,
        }
    }
}

#[cfg(windows)]
fn reconnect_wait_aborted(delay: Duration) -> bool {
    // The Windows console loop owns stdin; a Ctrl-C abort would need a
    // console reader here. Sleep and retry: the process can still be killed.
    std::thread::sleep(delay);
    false
}

/// Configure logging like upstream `TerminalClientMain`: files land in
/// `--logdir` (default temp dir) under an `etclient-<user>` prefix unless
/// `--silent` is given.
fn init_logging(args: &ClientArgs) {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned());
    et_cli::logging::init(et_cli::logging::LogOptions {
        directory: et_cli::logging::effective_log_directory(
            args.logdir.as_deref().map(std::path::PathBuf::from),
        ),
        prefix: format!("etclient-{user}"),
        to_stdout: args.logtostdout,
        silent: args.silent,
        append_pid: true,
        verbose: args.verbose,
        max_size: et_cli::logging::DEFAULT_MAX_LOG_SIZE,
    });
}

fn bootstrap_log_message(request: &BootstrapRequest) -> String {
    format!(
        "starting SSH bootstrap host={} options={}",
        request.host_alias,
        request.ssh_options.len()
    )
}

fn command_user(positional: Option<String>, option: Option<String>) -> Option<String> {
    match positional {
        Some(user) if user.is_empty() => None,
        Some(user) => Some(user),
        None => option,
    }
}

#[cfg(test)]
fn effective_user(
    positional: Option<String>,
    option: Option<String>,
    ssh_config: Option<String>,
) -> Option<String> {
    command_user(positional, option).or(ssh_config)
}

fn validate_bootstrap_mode(args: &ClientArgs) -> Result<(), ClientError> {
    if args.jserverfifo.is_some() && args.jumphost.is_none() {
        return Err(ClientError::Unsupported(
            "--jserverfifo requires --jumphost",
        ));
    }
    if let Some(jumphost) = args.jumphost.as_deref() {
        validate_jumphost(jumphost)?;
    }
    if args.no_exit && args.command.is_none() {
        return Err(ClientError::Unsupported("--no-exit requires --command"));
    }
    Ok(())
}

/// Validate `--jumphost` as an SSH ProxyJump target (OpenSSH `-J` argument).
///
/// Rejects empty values and option-injection shapes (`-o...`) that would be
/// interpreted as extra `ssh` flags rather than a hop host.
fn validate_jumphost(jumphost: &str) -> Result<(), ClientError> {
    let jumphost = jumphost.trim();
    if jumphost.is_empty() {
        return Err(ClientError::Unsupported("empty --jumphost value"));
    }
    // Comma-separated multi-hop jumps are allowed by OpenSSH; validate each hop.
    for hop in jumphost.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            return Err(ClientError::Unsupported("empty hop in --jumphost"));
        }
        let parsed = et_cli::host::parse_host_string(hop);
        let host = parsed.host.trim_matches(|c| c == '[' || c == ']');
        if host.is_empty() {
            return Err(ClientError::Unsupported("empty hop in --jumphost"));
        }
        if host.starts_with('-') || (!parsed.user.is_empty() && parsed.user.starts_with('-')) {
            return Err(ClientError::InvalidSshComponent("jumphost"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_transient_retries_until_success() {
        let mut attempts = 0;
        let result = retry_transient(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(ClientError::DnsTimeout("host:2022".to_owned()))
                } else {
                    Ok(7)
                }
            },
            |error| {
                assert!(error.is_transient_reconnect());
                false
            },
        );
        assert_eq!(result.unwrap(), 7);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn retry_transient_gives_up_when_wait_aborts() {
        let mut attempts = 0;
        let result = retry_transient(
            || -> Result<(), ClientError> {
                attempts += 1;
                Err(ClientError::UnreachableEndpoint {
                    endpoint: "10.10.10.10:2022".to_owned(),
                    source: std::io::Error::from(std::io::ErrorKind::TimedOut),
                })
            },
            |_| true,
        );
        assert!(matches!(
            result,
            Err(ClientError::UnreachableEndpoint { .. })
        ));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn retry_transient_propagates_fatal_errors_immediately() {
        let mut attempts = 0;
        let result = retry_transient(
            || -> Result<(), ClientError> {
                attempts += 1;
                Err(ClientError::ProtocolMismatch(None))
            },
            |_| panic!("fatal errors must not wait for a retry"),
        );
        assert!(matches!(result, Err(ClientError::ProtocolMismatch(None))));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn transient_reconnect_classification() {
        assert!(ClientError::DnsTimeout("h:1".to_owned()).is_transient_reconnect());
        assert!(ClientError::BootstrapTimeout("x").is_transient_reconnect());
        assert!(
            ClientError::Transport(et_net::connection::ConnError::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset
            )))
            .is_transient_reconnect()
        );
        assert!(!ClientError::ProtocolMismatch(None).is_transient_reconnect());
        assert!(!ClientError::ServerRejected {
            status: None,
            message: None
        }
        .is_transient_reconnect());
        assert!(!ClientError::InvalidPasskey.is_transient_reconnect());
    }

    #[test]
    fn username_precedence_matches_upstream() {
        assert_eq!(
            effective_user(
                Some("positional".to_string()),
                Some("option".to_string()),
                Some("config".to_string()),
            ),
            Some("positional".to_string())
        );
        assert_eq!(
            effective_user(None, Some("option".to_string()), Some("config".to_string()),),
            Some("option".to_string())
        );
        assert_eq!(
            effective_user(
                Some(String::new()),
                Some("option".to_string()),
                Some("config".to_string()),
            ),
            Some("config".to_string())
        );
    }

    #[test]
    fn jumphost_validation_rejects_injection_and_empty_hops() {
        assert!(validate_jumphost("jump.example").is_ok());
        assert!(validate_jumphost("user@jump.example:22").is_ok());
        assert!(validate_jumphost("jump1,user@jump2").is_ok());
        assert!(matches!(
            validate_jumphost(""),
            Err(ClientError::Unsupported("empty --jumphost value"))
        ));
        assert!(matches!(
            validate_jumphost("  "),
            Err(ClientError::Unsupported("empty --jumphost value"))
        ));
        assert!(matches!(
            validate_jumphost("-oProxyCommand=bad"),
            Err(ClientError::InvalidSshComponent("jumphost"))
        ));
        assert!(matches!(
            validate_jumphost("good,-evil"),
            Err(ClientError::InvalidSshComponent("jumphost"))
        ));
        assert!(matches!(
            validate_jumphost("good,"),
            Err(ClientError::Unsupported("empty hop in --jumphost"))
        ));
    }

    #[test]
    fn bootstrap_log_message_never_contains_credentials() {
        let request = BootstrapRequest {
            user: Some("user".to_owned()),
            host_alias: "host.example".to_owned(),
            jumphost: None,
            terminal_path: None,
            server_fifo: None,
            kill_other_sessions: false,
            verbose: 2,
            ssh_options: vec!["Compression=yes".to_owned()],
            term: "xterm".to_owned(),
            remote_shell: RemoteShell::Posix,
            session_shell: None,
        };
        let credentials = Credentials {
            id: "abcdefghijklmnop".to_owned(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_owned(),
        };
        let message = bootstrap_log_message(&request);
        assert!(!message.contains(&credentials.id));
        assert!(!message.contains(&credentials.passkey));
        assert_eq!(
            message,
            "starting SSH bootstrap host=host.example options=1"
        );
    }

    #[test]
    fn remote_mode_refactor_preserves_bare_posix_defaults() {
        let args = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(
            resolve_remote_mode(&args, None),
            RemoteMode {
                bootstrap_shell: RemoteShell::Posix,
                terminal_shell: RemoteShellKind::Posix,
                terminal_path: None,
            }
        );
    }

    #[test]
    fn remote_mode_refactor_preserves_explicit_windows_defaults() {
        let args = ClientArgs::try_parse_from(["et", "host", "--winserver"]).unwrap();
        assert_eq!(
            resolve_remote_mode(&args, Some(RemoteShell::Posix)),
            RemoteMode {
                bootstrap_shell: RemoteShell::Cmd,
                terminal_shell: RemoteShellKind::Cmd,
                terminal_path: Some("et.exe".to_owned()),
            }
        );
    }

    #[test]
    fn explicit_powershell_preserves_terminal_override() {
        let args =
            ClientArgs::try_parse_from(["et", "host", "--remote-shell", "powershell"]).unwrap();
        assert_eq!(
            resolve_remote_mode(&args, Some(RemoteShell::Posix)),
            RemoteMode {
                bootstrap_shell: RemoteShell::Cmd,
                terminal_shell: RemoteShellKind::Powershell,
                terminal_path: Some("et.exe".to_owned()),
            }
        );
    }

    #[test]
    fn bare_detected_windows_uses_cmd_defaults() {
        let args = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(
            resolve_remote_mode(&args, Some(RemoteShell::Cmd)),
            RemoteMode {
                bootstrap_shell: RemoteShell::Cmd,
                terminal_shell: RemoteShellKind::Cmd,
                terminal_path: Some("et.exe".to_owned()),
            }
        );
    }

    #[test]
    fn bare_detected_posix_preserves_posix_defaults() {
        let args = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(
            resolve_remote_mode(&args, Some(RemoteShell::Posix)),
            RemoteMode {
                bootstrap_shell: RemoteShell::Posix,
                terminal_shell: RemoteShellKind::Posix,
                terminal_path: None,
            }
        );
    }
}
