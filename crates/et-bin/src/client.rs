use std::ffi::OsString;
use std::time::Duration;

use clap::Parser;
use et_cli::client::ClientArgs;
use et_cli::host::parse_positional_host;

use crate::bootstrap::{
    build_invocation, build_jump_invocation, provisional_credentials, validate_ssh_destination,
    BootstrapRequest, JumpBootstrapRequest,
};
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::initial_connect::{connect_initial, reconnect, Endpoint};
use crate::resolver::{EndpointResolver, SystemResolver};
use crate::ssh_config::resolve_ssh_config;
use crate::ssh_process::{run_bootstrap, SshRunner, SystemSsh};

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = ClientArgs::try_parse_from(
        ["et"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
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
    let provisional = provisional_credentials()?;
    let forward_config =
        crate::forward_config::build(args, std::env::var("SSH_AUTH_SOCK").ok().as_deref())?;
    let has_forwarding = !forward_config.local_sources.is_empty()
        || !forward_config.initial_payload.reversetunnels.is_empty();
    // Bind local sources only after the encrypted session exists so accepted
    // tunnels can be multiplexed immediately (avoids pre-handshake accept races).
    let local_sources = forward_config.local_sources;

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

    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let request = BootstrapRequest {
        user,
        host_alias: destination.host,
        jumphost: args.jumphost.clone(),
        terminal_path: args.effective_terminal_path(),
        server_fifo: args.serverfifo.clone(),
        kill_other_sessions: args.kill_other_sessions,
        verbose: args.verbose,
        ssh_options: args.ssh_option.clone(),
        term,
    };
    let invocation = build_invocation(&request, &provisional);
    et_cli::logging::verbose(
        1,
        format!("Trying ssh with args: {}", invocation.args.join(" ")),
    );
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
    let mut initial_payload = forward_config.initial_payload;
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
            terminal_path: args.effective_terminal_path(),
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
        args.command.as_deref(),
        args.no_exit,
        args.keepalive,
        forwarder,
        !args.no_terminal,
        |connection| {
            reconnect(
                connection,
                &endpoint,
                &credentials,
                resolver,
                Deadline::after(RECONNECT_TIMEOUT),
            )
        },
    )
}

/// Configure logging like upstream `TerminalClientMain`: files land in
/// `--logdir` (default temp dir) under an `etclient-<user>` prefix unless
/// `--silent` is given.
fn init_logging(args: &ClientArgs) {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned());
    et_cli::logging::init(et_cli::logging::LogOptions {
        directory: args
            .logdir
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir),
        prefix: format!("etclient-{user}"),
        to_stdout: args.logtostdout,
        silent: args.silent,
        append_pid: true,
        verbose: args.verbose,
        max_size: et_cli::logging::DEFAULT_MAX_LOG_SIZE,
    });
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
}
