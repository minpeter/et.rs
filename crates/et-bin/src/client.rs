use std::ffi::OsString;
use std::time::Duration;

use clap::Parser;
use et_cli::client::ClientArgs;
use et_cli::host::parse_positional_host;

use crate::bootstrap::{
    build_invocation, provisional_credentials, validate_ssh_destination, BootstrapRequest,
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
    if parsed.telemetry {
        eprintln!("note: et.rs never collects telemetry; --telemetry is a no-op.");
    }
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
        terminal_path: args.terminal_path.clone(),
        server_fifo: args.serverfifo.clone(),
        kill_other_sessions: args.kill_other_sessions,
        verbose: args.verbose,
        ssh_options: args.ssh_option.clone(),
        term,
    };
    let provisional = provisional_credentials()?;
    let invocation = build_invocation(&request, &provisional);
    let credentials = run_bootstrap(runner, &invocation, deadline)?;
    let endpoint = Endpoint {
        host: resolved.hostname,
        port: destination.port,
    };
    let connection = connect_initial(&endpoint, &credentials, resolver, deadline)?;
    if args.no_terminal {
        return Ok(());
    }
    crate::client_terminal::run(
        connection,
        args.command.as_deref(),
        args.no_exit,
        args.keepalive,
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
    if !args.tunnel.is_empty()
        || !args.reverse_tunnel.is_empty()
        || args.forward_ssh_agent
        || args.ssh_socket.is_some()
    {
        return Err(ClientError::Unsupported(
            "tunnels and SSH-agent forwarding are not implemented yet",
        ));
    }
    if args.jumphost.is_some() || args.jserverfifo.is_some() {
        return Err(ClientError::Unsupported(
            "jumphost sessions are not implemented yet",
        ));
    }
    if args.no_exit && args.command.is_none() {
        return Err(ClientError::Unsupported("--no-exit requires --command"));
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
}
