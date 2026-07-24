use std::ffi::OsString;

use clap::Parser;
use et_cli::client::ClientArgs;
use et_cli::host::parse_positional_host;

use crate::bootstrap::{build_invocation, provisional_credentials, BootstrapRequest};
use crate::error::ClientError;
use crate::initial_connect::{connect_initial, Endpoint};
use crate::ssh_process::{run_bootstrap, SshRunner, SystemSsh};

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
    match run_client(&parsed, &SystemSsh) {
        Ok(()) => Ok(0),
        Err(error) => {
            eprintln!("et: {error}");
            Ok(error.exit_code())
        }
    }
}

fn run_client(args: &ClientArgs, runner: &dyn SshRunner) -> Result<(), ClientError> {
    let destination = parse_positional_host(&args.host, args.port)?;
    validate_bootstrap_mode(args)?;

    let user = args.username.clone().or(destination.user);
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let request = BootstrapRequest {
        user,
        host_alias: destination.host.clone(),
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
    let credentials = run_bootstrap(runner, &invocation)?;
    connect_initial(
        &Endpoint {
            host: destination.host,
            port: destination.port,
        },
        &credentials,
    )
}

fn validate_bootstrap_mode(args: &ClientArgs) -> Result<(), ClientError> {
    if !args.no_terminal {
        return Err(ClientError::Unsupported(
            "interactive terminal sessions are not implemented yet; use -N without tunnels for bootstrap-only mode",
        ));
    }
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
    if args.command.is_some() || args.no_exit {
        return Err(ClientError::Unsupported(
            "remote commands require the interactive terminal runtime, which is not implemented yet",
        ));
    }
    Ok(())
}
