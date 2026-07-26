use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};

use clap::error::ErrorKind;
use clap::Parser;
use et_cli::server::{resolve_config, ServerArgs};
use et_server::path::select_router_path;
use et_server::Runtime;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = ServerArgs::try_parse_from(
        ["etserver"]
            .iter()
            .map(|s| OsString::from(*s))
            .chain(args.iter().cloned()),
    )?;
    if parsed.daemon {
        // Re-exec ourselves detached and return, mirroring the upstream
        // parent process exiting immediately after `DaemonCreator::create`.
        crate::server_daemon::spawn_detached(args).map_err(|error| {
            clap::Error::raw(ErrorKind::Io, format!("could not daemonize: {error}"))
        })?;
        return Ok(0);
    }
    if parsed.daemon_child {
        crate::server_daemon::detach_child(parsed.pidfile.as_deref())
            .map_err(|error| clap::Error::raw(ErrorKind::Io, error))?;
    }
    let ini = load_config(args, &parsed)?;
    let config = resolve_config(&parsed, ini.as_deref())
        .map_err(|error| clap::Error::raw(ErrorKind::ValueValidation, error.to_string()))?;
    et_cli::logging::init(et_cli::logging::LogOptions {
        directory: config.log_directory.clone(),
        prefix: "etserver".to_owned(),
        to_stdout: parsed.logtostdout,
        silent: config.silent,
        append_pid: true,
        verbose: config.verbose,
        max_size: config.log_size,
    });
    et_cli::logging::info("In child, about to start server.");
    let mut signals = Signals::new([SIGINT, SIGTERM])
        .map_err(|error| clap_io("could not install server signal handlers", error))?;
    let router_path = select_router_path(config.server_fifo.as_deref())
        .map_err(|error| clap_io("could not select terminal router path", error))?;
    let mut runtime = Runtime::start(config.bind_ip, config.port, router_path)
        .map_err(|error| clap_io("could not start ET server", error))?;
    et_cli::logging::info(format!(
        "etserver listening on {:?} router {}",
        runtime.tcp_addresses(),
        runtime.router_path().display()
    ));
    if !parsed.daemon_child {
        print_ready(&runtime)?;
    }

    if signals.forever().next().is_none() {
        return Err(clap::Error::raw(
            ErrorKind::Io,
            "server signal stream ended unexpectedly",
        ));
    }
    et_cli::logging::info("Server is shutting down");
    runtime
        .shutdown()
        .map_err(|error| clap_io("could not shut down ET server", error))?;
    Ok(0)
}

fn load_config(args: &[OsString], parsed: &ServerArgs) -> Result<Option<String>, clap::Error> {
    match fs::read_to_string(&parsed.cfgfile) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !cfgfile_was_explicit(args) => {
            Ok(None)
        }
        Err(error) => Err(clap_io("could not read server configuration", error)),
    }
}

fn cfgfile_was_explicit(args: &[OsString]) -> bool {
    args.iter().any(|arg| {
        arg == "--cfgfile"
            || arg
                .to_str()
                .is_some_and(|value| value.starts_with("--cfgfile="))
    })
}

fn print_ready(runtime: &Runtime) -> Result<(), clap::Error> {
    let addresses = runtime
        .tcp_addresses()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "ETSERVER_READY tcp={addresses} router={}",
        runtime.router_path().display()
    )
    .and_then(|()| output.flush())
    .map_err(|error| clap_io("could not write server readiness", error))
}

fn clap_io(message: &str, error: impl std::fmt::Display) -> clap::Error {
    clap::Error::raw(ErrorKind::Io, format!("{message}: {error}"))
}
