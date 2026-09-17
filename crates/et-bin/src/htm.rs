//! `htm` and `htmd` role entry points, mirroring upstream HTM mains.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::Parser;
use et_htm::server::{pipe_name, HtmServer};

#[derive(Debug, Parser)]
#[command(name = "htm", version = et_cli::VERSION, long_version = et_cli::LONG_VERSION,
    about = "Headless terminal multiplexer")]
struct HtmArgs {
    #[arg(
        short = 'x',
        long = "kill-other-sessions",
        help = "stop the user's daemon before starting a new session"
    )]
    kill_other_sessions: bool,
    /// Print the running daemon's pane/affinity snapshot without attaching.
    #[arg(long, conflicts_with = "kill_other_sessions")]
    dump_panes: bool,
    /// Select an isolated IPC endpoint (Windows: beneath LOCALAPPDATA).
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long = "daemon-child", hide = true)]
    daemon_child: bool,
}

#[derive(Debug, Parser)]
#[command(name = "htmd", version = et_cli::VERSION, long_version = et_cli::LONG_VERSION,
    about = "Headless terminal multiplexer daemon")]
struct HtmdArgs {
    /// Select an isolated IPC endpoint (Windows: beneath LOCALAPPDATA).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Emit HTMD_READY on stdout after the IPC endpoint and initial PTY exist.
    #[arg(long)]
    ready_stdout: bool,
    #[arg(long, hide = true)]
    daemon_child: bool,
}

pub fn run_daemon(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = HtmdArgs::try_parse_from(
        std::iter::once(OsString::from("htmd")).chain(args.iter().cloned()),
    )?;
    #[cfg(unix)]
    if parsed.daemon_child {
        crate::detach::close_inherited_descriptors()
            .map_err(|error| clap_io("closing inherited descriptors", error))?;
        rustix::process::setsid().map_err(|error| clap_io("detaching htmd", error))?;
    }
    let path = parsed
        .socket
        .map(Ok)
        .unwrap_or_else(pipe_name)
        .map_err(|error| clap_io("selecting HTM endpoint", error))?;
    let mut server = HtmServer::bind(&path)
        .map_err(|error| clap_io("could not bind the htm IPC socket", error))?;
    if parsed.ready_stdout {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"HTMD_READY\n")
            .and_then(|()| stdout.flush())
            .map_err(|error| clap_io("reporting htmd readiness", error))?;
    }
    server
        .run()
        .map_err(|error| clap_io("htmd stopped with an error", error))?;
    Ok(0)
}

pub fn run_client(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = HtmArgs::try_parse_from(
        std::iter::once(OsString::from("htm")).chain(args.iter().cloned()),
    )?;
    let path = parsed
        .socket
        .map(Ok)
        .unwrap_or_else(pipe_name)
        .map_err(|error| clap_io("selecting HTM endpoint", error))?;
    if parsed.dump_panes {
        let dump = et_htm::server::dump_panes(&path)
            .map_err(|error| clap_io("reading HTM pane diagnostic", error))?;
        std::io::stdout()
            .lock()
            .write_all(dump.as_bytes())
            .map_err(|error| clap_io("writing HTM pane diagnostic", error))?;
        return Ok(0);
    }
    if parsed.kill_other_sessions {
        crate::htm_daemon::stop(&path).map_err(|error| clap_io("stopping htmd", error))?;
    }
    // Keep the first successful connection: a connect-and-drop probe creates a
    // phantom UI and can race the daemon's recovery writes.
    let mut stream = match et_htm::transport::connect(&path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            crate::htm_daemon::spawn(&path)
                .map_err(|error| clap_io("could not start htmd", error))?;
            et_htm::transport::connect(&path)
                .map_err(|error| clap_io("could not connect to htmd", error))?
        }
        Err(error) => return Err(clap_io("could not connect to htmd", error)),
    };
    let raw = RawTerminal::enter();
    // Avoid Rust's global line-buffered stdout: its process-exit flush could
    // block after the bridge's bounded final drain has already expired.
    #[cfg(unix)]
    let mut stdout = std::fs::File::from(
        rustix::io::dup(std::io::stdout())
            .map_err(|error| clap_io("duplicating HTM stdout", error))?,
    );
    #[cfg(unix)]
    let result = et_htm::client::run(
        &mut stream,
        &mut et_htm::client::Stdin(std::io::stdin()),
        &mut stdout,
    );
    #[cfg(windows)]
    let stdout = {
        use std::os::windows::io::AsHandle;
        std::fs::File::from(
            std::io::stdout()
                .as_handle()
                .try_clone_to_owned()
                .map_err(|error| clap_io("duplicating HTM stdout", error))?,
        )
    };
    #[cfg(windows)]
    let result = et_htm::client::run(
        &mut stream,
        et_htm::client::Stdin(std::io::stdin()),
        stdout,
        std::io::IsTerminal::is_terminal(&std::io::stdout()),
    );
    drop(raw);
    result.map_err(|error| clap_io("htm session ended with an error", error))?;
    Ok(0)
}

struct RawTerminal {
    enabled: bool,
}

impl RawTerminal {
    fn enter() -> Self {
        use std::io::IsTerminal;
        let enabled = std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && crossterm::terminal::enable_raw_mode().is_ok();
        Self { enabled }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(error) = crossterm::terminal::disable_raw_mode() {
                eprintln!("htm: restoring terminal mode: {error}");
            }
        }
    }
}

fn clap_io(message: &str, error: impl std::fmt::Display) -> clap::Error {
    clap::Error::raw(ErrorKind::Io, format!("{message}: {error}\n"))
}
