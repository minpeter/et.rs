//! `htm` and `htmd` role entry points, mirroring upstream `HtmClientMain.cpp`
//! and `HtmServerMain.cpp`.

use std::ffi::OsString;
use std::io::Write;

use clap::error::ErrorKind;
use clap::Parser;
use et_htm::server::{pipe_name, HtmServer};

#[derive(Debug, Parser)]
#[command(
    name = "htm",
    version = concat!("version ", env!("CARGO_PKG_VERSION")),
    about = "Headless terminal multiplexer"
)]
struct HtmArgs {
    #[arg(
        short = 'x',
        long = "kill-other-sessions",
        help = "kill all old sessions belonging to the user"
    )]
    kill_other_sessions: bool,
    /// Internal marker: this process is the re-executed daemon.
    #[arg(long = "daemon-child", hide = true)]
    daemon_child: bool,
}

#[derive(Debug, Parser)]
#[command(
    name = "htmd",
    version = concat!("version ", env!("CARGO_PKG_VERSION")),
    about = "Headless terminal multiplexer daemon"
)]
struct HtmdArgs {}

/// `htmd`: run the multiplexer daemon in the foreground.
pub fn run_daemon(args: &[OsString]) -> Result<i32, clap::Error> {
    HtmdArgs::try_parse_from(
        ["htmd"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
    let path = pipe_name();
    let mut server = HtmServer::bind(&path)
        .map_err(|error| clap_io("could not bind the htm IPC socket", error))?;
    server
        .run()
        .map_err(|error| clap_io("htmd stopped with an error", error))?;
    Ok(0)
}

/// `htm`: start the daemon if needed, then relay stdin/stdout to it in raw
/// terminal mode.
pub fn run_client(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = HtmArgs::try_parse_from(
        ["htm"]
            .iter()
            .map(|value| OsString::from(*value))
            .chain(args.iter().cloned()),
    )?;
    let path = pipe_name();
    if parsed.kill_other_sessions {
        stop_daemon(&path);
    }
    if std::os::unix::net::UnixStream::connect(&path).is_err() {
        spawn_daemon().map_err(|error| clap_io("could not start htmd", error))?;
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut stream = et_htm::client::connect(&path)
        .map_err(|error| clap_io("could not connect to htmd", error))?;

    // Raw mode for the duration of the session; the terminal is restored on
    // every exit path, including the HTM-mode-off escape upstream sends.
    let raw = RawTerminal::enter();
    let mut stdin = et_htm::client::Stdin(std::io::stdin());
    let mut stdout = std::io::stdout();
    let result = et_htm::client::run(&mut stream, &mut stdin, &mut stdout);
    let _ = stdout.write_all(et_htm::codes::LEAVE_HTM_MODE);
    let _ = stdout.flush();
    drop(raw);
    result.map_err(|error| clap_io("htm session ended with an error", error))?;
    Ok(0)
}

/// Raw terminal mode for the HTM relay, restored on drop.
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
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Re-exec this binary as a detached `htmd`, like upstream's daemon fork.
fn spawn_daemon() -> std::io::Result<()> {
    let executable = std::env::current_exe()?;
    std::process::Command::new(executable)
        .arg("htmd")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .current_dir("/")
        .spawn()
        .map(|_| ())
}

/// Remove a running daemon, matching upstream's `pkill -x -U <uid> htmd`.
fn stop_daemon(path: &std::path::Path) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let me = rustix::process::getuid().as_raw();
    for (pid, process) in system.processes() {
        let is_htmd = process
            .name()
            .to_str()
            .is_some_and(|name| name == "htmd" || name == "et")
            && process
                .cmd()
                .iter()
                .any(|argument| argument.to_str() == Some("htmd"));
        let same_user = process.user_id().map(|uid| **uid) == Some(me);
        if is_htmd && same_user && pid.as_u32() != std::process::id() {
            if let Ok(raw) = i32::try_from(pid.as_u32()) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(raw),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

fn clap_io(message: &str, error: impl std::fmt::Display) -> clap::Error {
    clap::Error::raw(ErrorKind::Io, format!("{message}: {error}\n"))
}
