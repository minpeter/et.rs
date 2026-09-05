#![forbid(unsafe_code)]

//! Single-binary entry point with role dispatch by `argv[0]`.
//!
//! One compiled binary serves every EternalTerminal role:
//! - `et`        → client (default)
//! - `etserver`  → server
//! - `etterminal`→ per-session terminal
//! - `htm`       → headless terminal multiplexer client
//! - `htmd`      → headless terminal multiplexer daemon
//!
//! Busybox-style symlinks (`ln -s et etserver`) select the role. The leading
//! positional subcommand (`et server`, `et terminal`, `et htm`, `et htmd`) is
//! an explicit fallback.

use std::ffi::OsString;

// A global allocator is a whole-program decision, so it is declared here in the
// shipped binary rather than in a library that every role links. jemalloc is
// used on Linux because its safe control API can return idle arenas to the
// kernel; the system allocator's trim entry point would need forbidden FFI.
#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__et-console-writer")) {
        std::process::exit(crate::client_output::run_windows_helper());
    }
    #[cfg(unix)]
    if let Some(code) = et_net::user_socket_ops::maybe_run_helper() {
        std::process::exit(code);
    }
    let argv: Vec<OsString> = std::env::args_os().collect();
    let prog = argv
        .first()
        .map(|a| {
            std::path::Path::new(a)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("et")
        })
        .unwrap_or("et");

    match dispatch(prog, &argv[1..]) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            crate::server_daemon::fail_startup(&error.to_string());
            error.exit();
        }
    }
}

fn dispatch(prog: &str, args: &[OsString]) -> Result<i32, clap::Error> {
    #[cfg(windows)]
    let prog = prog.strip_suffix(".exe").unwrap_or(prog);
    match prog {
        "etserver" => return role("etserver", args),
        "etterminal" => return role("etterminal", args),
        "htm" => return role("htm", args),
        "htmd" => return role("htmd", args),
        _ => {}
    }
    if let Some(first) = args.first().and_then(|s| s.to_str()) {
        match first {
            "server" => return role("etserver", &args[1..]),
            "terminal" => return role("etterminal", &args[1..]),
            "htm" => return role("htm", &args[1..]),
            "htmd" => return role("htmd", &args[1..]),
            "client" => return crate::client::run(&args[1..]),
            _ => {}
        }
    }
    crate::client::run(args)
}

fn role(name: &str, args: &[OsString]) -> Result<i32, clap::Error> {
    match name {
        "etserver" => crate::server::run(args),
        "etterminal" => crate::terminal::run(args),
        "htm" => crate::htm::run_client(args),
        "htmd" => crate::htm::run_daemon(args),
        _ => crate::client::run(args),
    }
}

mod bootstrap;
mod client;
mod client_environment;
mod client_output;
mod client_terminal;
mod client_terminal_loop;
#[cfg(windows)]
mod client_terminal_windows;
mod deadline;
mod detach;
mod error;
mod forward_config;
mod initial_connect;
mod resolver;
mod ssh_config;
mod ssh_process;

// Server-side roles. Upstream builds these only on POSIX, which is why an ET
// server on Windows meant running the Unix build inside WSL; here they are
// native on Windows too (ConPTY plus a loopback router).
mod server;
mod server_daemon;
mod terminal;
mod terminal_credentials;
mod terminal_daemon;
// The message of the day comes from `pam_motd`'s files, which exist only on
// POSIX systems.
#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod terminal_last_login;
#[cfg(unix)]
mod terminal_motd;
mod terminal_protocol;
mod terminal_pty;

mod htm;
mod htm_daemon;
mod terminal_jump;
