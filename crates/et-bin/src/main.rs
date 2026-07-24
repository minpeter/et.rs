#![forbid(unsafe_code)]

//! Single-binary entry point with role dispatch by `argv[0]`.
//!
//! One compiled binary serves all three EternalTerminal roles:
//! - `et`        → client (default)
//! - `etserver`  → server
//! - `etterminal`→ per-session terminal
//!
//! Busybox-style symlinks (`ln -s et etserver`) select the role. The leading
//! positional subcommand (`et server`, `et terminal`) is an explicit fallback.

use std::ffi::OsString;

fn main() {
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
        Err(error) => error.exit(),
    }
}

fn dispatch(prog: &str, args: &[OsString]) -> Result<i32, clap::Error> {
    if prog == "etserver" {
        return crate::server::run(args);
    }
    if prog == "etterminal" {
        return crate::terminal::run(args);
    }
    if let Some(first) = args.first().and_then(|s| s.to_str()) {
        match first {
            "server" => return crate::server::run(&args[1..]),
            "terminal" => return crate::terminal::run(&args[1..]),
            "client" => return crate::client::run(&args[1..]),
            _ => {}
        }
    }
    crate::client::run(args)
}

mod bootstrap;
mod client;
mod error;
mod initial_connect;
mod server;
mod ssh_process;
mod terminal;
