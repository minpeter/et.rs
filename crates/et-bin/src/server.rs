use std::ffi::OsString;

use clap::Parser;
use et_cli::server::{resolve_config, ServerArgs};

pub fn run(args: &[OsString]) -> Result<i32, Box<dyn std::error::Error>> {
    let parsed = ServerArgs::try_parse_from(
        ["etserver"]
            .iter()
            .map(|s| OsString::from(*s))
            .chain(args.iter().cloned()),
    )?;
    let _cfg = resolve_config(&parsed, None);
    eprintln!("etserver: listening is not yet implemented (transport layer WIP)");
    Ok(0)
}
