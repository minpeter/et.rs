use std::ffi::OsString;

use clap::error::ErrorKind;
use clap::Parser;
use et_cli::server::{resolve_config, ServerArgs};

pub fn run(args: &[OsString]) -> Result<i32, clap::Error> {
    let parsed = ServerArgs::try_parse_from(
        ["etserver"]
            .iter()
            .map(|s| OsString::from(*s))
            .chain(args.iter().cloned()),
    )?;
    let _config = resolve_config(&parsed, None)
        .map_err(|error| clap::Error::raw(ErrorKind::ValueValidation, error.to_string()))?;
    eprintln!("etserver: listening is not yet implemented (transport layer WIP)");
    Ok(2)
}
