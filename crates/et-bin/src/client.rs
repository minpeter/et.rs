use std::ffi::OsString;

use clap::Parser;
use et_cli::client::ClientArgs;

pub fn run(args: &[OsString]) -> Result<i32, Box<dyn std::error::Error>> {
    let parsed = ClientArgs::try_parse_from(
        ["et"]
            .iter()
            .map(|s| OsString::from(*s))
            .chain(args.iter().cloned()),
    )?;
    if parsed.telemetry {
        eprintln!("note: et.rs never collects telemetry; --telemetry is a no-op.");
    }
    eprintln!(
        "et: connecting to {}:{} is not yet implemented (transport layer WIP)",
        parsed.host, parsed.port
    );
    Ok(0)
}
