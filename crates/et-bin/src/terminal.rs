use std::ffi::OsString;

pub fn run(_args: &[OsString]) -> Result<i32, clap::Error> {
    eprintln!("etterminal: per-session terminal is not yet implemented");
    Ok(2)
}
