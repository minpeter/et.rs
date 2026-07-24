use std::ffi::OsString;

pub fn run(_args: &[OsString]) -> Result<i32, Box<dyn std::error::Error>> {
    eprintln!("etterminal: per-session terminal is not yet implemented");
    Ok(0)
}
