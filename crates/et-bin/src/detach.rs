//! Spawning processes that outlive the launching shell.
//!
//! Unix only needs a new process group; the child keeps running once the
//! bootstrap `ssh` exits.
//!
//! Windows needs more care. OpenSSH puts each session in a job object and
//! terminates the job when the session ends, so a plain `DETACHED_PROCESS`
//! child of an ssh-launched command dies with the connection. Sessions must
//! therefore break away from that job as well, which is the piece that makes an
//! `et` server and terminal usable on Windows without WSL. Some jobs forbid
//! breakaway, so the flag is dropped on retry.

use std::io;
use std::process::{Child, Command};

/// Configure `command` to survive the current shell/session.
pub fn configure(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_flags(true));
    }
}

/// Spawn `command` detached, retrying without job breakaway if the job object
/// does not allow it.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    match command.spawn() {
        Ok(child) => Ok(child),
        #[cfg(windows)]
        Err(error) => {
            use std::os::windows::process::CommandExt;
            command.creation_flags(windows_flags(false));
            command.spawn().map_err(|_| error)
        }
        #[cfg(unix)]
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn windows_flags(breakaway: bool) -> u32 {
    /// No inherited console.
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    /// Ctrl+C in the parent console does not reach the child.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    /// Leave the launching job object (e.g. the OpenSSH session job).
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let mut flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    if breakaway {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_child_runs_and_exits() {
        #[cfg(unix)]
        let mut command = Command::new("true");
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/C", "exit 0"]);
            command
        };
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        configure(&mut command);
        let mut child = spawn(&mut command).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn breakaway_is_requested_first_and_optional() {
        assert_ne!(windows_flags(true), windows_flags(false));
        assert_eq!(windows_flags(true) & 0x0100_0000, 0x0100_0000);
        assert_eq!(windows_flags(false) & 0x0100_0000, 0);
    }
}
