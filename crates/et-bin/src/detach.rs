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

use std::ffi::OsStr;
use std::io;
use std::process::{Child, Command};

/// Construct a re-exec command that closes every descriptor above stderr
/// before entering the long-lived child. The shell is only a descriptor-hygiene
/// trampoline; all executable paths and arguments remain positional values.
pub fn command(executable: &OsStr) -> Command {
    #[cfg(unix)]
    {
        const CLOSE_AND_EXEC: &str = r#"
for path in /proc/self/fd/[3-9] /proc/self/fd/[1-9][0-9]* /dev/fd/[3-9] /dev/fd/[1-9][0-9]*; do
    [ -e "$path" ] || continue
    fd=${path##*/}
    eval "exec ${fd}>&-" 2>/dev/null || :
done
exec "$@"
"#;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", CLOSE_AND_EXEC, "et-detached-child"]);
        command.arg(executable);
        command
    }
    #[cfg(windows)]
    {
        Command::new(executable)
    }
}

/// Configure `command` to survive the current shell/session. On Unix the
/// re-executed child calls `setsid()` itself; making it a process-group leader
/// here would make that operation fail with `EPERM`.
pub fn configure(command: &mut Command) {
    #[cfg(unix)]
    let _ = command;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_flags(true));
    }
}

/// Spawn `command` detached. Windows must fail closed when the enclosing job
/// forbids breakaway: retrying without breakaway would report readiness for a
/// child that OpenSSH kills as soon as bootstrap exits.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    command.spawn()
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
    fn breakaway_is_mandatory() {
        assert_eq!(windows_flags(true) & 0x0100_0000, 0x0100_0000);
    }
}
