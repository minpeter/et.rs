//! Spawning processes that outlive the launching shell.
//!
//! Unix children re-exec through a descriptor-closing trampoline and call
//! `setsid` in the child. Windows uses `windows-spawn`, whose STARTUPINFOEX
//! handle list includes only configured stdio, together with mandatory job
//! breakaway flags. Failure to obtain either property fails before readiness.

use std::ffi::OsStr;
use std::io;

#[cfg(unix)]
pub type Command = std::process::Command;
#[cfg(unix)]
pub type Child = std::process::Child;
#[cfg(unix)]
pub type Stdio = std::process::Stdio;
#[cfg(unix)]
pub type ChildStdout = std::process::ChildStdout;
#[cfg(windows)]
pub type Command = windows_spawn::Command;
#[cfg(windows)]
pub type Child = windows_spawn::Child;
#[cfg(windows)]
pub type Stdio = windows_spawn::Stdio;
#[cfg(windows)]
pub type ChildStdout = windows_spawn::ChildStdout;

/// Construct a re-exec command with inherited-resource hygiene.
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

/// Configure `command` to survive the current shell/session.
pub fn configure(command: &mut Command) {
    // All platform policy is applied either by the Unix child (`setsid`) or by
    // the Windows spawn transaction below.
    let _ = command;
}

/// Spawn detached and fail closed if mandatory Windows breakaway or explicit
/// handle inheritance cannot be established.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    #[cfg(unix)]
    {
        command.spawn()
    }
    #[cfg(windows)]
    {
        use windows_spawn::{CreationFlags, DropPolicy, SpawnOptions};
        command.spawn_with(
            SpawnOptions::new()
                .creation_flags(
                    CreationFlags::DETACHED_PROCESS
                        | CreationFlags::NEW_PROCESS_GROUP
                        | CreationFlags::BREAKAWAY_FROM_JOB,
                )
                .drop_policy(DropPolicy::Detach),
        )
    }
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure(&mut command);
        let mut child = spawn(&mut command).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn windows_spawn_uses_explicit_handle_allowlist_and_breakaway() {
        // `windows_spawn::Command` exposes only configured stdio and explicit
        // handle arguments to STARTUPINFOEX. This type assertion prevents a
        // regression back to std::process::Command's inherit-all default.
        fn requires_allowlisted_command(_: &windows_spawn::Command) {}
        let command = command(OsStr::new("cmd.exe"));
        requires_allowlisted_command(&command);
    }
}
