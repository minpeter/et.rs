//! `etserver --daemon` support, mirroring upstream `DaemonCreator::create`.
//!
//! Upstream double-forks, calls `setsid`, writes the pid file, `chdir("/")`,
//! and redirects stdio to `/dev/null`. Forking is not expressible in safe
//! Rust, so the same end state is reached by re-executing this binary as a
//! detached child: the parent returns immediately (exit 0), and the child
//! becomes a session leader before serving.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
pub const DEFAULT_PID_FILE: &str = "/var/run/etserver.pid";
/// Windows has no `/var/run`; the pid file lives beside the router endpoint.
#[cfg(windows)]
pub const DEFAULT_PID_FILE: &str = "etserver.pid";

/// Re-exec this binary as a detached background server and return.
///
/// The child receives the original arguments with `--daemon` replaced by the
/// internal `--daemon-child` marker so it knows to finish detaching.
pub fn spawn_detached(args: &[std::ffi::OsString]) -> Result<(), String> {
    // `current_exe()` can preserve the `etserver` busybox-style symlink on
    // macOS. Re-executing that path with the explicit `server` subcommand
    // would then parse as `etserver server …`; use the real binary so the
    // explicit role selection below is unambiguous on every Unix platform.
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate etserver executable: {error}"))?
        .canonicalize()
        .map_err(|error| format!("could not resolve etserver executable: {error}"))?;
    let mut child = Command::new(executable);
    child.arg("server");
    for argument in args {
        if argument == std::ffi::OsStr::new("--daemon") {
            child.arg("--daemon-child");
        } else {
            child.arg(argument);
        }
    }
    child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(root_directory());
    crate::detach::configure(&mut child);
    crate::detach::spawn(&mut child)
        .map(|_| ())
        .map_err(|error| format!("could not start background etserver: {error}"))
}

/// Finish detaching inside the re-executed child: become a session leader,
/// move to `/`, and record the pid file.
pub fn detach_child(pidfile: Option<&Path>) -> Result<(), String> {
    #[cfg(unix)]
    {
        // A fresh child of the original shell is not a process-group leader, so
        // this succeeds and drops the controlling terminal.
        if let Err(error) = rustix::process::setsid() {
            // Already a session leader is not an error for our purposes.
            if error != rustix::io::Errno::PERM {
                return Err(format!("could not create a new session: {error}"));
            }
        }
    }
    // The working directory is already `/`: the parent sets it on the child
    // via `Command::current_dir`, matching upstream's `chdir("/")`.
    let path = pidfile.unwrap_or_else(|| Path::new(DEFAULT_PID_FILE));
    write_pid_file(path)
}

/// Working directory for the detached server.
fn root_directory() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/")
    }
    #[cfg(windows)]
    {
        std::env::var_os("SystemDrive")
            .map(|drive| PathBuf::from(format!("{}\\", drive.to_string_lossy())))
            .unwrap_or_else(|| PathBuf::from("C:\\"))
    }
}

fn write_pid_file(path: &Path) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "Error opening pidfile for writing: {}: {error}",
            path.display()
        )
    })?;
    writeln!(file, "{}", std::process::id())
        .and_then(|()| file.flush())
        .map_err(|error| format!("Error writing pidfile: {}: {error}", path.display()))
}

/// Resolve the pid-file path with the upstream default.
#[cfg_attr(not(test), allow(dead_code))]
pub fn pid_file_path(explicit: Option<&Path>) -> PathBuf {
    explicit.map_or_else(|| PathBuf::from(DEFAULT_PID_FILE), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_defaults_to_the_upstream_location() {
        assert_eq!(pid_file_path(None), PathBuf::from("/var/run/etserver.pid"));
        assert_eq!(
            pid_file_path(Some(Path::new("/tmp/custom.pid"))),
            PathBuf::from("/tmp/custom.pid")
        );
    }

    #[test]
    fn pid_file_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("et-pidfile-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("etserver.pid");
        write_pid_file(&path).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents.trim(), std::process::id().to_string());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn pid_file_errors_are_reported_with_the_path() {
        let error = write_pid_file(Path::new("/nonexistent-dir/etserver.pid")).unwrap_err();
        assert!(error.contains("/nonexistent-dir/etserver.pid"));
    }
}
