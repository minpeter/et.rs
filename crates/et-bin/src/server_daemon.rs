//! `etserver --daemon` support, mirroring upstream `DaemonCreator::create`.
//!
//! Upstream double-forks, calls `setsid`, writes the pid file, `chdir("/")`,
//! and redirects stdio to `/dev/null`. Forking is not expressible in safe
//! Rust, so the same end state is reached by re-executing this binary as a
//! detached child: the parent returns after runtime-startup acknowledgement,
//! and the child becomes a session leader before serving.

use crate::detach::{ChildStderr, Stdio};
#[cfg(any(windows, test))]
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

#[cfg(unix)]
pub const DEFAULT_PID_FILE: &str = "/var/run/etserver.pid";
/// Windows has no `/var/run`; the pid file lives beside the router endpoint.
#[cfg(windows)]
pub const DEFAULT_PID_FILE: &str = "etserver.pid";

const STATUS_ENV: &str = "ET_SERVER_DAEMON_STATUS";
const STATUS_TOKEN: &str = "ready-v1";
const STATUS_MAGIC: &[u8; 4] = b"ETD1";
const STATUS_READY: u8 = 1;
const STATUS_FAILED: u8 = 2;
const MAX_STATUS_MESSAGE: usize = 8 * 1024;
#[cfg(unix)]
const SHUTDOWN_STATUS_ENV: &str = "ET_RS_TEST_SERVER_SHUTDOWN_SOCKET";
#[cfg(unix)]
const RUNTIME_STATUS_FRAME: &[u8; 4] = b"ETD0";
#[cfg(unix)]
const SHUTDOWN_STATUS_FRAME: &[u8; 4] = b"ETD2";
const READY_TIMEOUT: Duration = Duration::from_secs(45);

/// Re-exec this binary as a detached background server and return after the
/// child acknowledges runtime startup.
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
    let mut child = crate::detach::direct_command(executable.as_os_str());
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
        .stderr(Stdio::piped())
        .env(STATUS_ENV, STATUS_TOKEN)
        .current_dir(root_directory());
    crate::detach::configure(&mut child);
    let mut child = crate::detach::spawn(&mut child)
        .map_err(|error| format!("could not start background etserver: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "background etserver status pipe was not created".to_owned())?;
    await_startup(child, stderr, READY_TIMEOUT)
}

/// Finish detaching inside the re-executed child: become a session leader,
/// move to `/`, and record the pid file.
pub fn detach_child(pidfile: Option<&Path>) -> Result<(), String> {
    #[cfg(unix)]
    {
        crate::detach::close_inherited_descriptors()
            .map_err(|error| format!("could not close inherited descriptors: {error}"))?;
        // A fresh child of the original shell is not a process-group leader, so
        // this succeeds and drops the controlling terminal.
        rustix::process::setsid()
            .map_err(|error| format!("could not create a new session: {error}"))?;
    }
    // The working directory is already `/`: the parent sets it on the child
    // via `Command::current_dir`, matching upstream's `chdir("/")`.
    let path = pidfile.unwrap_or_else(|| Path::new(DEFAULT_PID_FILE));
    write_pid_file(path)
}

/// Acknowledge that signal handling and the server runtime are both ready.
pub fn signal_startup_complete() -> Result<(), String> {
    write_startup_status(STATUS_READY, "")
}

/// Report a bounded daemon startup failure to the spawning parent.
pub fn fail_startup(message: &str) {
    let _ = write_startup_status(STATUS_FAILED, message);
}

fn write_startup_status(code: u8, message: &str) -> Result<(), String> {
    if std::env::var(STATUS_ENV).as_deref() != Ok(STATUS_TOKEN) {
        return Ok(());
    }
    let bytes = message.as_bytes();
    let bytes = &bytes[..bytes.len().min(MAX_STATUS_MESSAGE)];
    let length = u16::try_from(bytes.len()).expect("daemon status bound fits u16");
    let stderr = std::io::stderr();
    let mut output = stderr.lock();
    output
        .write_all(STATUS_MAGIC)
        .and_then(|()| output.write_all(&[code]))
        .and_then(|()| output.write_all(&length.to_be_bytes()))
        .and_then(|()| output.write_all(bytes))
        .and_then(|()| output.flush())
        .map_err(|error| format!("could not write daemon startup status: {error}"))
}

fn await_startup(
    mut child: crate::detach::Child,
    stderr: ChildStderr,
    timeout: Duration,
) -> Result<(), String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = match spawn_status_worker(stderr, sender) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let result = match receiver.recv_timeout(timeout) {
        Ok(result) => {
            result.map_err(|error| format!("background etserver did not detach: {error}"))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err("timed out waiting for background etserver to detach".to_owned())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("background etserver status reader terminated".to_owned())
        }
    };
    if result.is_ok() {
        let _ = worker.join();
        return Ok(());
    }

    let status = match child.try_wait() {
        Ok(Some(status)) => format!("child exited with {status}"),
        Ok(None) => {
            let _ = child.kill();
            match child.wait() {
                Ok(status) => format!("child was still running and was killed: {status}"),
                Err(wait_error) => format!("child kill/wait failed: {wait_error}"),
            }
        }
        Err(wait_error) => format!("could not inspect child exit status: {wait_error}"),
    };
    let _ = worker.join();
    Err(format!("{}; {status}", result.unwrap_err()))
}

fn spawn_status_worker(
    stderr: ChildStderr,
    sender: mpsc::SyncSender<Result<(), String>>,
) -> Result<std::thread::JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name("et-server-daemon-status".to_owned())
        .spawn(move || {
            let _ = sender.send(read_status(stderr));
        })
        .map_err(|error| format!("could not start daemon status worker: {error}"))
}

fn read_status(mut status: impl Read) -> Result<(), String> {
    let mut header = [0u8; 7];
    let mut filled = 0;
    while filled < header.len() {
        match status.read(&mut header[filled..]) {
            Ok(0) => {
                return Err(format!(
                    "daemon status channel closed after {filled} header bytes: {}",
                    escaped_status_bytes(&header[..filled])
                ));
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(format!(
                    "daemon status channel failed after {filled} header bytes: {error}; bytes={}",
                    escaped_status_bytes(&header[..filled])
                ));
            }
        }
    }
    if &header[..4] != STATUS_MAGIC {
        return Err(format!(
            "malformed daemon startup status: {}",
            escaped_status_bytes(&header)
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    if length > MAX_STATUS_MESSAGE {
        return Err("oversized daemon startup status".to_owned());
    }
    let mut message = vec![0u8; length];
    status
        .read_exact(&mut message)
        .map_err(|error| format!("truncated daemon startup status: {error}"))?;
    match header[4] {
        STATUS_READY if message.is_empty() => Ok(()),
        STATUS_FAILED => Err(String::from_utf8_lossy(&message).into_owned()),
        _ => Err("malformed daemon startup status".to_owned()),
    }
}

fn escaped_status_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

/// Signal an opt-in test observer after signal handling and runtime startup.
pub fn signal_runtime_started() -> Result<(), String> {
    #[cfg(unix)]
    signal_test_status(RUNTIME_STATUS_FRAME, "runtime startup")?;
    Ok(())
}

/// Signal an opt-in test observer after runtime shutdown and router cleanup.
pub fn signal_shutdown_complete() -> Result<(), String> {
    #[cfg(unix)]
    signal_test_status(SHUTDOWN_STATUS_FRAME, "shutdown completion")?;
    Ok(())
}

#[cfg(unix)]
fn signal_test_status(frame: &[u8; 4], phase: &str) -> Result<(), String> {
    let Some(path) = std::env::var_os(SHUTDOWN_STATUS_ENV) else {
        return Ok(());
    };
    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|error| format!("could not connect daemon {phase} status: {error}"))?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not signal daemon {phase}: {error}"))
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

/// Record this process id at `path`.
///
/// Unix refuses symlinks, extra hard links, fifos, and writable ancestors,
/// then truncates. Upstream calls this only from the daemon child and never
/// removes the file. Foreground `etserver --pidfile` uses the same writer
/// and the same retention.
pub(crate) fn write_pid_file(path: &Path) -> Result<(), String> {
    let contents = format!("{}\n", std::process::id());
    #[cfg(unix)]
    {
        // Refuse symlinks, extra hard links, special files, and directories
        // whose ancestors another user can replace. Truncate only after the
        // inode checks, so a stale pid cannot survive and a victim cannot be
        // overwritten through a planted link.
        et_server::private_storage::replace_file(path, &contents).map_err(|error| {
            format!(
                "Error opening pidfile for writing: {}: {error}",
                path.display()
            )
        })
    }
    #[cfg(not(unix))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = options.open(path).map_err(|error| {
            format!(
                "Error opening pidfile for writing: {}: {error}",
                path.display()
            )
        })?;
        file.write_all(contents.as_bytes())
            .and_then(|()| file.flush())
            .map_err(|error| format!("Error writing pidfile: {}: {error}", path.display()))
    }
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
        #[cfg(unix)]
        assert_eq!(pid_file_path(None), PathBuf::from("/var/run/etserver.pid"));
        #[cfg(windows)]
        assert_eq!(pid_file_path(None), PathBuf::from("etserver.pid"));
        assert_eq!(
            pid_file_path(Some(Path::new("/tmp/custom.pid"))),
            PathBuf::from("/tmp/custom.pid")
        );
    }

    #[cfg(unix)]
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

    #[test]
    fn pid_file_truncates_stale_contents() {
        let directory = std::env::temp_dir().join(format!(
            "et-pid-truncate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.join("daemon.pid");
        fs::write(&path, "123456789\nstale trailing bytes\n").unwrap();
        write_pid_file(&path).unwrap();
        write_pid_file(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id())
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn pid_file_refuses_links_special_files_and_writable_parents() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::time::Duration;

        let directory = std::env::temp_dir().join(format!(
            "et-pid-secure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = directory.join("victim");
        fs::write(&victim, "DO NOT OVERWRITE THIS FILE\n").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();

        let link = directory.join("daemon.pid");
        symlink(&victim, &link).unwrap();
        assert!(write_pid_file(&link).is_err());
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "DO NOT OVERWRITE THIS FILE\n"
        );
        fs::remove_file(&link).unwrap();

        std::fs::hard_link(&victim, &link).unwrap();
        assert!(write_pid_file(&link).is_err());
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "DO NOT OVERWRITE THIS FILE\n"
        );
        fs::remove_file(&link).unwrap();

        // rustix::fs::mknodat is unavailable on macOS. mkfifo is on Linux and macOS.
        let created = std::process::Command::new("mkfifo")
            .arg(&link)
            .status()
            .expect("mkfifo");
        assert!(created.success(), "mkfifo failed: {created}");
        let path = link.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(write_pid_file(&path));
        });
        let result = receiver.recv_timeout(Duration::from_secs(2));
        assert!(
            result.is_ok(),
            "pid write blocked on a FIFO instead of refusing it"
        );
        assert!(result.unwrap().is_err());
        fs::remove_file(&link).unwrap();

        fs::write(&link, "UNCHANGED\n").unwrap();
        fs::set_permissions(&link, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_pid_file(&link).is_err());
        assert_eq!(fs::read_to_string(&link).unwrap(), "UNCHANGED\n");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&link, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(write_pid_file(&link).is_err());
        assert_eq!(fs::read_to_string(&link).unwrap(), "UNCHANGED\n");
        let _ = fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn partial_status_timeout_kills_reaps_then_joins_reader() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "printf ET >&2; printf R >&1; exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let mut ready = [0u8; 1];
        child.stdout.take().unwrap().read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");
        let stderr = child.stderr.take().unwrap();

        let error = await_startup(child, stderr, Duration::from_millis(50)).unwrap_err();

        assert!(error.contains("timed out waiting for background etserver"));
        assert!(error.contains("was killed"));
        assert!(nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err());
    }
}
