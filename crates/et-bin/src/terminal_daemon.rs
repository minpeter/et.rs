//! Detached per-session terminal startup over an inherited, bounded status pipe.
//!
//! The bootstrap parent owns the child until it receives a structured
//! `Registered` status. Every earlier return kills and reaps the child. The
//! anonymous stdout pipe is inherited across exec, unlike the old discoverable
//! readiness listener, so unrelated local processes cannot forge readiness.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::terminal_credentials::CredentialInput;

pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_MAGIC: &[u8; 4] = b"ETS1";
const STATUS_REGISTERED: u8 = 1;
const STATUS_FAILED: u8 = 2;
const MAX_STATUS_MESSAGE: usize = 8 * 1024;

pub fn spawn(router: &Path, input: &CredentialInput, verbose: u8) -> Result<(), String> {
    spawn_with_args(router, input, verbose, &[])
}

pub fn spawn_with_args(
    router: &Path,
    input: &CredentialInput,
    verbose: u8,
    extra: &[String],
) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate et executable: {error}"))?
        .canonicalize()
        .map_err(|error| format!("could not resolve et executable: {error}"))?;
    let mut command = crate::detach::command(executable.as_os_str());
    command
        .args([
            "terminal",
            "--session-child",
            "--ready-socket",
            "inherited",
            "--serverfifo",
            router
                .to_str()
                .ok_or_else(|| "invalid terminal router path".to_owned())?,
            &format!("--verbose={verbose}"),
        ])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::detach::configure(&mut command);
    let child = crate::detach::spawn(&mut command)
        .map_err(|error| format!("could not start terminal session process: {error}"))?;
    let mut startup = StartupChild::new(child);

    let credential_line = format!("{}/{}_{}\n", input.id, input.passkey, input.term);
    startup
        .child_mut()
        .stdin
        .take()
        .ok_or_else(|| "terminal child stdin was not created".to_owned())?
        .write_all(credential_line.as_bytes())
        .map_err(|error| format!("could not send terminal credentials: {error}"))?;

    let stdout = startup
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| "terminal child status pipe was not created".to_owned())?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("et-terminal-status".to_owned())
        .spawn(move || {
            let _ = sender.send(read_status(stdout));
        })
        .map_err(|error| format!("could not start terminal status worker: {error}"))?;
    startup.worker = Some(worker);

    let result = receiver
        .recv_timeout(READY_TIMEOUT)
        .map_err(|_| "timed out waiting for terminal registration".to_owned())?
        .map_err(|error| format!("terminal session process did not become ready: {error}"));
    if result.is_ok() {
        startup.commit();
    }
    result
}

/// Report committed router registration over the inherited stdout pipe.
pub fn signal(target: &Path) -> Result<(), String> {
    if target == Path::new("inherited") {
        return write_status(STATUS_REGISTERED, "");
    }
    // Compatibility for directly launched session-child test harnesses and
    // mixed local upgrades. Production bootstrap always uses the inherited
    // status pipe above.
    #[cfg(unix)]
    {
        let mut stream = std::os::unix::net::UnixStream::connect(target)
            .map_err(|error| format!("could not connect terminal readiness socket: {error}"))?;
        stream
            .write_all(&[1])
            .map_err(|error| format!("could not signal terminal readiness: {error}"))
    }
    #[cfg(windows)]
    {
        Err("legacy readiness sockets are unsupported on Windows".to_owned())
    }
}

/// Report a bounded startup failure before the bootstrap parent commits.
pub fn fail(message: &str) {
    let _ = write_status(STATUS_FAILED, message);
}

fn write_status(code: u8, message: &str) -> Result<(), String> {
    let bytes = message.as_bytes();
    let bytes = &bytes[..bytes.len().min(MAX_STATUS_MESSAGE)];
    let length = u16::try_from(bytes.len()).expect("status bound fits u16");
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(STATUS_MAGIC)
        .and_then(|()| output.write_all(&[code]))
        .and_then(|()| output.write_all(&length.to_be_bytes()))
        .and_then(|()| output.write_all(bytes))
        .and_then(|()| output.flush())
        .map_err(|error| format!("could not write terminal startup status: {error}"))
}

fn read_status(mut reader: impl Read) -> Result<(), String> {
    let mut header = [0u8; 7];
    reader
        .read_exact(&mut header)
        .map_err(|error| format!("terminal status channel closed: {error}"))?;
    if &header[..4] != STATUS_MAGIC {
        return Err("malformed terminal startup status".to_owned());
    }
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    if length > MAX_STATUS_MESSAGE {
        return Err("terminal startup status exceeds 8 KiB".to_owned());
    }
    let mut message = vec![0; length];
    reader
        .read_exact(&mut message)
        .map_err(|error| format!("truncated terminal startup status: {error}"))?;
    match header[4] {
        STATUS_REGISTERED if message.is_empty() => Ok(()),
        STATUS_FAILED => Err(String::from_utf8_lossy(&message).into_owned()),
        _ => Err("invalid terminal startup status".to_owned()),
    }
}

struct StartupChild {
    child: Option<Child>,
    worker: Option<JoinHandle<()>>,
    committed: bool,
}

impl StartupChild {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            worker: None,
            committed: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("startup child is owned")
    }

    fn commit(&mut self) {
        self.committed = true;
        self.child.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for StartupChild {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(child) = self.child.as_mut() {
                stop(child);
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_status_is_bounded_and_rejects_truncation() {
        let mut frame = Vec::new();
        frame.extend_from_slice(STATUS_MAGIC);
        frame.push(STATUS_FAILED);
        frame.extend_from_slice(&3u16.to_be_bytes());
        frame.extend_from_slice(b"bad");
        assert_eq!(read_status(frame.as_slice()), Err("bad".to_owned()));
        frame.pop();
        assert!(read_status(frame.as_slice())
            .unwrap_err()
            .contains("truncated"));
    }

    #[test]
    fn arbitrary_readiness_bytes_are_not_accepted() {
        assert!(read_status(b"\x01".as_slice()).is_err());
    }

    #[test]
    fn remote_deadline_leaves_outer_propagation_and_cleanup_margin() {
        let outer = crate::ssh_process::DEFAULT_BOOTSTRAP_TIMEOUT;
        assert!(outer >= READY_TIMEOUT + Duration::from_secs(30));
    }

    #[cfg(unix)]
    #[test]
    fn uncommitted_startup_guard_kills_and_reaps_child() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        drop(StartupChild::new(child));
        assert!(nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signal_exit_is_observed_as_closed_status_channel() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let error = read_status(child.stdout.take().unwrap()).unwrap_err();
        let status = child.wait().unwrap();
        assert!(!status.success());
        assert!(error.contains("closed"));
    }
}
