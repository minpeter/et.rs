//! HTM's local IPC boundary. Unix preserves the upstream socket path/mode.
//! Windows uses et-net's authenticated loopback endpoint-file convention.

#[cfg(windows)]
#[path = "transport_windows.rs"]
mod platform;
#[cfg(windows)]
pub use platform::{connect, pipe_name, readable, Listener, Stream};

#[cfg(unix)]
pub use std::os::unix::net::UnixStream as Stream;

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub fn pipe_name() -> io::Result<PathBuf> {
    Ok(std::env::temp_dir().join(format!("htm.{}.ipc", rustix::process::getuid().as_raw())))
}

#[cfg(unix)]
pub fn connect(path: &Path) -> io::Result<Stream> {
    Stream::connect(path)
}

#[cfg(unix)]
pub struct Listener {
    listener: std::os::unix::net::UnixListener,
    path: Option<PathBuf>,
}

#[cfg(unix)]
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() && Stream::connect(path).is_err() {
            std::fs::remove_file(path)?;
        }
        let listener = Self {
            listener: std::os::unix::net::UnixListener::bind(path)?,
            path: Some(path.to_path_buf()),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        listener.listener.set_nonblocking(true)?;
        Ok(listener)
    }

    pub fn accept(&self) -> io::Result<Stream> {
        self.listener.accept().map(|(stream, _)| stream)
    }

    pub fn retire(&mut self) -> io::Result<()> {
        if let Some(path) = self.path.take() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            eprintln!("htmd: retiring IPC socket: {error}");
        }
    }
}

/// Wait for daemon input using upstream's 10ms output-drain cadence.
#[cfg(unix)]
pub fn readable(stream: &Stream) -> io::Result<bool> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut descriptors = [PollFd::new(
        stream,
        PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
    )];
    poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        }),
    )?;
    // Read before reacting to HUP so a final complete message is not discarded.
    Ok(!descriptors[0].revents().is_empty())
}
