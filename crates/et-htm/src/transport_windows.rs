//! Authenticated, loopback-only HTM IPC. The secret inherits the user's
//! LOCALAPPDATA ACL, matching et-server's Windows router policy. Never put an
//! endpoint in the shared temp directory or accept an unauthenticated UI.

use std::fs::{File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub use std::net::TcpStream as Stream;

pub fn pipe_name() -> io::Result<PathBuf> {
    Ok(private_base()?.join("et-htm").join("htm.ipc"))
}

fn private_base() -> io::Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LOCALAPPDATA must be an absolute user-private directory",
            )
        })?;
    check_directory(&base)?;
    Ok(base)
}

fn check_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTM directory must not be a reparse point",
        ));
    }
    Ok(())
}

/// Restrict even explicit --socket paths to the existing user-private tree.
/// Reject parent traversal and every junction/symlink below LOCALAPPDATA.
fn prepare_path(path: &Path) -> io::Result<()> {
    let base = private_base()?;
    let relative = path.strip_prefix(&base).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTM endpoint must be under LOCALAPPDATA",
        )
    })?;
    if relative.components().count() < 2
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTM endpoint requires a private subdirectory",
        ));
    }
    let mut directory = base;
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            directory.push(part);
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            check_directory(&directory)?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTM endpoint must be a regular file",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn connect(path: &Path) -> io::Result<Stream> {
    prepare_path(path)?;
    et_net::local::connect(path)
}

pub struct Listener {
    listener: TcpListener,
    token: String,
    path: Option<PathBuf>,
    lock: Option<File>,
}

impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        prepare_path(path)?;
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        prepare_path(Path::new(&lock_path))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::AddrInUse, "htmd is already running")
            }
            std::fs::TryLockError::Error(error) => error,
        })?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let result = Self {
            listener,
            token: et_net::local::new_token(),
            path: Some(path.to_path_buf()),
            lock: Some(lock),
        };
        // Only the lock owner can retire a stale endpoint or publish a new one.
        // Files inherit the already-private parent ACL, as et-server's do.
        std::fs::write(
            path,
            format!("{}\n{}\n", result.listener.local_addr()?, result.token),
        )?;
        Ok(result)
    }

    pub fn accept(&self) -> io::Result<Stream> {
        let (mut stream, peer) = self.listener.accept()?;
        // Winsock accepts inherit FIONBIO from the listener. Token and frame
        // bodies use bounded blocking read_exact, including fragmented writes.
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        if !peer.ip().is_loopback()
            || et_net::local::accept_token(&mut stream, &self.token).is_err()
        {
            // No state, escape sequence, or pane output precedes authentication.
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub fn retire(&mut self) -> io::Result<()> {
        if let Some(path) = self.path.take() {
            std::fs::remove_file(path)?;
        }
        // Leave the empty lock file in place: unlinking a lock creates races
        // with another process that has already opened the same file.
        self.lock.take();
        Ok(())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            eprintln!("htmd: retiring IPC endpoint: {error}");
        }
    }
}

pub fn readable(stream: &Stream) -> io::Result<bool> {
    use filedescriptor::{poll, pollfd, AsRawSocketDescriptor, POLLIN};
    let mut descriptors = [pollfd {
        fd: stream.as_socket_descriptor(),
        events: POLLIN,
        revents: 0,
    }];
    poll(&mut descriptors, Some(Duration::from_millis(10))).map_err(io::Error::other)?;
    Ok(descriptors[0].revents != 0)
}

#[cfg(test)]
#[path = "transport_windows_tests.rs"]
mod tests;
