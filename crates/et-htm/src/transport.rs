//! HTM's local IPC boundary. Unix uses an owned, private socket directory.
//! Windows uses et-net's authenticated loopback endpoint-file convention.

#[cfg(any(windows, test))]
#[path = "transport_auth.rs"]
mod auth;

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
    use std::os::unix::fs::DirBuilderExt;
    let name = format!("htm.{}", rustix::process::getuid().as_raw());
    let directory = std::env::temp_dir().join(&name);
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let path = directory.join(format!("{name}.ipc"));
    check_path(&path)?;
    Ok(path)
}

#[cfg(unix)]
pub fn connect(path: &Path) -> io::Result<Stream> {
    check_path(path)?;
    Stream::connect(path)
}

#[cfg(unix)]
fn check_path(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let uid = rustix::process::getuid().as_raw();
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTM socket directory must be owned by this user and mode 0700",
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_socket() || metadata.uid() != uid => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTM endpoint must be an owned socket",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
        check_path(path)?;
        if path.exists() {
            match Stream::connect(path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "htmd is already running",
                    ))
                }
            }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    #[test]
    fn private_path_rejects_files_links_and_public_directories() {
        let directory = std::env::temp_dir().join(format!(
            "et-htm-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("htm.ipc");
        std::fs::write(&path, b"keep").unwrap();
        assert!(Listener::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(Listener::bind(&path).is_err());
        assert!(connect(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Listener::bind(&path).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let mut listener = Listener::bind(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Listener::bind(&path).is_err());
        listener.retire().unwrap();
        let replacement = Listener::bind(&path).unwrap();
        drop(listener);
        assert!(connect(&path).is_ok());
        drop(replacement);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
