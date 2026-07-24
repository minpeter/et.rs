use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::path::{PathError, RouterPath};

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

pub(crate) struct OwnedRouterListener {
    listener: UnixListener,
    path: PathBuf,
    identity: FileIdentity,
}

impl OwnedRouterListener {
    pub(crate) fn bind(selected: &RouterPath) -> Result<Self, PathError> {
        selected.prepare()?;
        prepare_socket_path(selected.path())?;
        let listener = UnixListener::bind(selected.path()).map_err(|source| PathError::Io {
            operation: "bind router socket",
            path: selected.path().to_path_buf(),
            source,
        })?;
        let metadata = fs::symlink_metadata(selected.path()).map_err(|source| PathError::Io {
            operation: "inspect bound router socket",
            path: selected.path().to_path_buf(),
            source,
        })?;
        let identity = FileIdentity::from_metadata(&metadata);
        let owned = Self {
            listener,
            path: selected.path().to_path_buf(),
            identity,
        };
        fs::set_permissions(
            selected.path(),
            fs::Permissions::from_mode(selected.socket_mode()),
        )
        .map_err(|source| PathError::Io {
            operation: "set router socket permissions on",
            path: selected.path().to_path_buf(),
            source,
        })?;
        owned
            .listener
            .set_nonblocking(true)
            .map_err(|source| PathError::Io {
                operation: "configure router socket",
                path: selected.path().to_path_buf(),
                source,
            })?;
        Ok(owned)
    }

    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }

    pub(crate) fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
        self.listener.accept()
    }
}

impl Drop for OwnedRouterListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && self.identity.matches(&metadata)
            && metadata.uid() == rustix::process::geteuid().as_raw()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        }
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        self.device == metadata.dev() && self.inode == metadata.ino() && self.uid == metadata.uid()
    }
}

fn prepare_socket_path(path: &Path) -> Result<(), PathError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(PathError::Io {
                operation: "inspect router path",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(PathError::Symlink(path.to_path_buf()));
    }
    if !metadata.file_type().is_socket() {
        return Err(PathError::NotSocket(path.to_path_buf()));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(PathError::WrongOwner(path.to_path_buf()));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(PathError::LiveSocket(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            remove_stale_socket(path, FileIdentity::from_metadata(&metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PathError::Io {
            operation: "probe router socket",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_stale_socket(path: &Path, expected: FileIdentity) -> Result<(), PathError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PathError::Io {
        operation: "reinspect stale router socket",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_socket() || !expected.matches(&metadata) {
        return Err(PathError::NotSocket(path.to_path_buf()));
    }
    fs::remove_file(path).map_err(|source| PathError::Io {
        operation: "remove stale router socket",
        path: path.to_path_buf(),
        source,
    })
}
