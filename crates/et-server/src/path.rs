//! Router path selection and secure parent-directory preparation.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const FIFO_NAME: &str = "etserver.idpasskey.fifo";
const ROOT_FIFO: &str = "/var/run/etserver.idpasskey.fifo";

#[derive(Clone, Debug)]
pub struct RouterPath {
    path: PathBuf,
    socket_mode: u32,
    plan: DirectoryPlan,
}

#[derive(Clone, Debug)]
enum DirectoryPlan {
    Existing,
    RootDefault,
    Xdg { base: PathBuf },
    Home { home: PathBuf },
}

impl RouterPath {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn socket_mode(&self) -> u32 {
        self.socket_mode
    }

    pub(crate) fn prepare(&self) -> Result<(), PathError> {
        match &self.plan {
            DirectoryPlan::Existing => {
                let parent = self
                    .path
                    .parent()
                    .ok_or_else(|| PathError::UnsafeDirectory(self.path.clone()))?;
                validate_directory(parent, false)
            }
            DirectoryPlan::RootDefault => {
                let parent = self
                    .path
                    .parent()
                    .ok_or_else(|| PathError::UnsafeDirectory(self.path.clone()))?;
                let target = fs::canonicalize(parent).map_err(|source| PathError::Io {
                    operation: "resolve trusted root router directory",
                    path: parent.to_path_buf(),
                    source,
                })?;
                validate_directory(&target, false)
            }
            DirectoryPlan::Xdg { base } => {
                validate_directory(base, true)?;
                create_and_validate(&base.join("etserver"), 0o700, true)
            }
            DirectoryPlan::Home { home } => {
                validate_directory(home, true)?;
                let local = home.join(".local");
                create_and_validate(&local, 0o755, false)?;
                let share = local.join("share");
                create_and_validate(&share, 0o755, false)?;
                create_and_validate(&share.join("etserver"), 0o700, true)
            }
        }
    }
}

#[derive(Debug)]
pub enum PathError {
    RelativeOverride(PathBuf),
    MissingHome,
    RelativeHome(PathBuf),
    Symlink(PathBuf),
    NotSocket(PathBuf),
    LiveSocket(PathBuf),
    UnsafeDirectory(PathBuf),
    WrongOwner(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RelativeOverride(path) => {
                write!(
                    f,
                    "serverfifo override must be absolute: {}",
                    path.display()
                )
            }
            Self::MissingHome => write!(
                f,
                "HOME must be an absolute path when XDG_RUNTIME_DIR is unavailable"
            ),
            Self::RelativeHome(path) => write!(f, "HOME must be absolute: {}", path.display()),
            Self::Symlink(path) => {
                write!(f, "router path must not be a symlink: {}", path.display())
            }
            Self::NotSocket(path) => write!(f, "router path is not a socket: {}", path.display()),
            Self::LiveSocket(path) => {
                write!(f, "router socket is already live: {}", path.display())
            }
            Self::UnsafeDirectory(path) => {
                write!(f, "router directory is not secure: {}", path.display())
            }
            Self::WrongOwner(path) => {
                write!(f, "router path has the wrong owner: {}", path.display())
            }
            Self::Io {
                operation,
                path,
                source,
            } => {
                write!(f, "could not {operation} {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn select_router_path(override_path: Option<&Path>) -> Result<RouterPath, PathError> {
    let euid = rustix::process::geteuid().as_raw();
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    select_router_path_for(euid, override_path, xdg.as_deref(), home.as_deref())
}

pub fn select_router_path_for(
    euid: u32,
    override_path: Option<&Path>,
    xdg_runtime_dir: Option<&Path>,
    home: Option<&Path>,
) -> Result<RouterPath, PathError> {
    let socket_mode = if euid == 0 { 0o666 } else { 0o600 };
    if let Some(path) = override_path {
        if !path.is_absolute() {
            return Err(PathError::RelativeOverride(path.to_path_buf()));
        }
        return Ok(RouterPath {
            path: path.to_path_buf(),
            socket_mode,
            plan: DirectoryPlan::Existing,
        });
    }
    if euid == 0 {
        return Ok(RouterPath {
            path: PathBuf::from(ROOT_FIFO),
            socket_mode,
            plan: DirectoryPlan::RootDefault,
        });
    }
    if let Some(base) = xdg_runtime_dir.filter(|path| path.is_absolute()) {
        return Ok(RouterPath {
            path: base.join("etserver").join(FIFO_NAME),
            socket_mode,
            plan: DirectoryPlan::Xdg {
                base: base.to_path_buf(),
            },
        });
    }
    let home = home.ok_or(PathError::MissingHome)?;
    if !home.is_absolute() {
        return Err(PathError::RelativeHome(home.to_path_buf()));
    }
    Ok(RouterPath {
        path: home
            .join(".local")
            .join("share")
            .join("etserver")
            .join(FIFO_NAME),
        socket_mode,
        plan: DirectoryPlan::Home {
            home: home.to_path_buf(),
        },
    })
}

fn create_and_validate(path: &Path, mode: u32, private: bool) -> Result<(), PathError> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
                PathError::Io {
                    operation: "set permissions on",
                    path: path.to_path_buf(),
                    source,
                }
            })?
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(PathError::Io {
                operation: "create directory",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    validate_directory(path, private)
}

fn validate_directory(path: &Path, private: bool) -> Result<(), PathError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PathError::Io {
        operation: "inspect directory",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(PathError::WrongOwner(path.to_path_buf()));
    }
    let forbidden = if private { 0o077 } else { 0o022 };
    if metadata.mode() & forbidden != 0 {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod path_tests;
