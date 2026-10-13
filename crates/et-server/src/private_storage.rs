//! Descriptor walk for private files and directories.
//!
//! Upstream `private_storage` (EternalTerminal #893). Every ancestor is opened
//! with `O_NOFOLLOW`. A root-owned symlink is followed only when its parent is
//! not writable by other users, so macOS `/tmp` → `/private/tmp` still works
//! and a user-planted link does not. Group write is allowed only for the
//! owner's user-private group.

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    fchmod, fstat, ftruncate, mkdirat, open, openat, readlinkat, statat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;

use crate::path::PathError;

const MAX_SYMLINKS: u32 = 40;

/// Create `path` as a private `0700` directory, or tighten an existing safe one.
pub fn ensure_directory(path: &Path) -> Result<(), PathError> {
    let _opened = open_directory(path, true, true, 0)?;
    Ok(())
}

/// The final directory must be owned by this user. Ancestors may be root-owned,
/// including a sticky directory such as `/tmp`.
pub fn check_user_directory(path: &Path) -> Result<(), PathError> {
    let opened = open_directory(path, false, false, 0)?;
    let stat = fstat(&opened.fd).map_err(|errno| io_error("inspect directory", path, errno))?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(PathError::WrongOwner(path.to_path_buf()));
    }
    if writable_by_others(&stat) {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

/// Replace `path` with `contents` without following a link or truncating an
/// unsafe inode. The parent walk matches [`ensure_directory`].
pub fn replace_file(path: &Path, contents: &str) -> Result<(), PathError> {
    let normalized = normalize(path);
    let parent = normalized
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PathError::UnsafeDirectory(normalized.clone()))?;
    let name = normalized
        .file_name()
        .ok_or_else(|| PathError::UnsafeDirectory(normalized.clone()))?;
    let directory = open_directory(parent, false, false, 0)?;
    let descriptor = openat(
        &directory.fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| io_error("open pid file", &normalized, errno))?;
    verify_file(&descriptor, &normalized)?;
    ftruncate(&descriptor, 0).map_err(|errno| io_error("truncate pid file", &normalized, errno))?;
    let mut file = std::fs::File::from(descriptor);
    use std::io::Write;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|source| PathError::Io {
            operation: "write pid file",
            path: normalized,
            source,
        })?;
    Ok(())
}

struct Opened {
    fd: OwnedFd,
}

fn open_directory(
    path: &Path,
    create: bool,
    make_private: bool,
    depth: u32,
) -> Result<Opened, PathError> {
    if depth > MAX_SYMLINKS {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    let path = normalize(path);
    if make_private && path == Path::new("/") {
        return Err(PathError::UnsafeDirectory(path));
    }
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| io_error("open filesystem root", Path::new("/"), errno))?;
    verify_ancestor(&root, Path::new("/"))?;
    let mut current = root;
    let mut resolved = PathBuf::from("/");
    let components: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir | Component::Prefix(_) => Some(OsString::from("..")),
        })
        .collect();
    if components.iter().any(|component| component == "..") {
        return Err(PathError::UnsafeDirectory(path));
    }
    for (index, name) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let traversed = resolved.join(name);
        let parent_stat =
            fstat(&current).map_err(|errno| io_error("inspect directory", &resolved, errno))?;
        match openat(
            &current,
            name.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                verify_ancestor(&fd, &traversed)?;
                current = fd;
                resolved = traversed;
            }
            Err(Errno::NOENT) if create => {
                match mkdirat(&current, name.as_os_str(), Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(errno) => return Err(io_error("create directory", &traversed, errno)),
                }
                let fd = openat(
                    &current,
                    name.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|errno| io_error("open directory", &traversed, errno))?;
                verify_ancestor(&fd, &traversed)?;
                current = fd;
                resolved = traversed;
            }
            Err(errno) => {
                let link = statat(&current, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).ok();
                let is_link = link
                    .as_ref()
                    .is_some_and(|stat| FileType::from_raw_mode(stat.st_mode).is_symlink());
                let follow = link.as_ref().is_some_and(|stat| {
                    FileType::from_raw_mode(stat.st_mode).is_symlink()
                        && stat.st_uid == 0
                        && !(make_private && final_component)
                        && !writable_by_others(&parent_stat)
                });
                if is_link && !follow {
                    return Err(PathError::UnsafeDirectory(traversed));
                }
                if !follow {
                    return Err(io_error("open directory", &traversed, errno));
                }
                let target = read_link(&current, name, &traversed)?;
                let target_path = if target.is_absolute() {
                    target
                } else {
                    resolved.join(target)
                };
                let opened = open_directory(&target_path, false, false, depth + 1)?;
                current = opened.fd;
                resolved = normalize(&target_path);
            }
        }
    }
    if make_private {
        let stat =
            fstat(&current).map_err(|errno| io_error("inspect directory", &resolved, errno))?;
        if stat.st_uid != rustix::process::geteuid().as_raw() {
            return Err(PathError::WrongOwner(resolved));
        }
        if writable_by_others(&stat) {
            return Err(PathError::UnsafeDirectory(resolved.clone()));
        }
        fchmod(&current, Mode::from_raw_mode(0o700))
            .map_err(|errno| io_error("restrict directory", &resolved, errno))?;
    }
    Ok(Opened { fd: current })
}

fn verify_ancestor(fd: &OwnedFd, path: &Path) -> Result<(), PathError> {
    let stat = fstat(fd).map_err(|errno| io_error("inspect directory", path, errno))?;
    let sticky_root = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
    let owner_ok = stat.st_uid == rustix::process::geteuid().as_raw() || stat.st_uid == 0;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || !owner_ok
        || (writable_by_others(&stat) && !sticky_root)
    {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn verify_file(fd: &OwnedFd, path: &Path) -> Result<(), PathError> {
    let stat = fstat(fd).map_err(|errno| io_error("inspect pid file", path, errno))?;
    let regular = FileType::from_raw_mode(stat.st_mode).is_file();
    if !regular || stat.st_nlink != 1 || writable_by_others(&stat) {
        return Err(PathError::UnsafeDirectory(path.to_path_buf()));
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(PathError::WrongOwner(path.to_path_buf()));
    }
    fchmod(fd, Mode::RUSR | Mode::WUSR)
        .map_err(|errno| io_error("restrict pid file", path, errno))?;
    Ok(())
}

fn writable_by_others(stat: &rustix::fs::Stat) -> bool {
    if stat.st_mode & 0o002 != 0 {
        return true;
    }
    stat.st_mode & 0o020 != 0 && !is_user_private_group(stat.st_uid, stat.st_gid)
}

fn is_user_private_group(uid: u32, gid: u32) -> bool {
    let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return false;
    };
    let Ok(Some(group)) = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid)) else {
        return false;
    };
    if group.name != user.name || user.gid != group.gid {
        return false;
    }
    group.mem.is_empty() || (group.mem.len() == 1 && group.mem[0] == user.name)
}

fn read_link(dir: &OwnedFd, name: &OsString, path: &Path) -> Result<PathBuf, PathError> {
    let target: CString = readlinkat(dir, name.as_os_str(), Vec::new())
        .map_err(|errno| io_error("read directory symlink", path, errno))?;
    Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
}

fn normalize(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if out.components().next_back().is_some_and(|component| {
                    !matches!(component, Component::RootDir | Component::ParentDir)
                }) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn io_error(operation: &'static str, path: &Path, errno: Errno) -> PathError {
    PathError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from(errno),
    }
}
