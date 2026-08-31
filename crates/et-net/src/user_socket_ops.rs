//! Privilege-dropped UNIX listen/connect, porting EternalTerminal #784
//! `UserSocketOps` (ANT-2026-AVTT7HQH / ANT-2026-A3WQS3AG).
//!
//! etserver is multithreaded and must not `seteuid` in-process. Upstream
//! forks, then `setgroups`/`setgid`/`setuid` to the session user, and
//! returns the fd via `SCM_RIGHTS`. et.rs cannot call `fork` (that API is
//! `unsafe`); it re-execs a helper, drops with [`nix`] in that
//! single-threaded process, and uses the same fd-passing protocol.

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

const OP_ENV: &str = "ET_RS_USER_SOCKET_OP";
const PATH_ENV: &str = "ET_RS_USER_SOCKET_PATH";
const UID_ENV: &str = "ET_RS_USER_SOCKET_UID";
const GID_ENV: &str = "ET_RS_USER_SOCKET_GID";
const HELPER_ENV: &str = "ET_RS_USER_SOCKET_HELPER";
const HELPER_NAME: &str = "et-user-socket-helper";
/// `sockaddr_un.sun_path` on Linux, including the trailing NUL.
const UNIX_PATH_MAX: usize = 108;

#[derive(Clone, Copy)]
enum Op {
    Listen,
    Connect,
    ListenTcp,
}

impl Op {
    fn as_env(self) -> &'static str {
        match self {
            Self::Listen => "listen",
            Self::Connect => "connect",
            Self::ListenTcp => "listen-tcp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "listen" => Some(Self::Listen),
            "connect" => Some(Self::Connect),
            "listen-tcp" => Some(Self::ListenTcp),
            _ => None,
        }
    }
}

/// Run the helper if this process was spawned by [`listen_unix_as_user`] or
/// [`connect_unix_as_user`]. Returns `Some(exit_code)` when handled.
pub fn maybe_run_helper() -> Option<i32> {
    std::env::var_os(OP_ENV)?;
    Some(run_helper())
}

/// Helper entry used by `et` and `et-user-socket-helper`.
pub fn run_helper() -> i32 {
    let stdin = io::stdin();
    let channel = stdin.as_fd();
    if let Err(error) = drop_helper_privileges() {
        return send_error(channel, &error);
    }
    let op = std::env::var(OP_ENV)
        .ok()
        .and_then(|value| Op::parse(&value));
    let argument = std::env::var(PATH_ENV).unwrap_or_default();
    match op {
        Some(Op::Listen) if !argument.is_empty() => match listen_at_path(Path::new(&argument)) {
            Ok(listener) => send_result(channel, Some(listener.as_fd()), 0, 0),
            Err(error) => send_error(channel, &error),
        },
        Some(Op::Connect) if !argument.is_empty() => match connect_at_path(Path::new(&argument)) {
            Ok(stream) => send_result(channel, Some(stream.as_fd()), 0, 0),
            Err(error) => send_error(channel, &error),
        },
        Some(Op::ListenTcp) => match argument.parse() {
            Ok(address) => match listen_tcp_at_address(address) {
                Ok(listener) => send_result(channel, Some(listener.as_fd()), 0, 0),
                Err(error) => send_error(channel, &error),
            },
            Err(_) => send_result(channel, None, -1, rustix::io::Errno::INVAL.raw_os_error()),
        },
        Some(Op::Listen | Op::Connect) | None => {
            send_result(channel, None, -1, rustix::io::Errno::INVAL.raw_os_error())
        }
    }
}

/// Bind/listen a new owner-only UNIX socket path with the current credentials.
pub fn listen_at_path(path: &Path) -> io::Result<UnixListener> {
    listen_at_path_with(path, || Ok(()))
}

fn listen_at_path_with(
    path: &Path,
    after_bind: impl FnOnce() -> io::Result<()>,
) -> io::Result<UnixListener> {
    if path_too_long(path) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::NAMETOOLONG.raw_os_error(),
        ));
    }
    let listener = UnixListener::bind(path)?;
    let mut cleanup = SocketPathCleanup(Some(path.to_path_buf()));
    after_bind()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    cleanup.0 = None;
    Ok(listener)
}

struct SocketPathCleanup(Option<PathBuf>);

impl Drop for SocketPathCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.as_ref() {
            let _ = fs::remove_file(path);
        }
    }
}

/// connect() to a UNIX socket path with the current credentials.
pub fn connect_at_path(path: &Path) -> io::Result<UnixStream> {
    if path_too_long(path) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::NAMETOOLONG.raw_os_error(),
        ));
    }
    UnixStream::connect(path)
}

/// Bind/listen as `uid`/`gid`, returning the listening socket.
pub fn listen_unix_as_user(path: impl AsRef<Path>, uid: u32, gid: u32) -> io::Result<UnixListener> {
    let path = path.as_ref();
    if already_session_user(uid, gid) {
        return listen_at_path(path);
    }
    Ok(UnixListener::from(run_as_user(
        Op::Listen,
        path.as_os_str(),
        uid,
        gid,
    )?))
}

/// connect() as `uid`/`gid`, returning the connected socket.
pub fn connect_unix_as_user(path: impl AsRef<Path>, uid: u32, gid: u32) -> io::Result<UnixStream> {
    let path = path.as_ref();
    if already_session_user(uid, gid) {
        return connect_at_path(path);
    }
    Ok(UnixStream::from(run_as_user(
        Op::Connect,
        path.as_os_str(),
        uid,
        gid,
    )?))
}

/// Bind one TCP address as `uid`/`gid`, returning the listening socket.
pub fn listen_tcp_as_user(address: SocketAddr, uid: u32, gid: u32) -> io::Result<TcpListener> {
    if already_session_user(uid, gid) {
        return listen_tcp_at_address(address);
    }
    let argument = address.to_string();
    Ok(TcpListener::from(run_as_user(
        Op::ListenTcp,
        OsStr::new(&argument),
        uid,
        gid,
    )?))
}

fn listen_tcp_at_address(address: SocketAddr) -> io::Result<TcpListener> {
    crate::forward_endpoint::bind_tcp_single_family(address)?
        .ok_or_else(|| io::Error::from_raw_os_error(rustix::io::Errno::AFNOSUPPORT.raw_os_error()))
}

fn already_session_user(uid: u32, gid: u32) -> bool {
    rustix::process::geteuid().as_raw() == uid && rustix::process::getegid().as_raw() == gid
}

fn run_as_user(op: Op, argument: &OsStr, uid: u32, gid: u32) -> io::Result<OwnedFd> {
    let helper = helper_exe()?;
    let (parent, child) = UnixStream::pair()?;
    let mut command = Command::new(helper);
    command
        .env(OP_ENV, op.as_env())
        .env(PATH_ENV, argument)
        .env(UID_ENV, uid.to_string())
        .env(GID_ENV, gid.to_string())
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child_proc = command.spawn()?;
    let result = recv_result(&parent);
    let _ = child_proc.wait();
    result
}

fn drop_helper_privileges() -> io::Result<()> {
    let uid = std::env::var(UID_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| rustix::process::getuid().as_raw());
    let gid = std::env::var(GID_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| rustix::process::getgid().as_raw());
    if !rustix::process::geteuid().is_root()
        && (rustix::process::geteuid().as_raw() != uid
            || rustix::process::getegid().as_raw() != gid)
    {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::PERM.raw_os_error(),
        ));
    }
    let uid_text = uid.to_string();
    let gid_text = gid.to_string();
    privdrop::PrivDrop::default()
        .user(&uid_text)
        .group(&gid_text)
        .group_list(&[&gid_text])
        .fallback_to_ids_if_names_are_numeric()
        .apply()
        .map_err(privdrop_io_error)?;
    let identity = HelperIdentity {
        euid: rustix::process::geteuid().as_raw(),
        egid: rustix::process::getegid().as_raw(),
        groups: rustix::process::getgroups()?
            .into_iter()
            .map(rustix::process::Gid::as_raw)
            .collect(),
    };
    if !helper_identity_matches((uid, gid), &[gid], &identity) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::PERM.raw_os_error(),
        ));
    }
    Ok(())
}

fn privdrop_io_error(error: privdrop::PrivDropError) -> io::Error {
    let errno = error
        .source()
        .and_then(|source| source.downcast_ref::<privdrop::reexports::nix::errno::Errno>())
        .copied();
    match errno {
        Some(errno) => io::Error::from_raw_os_error(errno as i32),
        None => io::Error::other(error),
    }
}

struct HelperIdentity {
    euid: u32,
    egid: u32,
    groups: Vec<u32>,
}

fn helper_identity_matches(
    target: (u32, u32),
    expected_groups: &[u32],
    identity: &HelperIdentity,
) -> bool {
    let mut expected = expected_groups.to_vec();
    expected.sort_unstable();
    let mut observed = identity.groups.clone();
    observed.sort_unstable();
    identity.euid == target.0 && identity.egid == target.1 && observed == expected
}

fn helper_exe() -> io::Result<PathBuf> {
    for candidate in helper_candidates() {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "et-user-socket-helper not found",
    ))
}

fn helper_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os(HELPER_ENV) {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_et_user_socket_helper") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            candidates.push(dir.join(HELPER_NAME));
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join(HELPER_NAME));
            }
        }
        if !looks_like_rustc_test_exe(&current) {
            candidates.push(current);
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let crate_dir = PathBuf::from(manifest);
        for profile in ["debug", "release"] {
            candidates.push(crate_dir.join(format!("../../target/{profile}/{HELPER_NAME}")));
            candidates.push(crate_dir.join(format!("target/{profile}/{HELPER_NAME}")));
        }
    }
    candidates
}

fn looks_like_rustc_test_exe(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "deps")
}

fn path_too_long(path: &Path) -> bool {
    path.as_os_str().len() >= UNIX_PATH_MAX
}

fn send_error(channel: BorrowedFd<'_>, error: &io::Error) -> i32 {
    send_result(
        channel,
        None,
        -1,
        error
            .raw_os_error()
            .unwrap_or_else(|| rustix::io::Errno::IO.raw_os_error()),
    )
}

fn send_result(channel: BorrowedFd<'_>, fd: Option<BorrowedFd<'_>>, status: i32, err: i32) -> i32 {
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&status.to_ne_bytes());
    header[4..].copy_from_slice(&err.to_ne_bytes());
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let rights;
    if status == 0 {
        if let Some(fd) = fd {
            rights = [fd];
            let _ = control.push(SendAncillaryMessage::ScmRights(&rights));
        }
    }
    match sendmsg(
        channel,
        &[IoSlice::new(&header)],
        &mut control,
        SendFlags::empty(),
    ) {
        Ok(_) => i32::from(status != 0),
        Err(_) => 1,
    }
}

fn recv_result(channel: &UnixStream) -> io::Result<OwnedFd> {
    let mut header = [0u8; 8];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        channel,
        &mut [IoSliceMut::new(&mut header)],
        &mut control,
        RecvFlags::empty(),
    )?;
    if received.bytes != header.len() {
        return Err(io::Error::other(
            "user-socket helper returned a short reply",
        ));
    }
    let status = i32::from_ne_bytes(header[..4].try_into().expect("header status"));
    let err = i32::from_ne_bytes(header[4..].try_into().expect("header errno"));
    if status != 0 {
        return Err(if err != 0 {
            io::Error::from_raw_os_error(err)
        } else {
            io::Error::other("user-socket helper failed")
        });
    }
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(mut rights) = message {
            if let Some(fd) = rights.next() {
                return Ok(fd);
            }
        }
    }
    Err(io::Error::other("user-socket helper omitted the socket fd"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("et_user_sock_{stamp}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn long_unix_path() -> PathBuf {
        PathBuf::from("x".repeat(UNIX_PATH_MAX + 8))
    }

    #[test]
    fn privilege_drop_errno_preserves_io_error_kind() {
        // Given
        let denied = privdrop::PrivDropError::from(privdrop::reexports::nix::errno::Errno::EPERM);

        // When
        let error = privdrop_io_error(denied);

        // Then
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn helper_identity_rejects_inherited_privileged_supplementary_group() {
        // Given
        let target = (65_534, 65_534);
        let inherited = HelperIdentity {
            euid: 65_534,
            egid: 65_534,
            groups: vec![0, 65_534],
        };
        let dropped = HelperIdentity {
            euid: 65_534,
            egid: 65_534,
            groups: vec![65_534],
        };

        // When / Then
        assert!(!helper_identity_matches(target, &[65_534], &inherited));
        assert!(helper_identity_matches(target, &[65_534], &dropped));
    }

    #[test]
    fn listen_failure_after_bind_cleans_socket_and_immediate_retry_succeeds() {
        // Given
        let dir = temp_dir();
        let path = dir.join("post-bind-failure.sock");

        // When
        let error = listen_at_path_with(&path, || Err(io::Error::other("injected before chmod")))
            .unwrap_err();

        // Then
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!path.exists());
        let listener = listen_at_path(&path).unwrap();
        assert!(path.exists());
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn listen_and_connect_at_path_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("sock");
        let listener = listen_at_path(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let mut client = connect_at_path(&path).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        client.write_all(b"ok").unwrap();
        let mut buf = [0u8; 2];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
        drop(listener);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn listen_and_connect_as_current_user() {
        let dir = temp_dir();
        let path = dir.join("sock");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let listener = listen_unix_as_user(&path, uid, gid).unwrap();
        let mut client = connect_unix_as_user(&path, uid, gid).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        drop(listener);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn listen_at_path_rejects_oversized_path() {
        let error = listen_at_path(&long_unix_path()).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        );
    }

    #[test]
    fn connect_at_path_rejects_oversized_path() {
        let error = connect_at_path(&long_unix_path()).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        );
    }

    #[test]
    fn listen_unix_as_user_rejects_oversized_path() {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let error = listen_unix_as_user(long_unix_path(), uid, gid).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        );
    }

    #[test]
    fn connect_unix_as_user_rejects_oversized_path() {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let error = connect_unix_as_user(long_unix_path(), uid, gid).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        );
    }

    #[test]
    fn listen_at_path_fails_when_path_is_a_directory() {
        let dir = temp_dir();
        assert!(listen_at_path(&dir).is_err());
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn connect_at_path_fails_when_nothing_listens() {
        let dir = temp_dir();
        let path = dir.join("missing");
        assert!(connect_at_path(&path).is_err());
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn listen_at_path_refuses_to_unlink_an_existing_socket() {
        // Given
        let dir = temp_dir();
        let path = dir.join("sock");
        let first = listen_at_path(&path).unwrap();

        // When
        let error = listen_at_path(&path).unwrap_err();

        // Then
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(fs::metadata(&path).unwrap().file_type().is_socket());
        drop(first);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    fn unprivileged_drop_user() -> Option<(u32, u32)> {
        if rustix::process::getuid().as_raw() != 0 {
            return None;
        }
        for name in ["nobody", "nfsnobody"] {
            if let Some(ids) = passwd_ids(name) {
                if ids.0 != 0 && ids.0 <= 65534 {
                    return Some(ids);
                }
            }
        }
        None
    }

    fn passwd_ids(name: &str) -> Option<(u32, u32)> {
        let text = fs::read_to_string("/etc/passwd").ok()?;
        for line in text.lines() {
            let mut fields = line.split(':');
            if fields.next()? != name {
                continue;
            }
            let _ = fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            let gid = fields.next()?.parse().ok()?;
            return Some((uid, gid));
        }
        None
    }

    /// ANT-2026-AVTT7HQH: privilege-dropped listen cannot unlink a root-owned
    /// file. Skips when not root (no setuid drop), like ET's nobody-user tests.
    #[test]
    fn listen_as_user_does_not_destroy_root_only_file() {
        let Some((uid, gid)) = unprivileged_drop_user() else {
            eprintln!("skipping privilege-drop listen test: not root or no nobody user");
            return;
        };
        let dir = temp_dir();
        let victim = dir.join("victim_file");
        fs::write(&victim, b"keepme").unwrap();
        rustix::fs::chown(
            &dir,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .unwrap();
        rustix::fs::chmod(&dir, rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
        rustix::fs::chown(
            &victim,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .unwrap();
        assert!(listen_unix_as_user(&victim, uid, gid).is_err());
        assert!(victim.is_file());
        let _ = fs::remove_file(&victim);
        let _ = fs::remove_dir(&dir);
    }

    /// ANT-2026-A3WQS3AG: privilege-dropped connect cannot open a mode-000
    /// socket. Skips when not root.
    #[test]
    fn connect_as_user_cannot_open_mode_000_socket() {
        let Some((uid, gid)) = unprivileged_drop_user() else {
            eprintln!("skipping privilege-drop connect test: not root or no nobody user");
            return;
        };
        let dir = temp_dir();
        rustix::fs::chmod(&dir, rustix::fs::Mode::from_raw_mode(0o777)).unwrap();
        let path = dir.join("denied.sock");
        let listener = listen_at_path(&path).unwrap();
        rustix::fs::chmod(&path, rustix::fs::Mode::from_raw_mode(0)).unwrap();
        assert!(connect_unix_as_user(&path, uid, gid).is_err());
        drop(listener);
        let _ = rustix::fs::chmod(&path, rustix::fs::Mode::from_raw_mode(0o700));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
