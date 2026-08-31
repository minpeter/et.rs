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
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use wait_timeout::ChildExt;

const OP_ENV: &str = "ET_RS_USER_SOCKET_OP";
const PATH_ENV: &str = "ET_RS_USER_SOCKET_PATH";
const PORT_ENV: &str = "ET_RS_USER_SOCKET_PORT";
const UID_ENV: &str = "ET_RS_USER_SOCKET_UID";
const GID_ENV: &str = "ET_RS_USER_SOCKET_GID";
const HELPER_ENV: &str = "ET_RS_USER_SOCKET_HELPER";
const HELPER_NAME: &str = "et-user-socket-helper";
/// `sockaddr_un.sun_path` on Linux, including the trailing NUL.
const UNIX_PATH_MAX: usize = 108;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const ATOMIC_SCM_RIGHTS_CLOEXEC: bool = cfg!(any(target_os = "linux", target_os = "android"));
static HELPER_SPAWN_LOCK: HelperSpawnLock = HelperSpawnLock {
    held: Mutex::new(false),
    available: Condvar::new(),
};

#[derive(Clone, Copy)]
enum Op {
    Listen,
    Connect,
    ConnectTcp,
    ListenTcp,
}

impl Op {
    fn as_env(self) -> &'static str {
        match self {
            Self::Listen => "listen",
            Self::Connect => "connect",
            Self::ConnectTcp => "connect-tcp",
            Self::ListenTcp => "listen-tcp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "listen" => Some(Self::Listen),
            "connect" => Some(Self::Connect),
            "connect-tcp" => Some(Self::ConnectTcp),
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
        Some(Op::Listen) if !argument.is_empty() => {
            match PendingUnixListener::bind_anchored(Path::new(&argument)) {
                Ok(listener) => listener.send_and_serve(channel),
                Err(error) => send_error(channel, &error),
            }
        }
        Some(Op::Connect) if !argument.is_empty() => match connect_at_path(Path::new(&argument)) {
            Ok(stream) => send_result(channel, Some(stream.as_fd()), 0, 0),
            Err(error) => send_error(channel, &error),
        },
        Some(Op::ConnectTcp) if !argument.is_empty() => match env_u16(PORT_ENV) {
            Ok(port) => match crate::forward_endpoint::connect_tcp(&argument, port) {
                Ok(stream) => send_result(channel, Some(stream.as_fd()), 0, 0),
                Err(error) => send_error(channel, &error),
            },
            Err(error) => send_error(channel, &error),
        },
        Some(Op::ListenTcp) => match argument.parse() {
            Ok(address) => match listen_tcp_at_address(address) {
                Ok(listener) => send_result(channel, Some(listener.as_fd()), 0, 0),
                Err(error) => send_error(channel, &error),
            },
            Err(_) => send_result(channel, None, -1, rustix::io::Errno::INVAL.raw_os_error()),
        },
        Some(Op::Listen | Op::Connect | Op::ConnectTcp) | None => {
            send_result(channel, None, -1, rustix::io::Errno::INVAL.raw_os_error())
        }
    }
}

/// Bind/listen a new owner-only UNIX socket path with the current credentials.
pub fn listen_at_path(path: &Path) -> io::Result<UnixListener> {
    PendingUnixListener::bind(path).map(PendingUnixListener::into_listener)
}

struct PendingUnixListener {
    listener: Option<UnixListener>,
    cleanup: PendingSocketPath,
}

impl PendingUnixListener {
    fn bind(path: &Path) -> io::Result<Self> {
        if path_too_long(path) {
            return Err(io::Error::from_raw_os_error(
                rustix::io::Errno::NAMETOOLONG.raw_os_error(),
            ));
        }
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let cleanup = PendingSocketPath {
            path: Some(path.to_path_buf()),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener: Some(listener),
            cleanup,
        })
    }

    fn into_listener(mut self) -> UnixListener {
        self.cleanup.path.take();
        self.listener.take().expect("bound Unix listener")
    }

    fn send_and_serve(mut self, channel: BorrowedFd<'_>) -> i32 {
        let status = send_result(
            channel,
            Some(self.listener.as_ref().expect("bound Unix listener").as_fd()),
            0,
            0,
        );
        if status != 0 {
            return status;
        }
        drop(self.listener.take());
        let mut buffer = [0_u8; 1];
        loop {
            match rustix::io::read(channel, &mut buffer) {
                Ok(0) => return 0,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return 1,
            }
        }
    }

    fn bind_anchored(path: &Path) -> io::Result<Self> {
        if path_too_long(path) {
            return Err(io::Error::from_raw_os_error(
                rustix::io::Errno::NAMETOOLONG.raw_os_error(),
            ));
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            std::env::set_current_dir(parent)?;
        }
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix socket path has no file name",
            )
        })?;
        Self::bind(Path::new(name))
    }
}

struct PendingSocketPath {
    path: Option<PathBuf>,
    device: u64,
    inode: u64,
}

impl Drop for PendingSocketPath {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        if fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
        {
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
pub fn listen_unix_as_user(
    path: impl AsRef<Path>,
    uid: u32,
    gid: u32,
) -> io::Result<UserUnixListener> {
    listen_unix_as_user_until(path, uid, gid, Instant::now() + HELPER_TIMEOUT)
}

pub(crate) fn listen_unix_as_user_until(
    path: impl AsRef<Path>,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<UserUnixListener> {
    let path = path.as_ref();
    run_listener_as_user(path, uid, gid, deadline)
}

pub struct UserUnixListener {
    listener: UnixListener,
    cleanup: Option<UserSocketCleanup>,
}

impl std::fmt::Debug for UserUnixListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserUnixListener")
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for UserUnixListener {
    type Target = UnixListener;

    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

impl UserUnixListener {
    pub(crate) fn into_parts(self) -> (UnixListener, Option<UserSocketCleanup>) {
        (self.listener, self.cleanup)
    }
}

pub(crate) struct UserSocketCleanup {
    channel: Option<UnixStream>,
    child: Option<std::process::Child>,
}

impl Drop for UserSocketCleanup {
    fn drop(&mut self) {
        drop(self.channel.take());
        if let Some(mut child) = self.child.take() {
            match child.wait_timeout(HELPER_TIMEOUT) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
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
    listen_tcp_as_user_until(address, uid, gid, Instant::now() + HELPER_TIMEOUT)
}

pub(crate) fn connect_tcp_as_user(
    host: &str,
    port: u16,
    uid: u32,
    gid: u32,
) -> io::Result<std::net::TcpStream> {
    if already_session_user(uid, gid) {
        return crate::forward_endpoint::connect_tcp(host, port);
    }
    Ok(std::net::TcpStream::from(run_as_user_until_with_port(
        Op::ConnectTcp,
        OsStr::new(host),
        uid,
        gid,
        Instant::now() + HELPER_TIMEOUT,
        Some(port),
    )?))
}

pub fn listen_tcp_as_user_deadline(
    address: SocketAddr,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<TcpListener> {
    listen_tcp_as_user_until(address, uid, gid, deadline)
}

#[doc(hidden)]
pub fn listen_tcp_as_user_deadline_with_helper(
    address: SocketAddr,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
) -> io::Result<TcpListener> {
    let argument = address.to_string();
    let mut spawned = spawn_helper_with_executable(
        Op::ListenTcp,
        OsStr::new(&argument),
        uid,
        gid,
        None,
        deadline,
        helper,
    )?;
    let result = recv_result_until(spawned.channel(), deadline);
    spawned.release_spawn_guard();
    finish_helper(&mut spawned, result, deadline).map(TcpListener::from)
}

pub(crate) fn listen_tcp_as_user_until(
    address: SocketAddr,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<TcpListener> {
    if already_session_user(uid, gid) {
        return listen_tcp_at_address(address);
    }
    let argument = address.to_string();
    Ok(TcpListener::from(run_as_user_until(
        Op::ListenTcp,
        OsStr::new(&argument),
        uid,
        gid,
        deadline,
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
    run_as_user_until(op, argument, uid, gid, Instant::now() + HELPER_TIMEOUT)
}

fn run_as_user_until(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<OwnedFd> {
    run_as_user_until_with_port(op, argument, uid, gid, deadline, None)
}

fn run_as_user_until_with_port(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    deadline: Instant,
    port: Option<u16>,
) -> io::Result<OwnedFd> {
    let mut helper = spawn_helper(op, argument, uid, gid, port, deadline)?;
    let result = recv_result_until(helper.channel(), deadline);
    helper.release_spawn_guard();
    finish_helper(&mut helper, result, deadline)
}

fn run_listener_as_user(
    path: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<UserUnixListener> {
    let mut helper = spawn_helper(Op::Listen, path.as_os_str(), uid, gid, None, deadline)?;
    let result = recv_result_until(helper.channel(), deadline);
    helper.release_spawn_guard();
    match reject_success_after_deadline(result, deadline) {
        Ok(fd) => {
            let (channel, child) = helper.take_persistent();
            Ok(UserUnixListener {
                listener: UnixListener::from(fd),
                cleanup: Some(UserSocketCleanup {
                    channel: Some(channel),
                    child: Some(child),
                }),
            })
        }
        Err(error) => Err(error),
    }
}

trait KillAndWait {
    fn kill_and_wait(&mut self);
}

impl KillAndWait for std::process::Child {
    fn kill_and_wait(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

struct ChildLease<C: KillAndWait> {
    child: Option<C>,
}

impl<C: KillAndWait> ChildLease<C> {
    fn new(child: C) -> Self {
        Self { child: Some(child) }
    }

    fn as_mut(&mut self) -> &mut C {
        self.child.as_mut().expect("live helper child")
    }

    fn take(&mut self) -> Option<C> {
        self.child.take()
    }

    fn reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill_and_wait();
        }
    }
}

impl<C: KillAndWait> Drop for ChildLease<C> {
    fn drop(&mut self) {
        self.reap();
    }
}

struct SpawnedHelper {
    channel: Option<UnixStream>,
    child: ChildLease<std::process::Child>,
    spawn_guard: Option<HelperSpawnGuard>,
}

impl SpawnedHelper {
    fn channel(&self) -> &UnixStream {
        self.channel.as_ref().expect("live helper channel")
    }

    fn release_spawn_guard(&mut self) {
        drop(self.spawn_guard.take());
    }

    fn take_persistent(&mut self) -> (UnixStream, std::process::Child) {
        (
            self.channel.take().expect("live helper channel"),
            self.child.take().expect("live helper child"),
        )
    }
}

fn spawn_helper(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    port: Option<u16>,
    deadline: Instant,
) -> io::Result<SpawnedHelper> {
    let helper = helper_exe()?;
    spawn_helper_with_executable(op, argument, uid, gid, port, deadline, &helper)
}

fn spawn_helper_with_executable(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    port: Option<u16>,
    deadline: Instant,
    helper: &Path,
) -> io::Result<SpawnedHelper> {
    let (parent, child) = UnixStream::pair()?;
    let mut command = Command::new(helper);
    command
        .env(OP_ENV, op.as_env())
        .env(PATH_ENV, argument)
        .env(UID_ENV, uid.to_string())
        .env(GID_ENV, gid.to_string());
    if let Some(port) = port {
        command.env(PORT_ENV, port.to_string());
    }
    command
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let spawn_guard = helper_spawn_guard(ATOMIC_SCM_RIGHTS_CLOEXEC, deadline)?;
    let child = command.spawn()?;
    Ok(SpawnedHelper {
        channel: Some(parent),
        child: ChildLease::new(child),
        spawn_guard,
    })
}

struct HelperSpawnLock {
    held: Mutex<bool>,
    available: Condvar,
}

impl HelperSpawnLock {
    fn acquire(&'static self, deadline: Instant) -> io::Result<HelperSpawnGuard> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let remaining = remaining_until(deadline)?;
            if !*held {
                *held = true;
                return Ok(HelperSpawnGuard(self));
            }
            let (next, _) = self
                .available
                .wait_timeout(held, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            held = next;
        }
    }
}

struct HelperSpawnGuard(&'static HelperSpawnLock);

impl Drop for HelperSpawnGuard {
    fn drop(&mut self) {
        let mut held = self
            .0
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *held = false;
        self.0.available.notify_one();
    }
}

fn helper_spawn_guard(
    atomic_cloexec: bool,
    deadline: Instant,
) -> io::Result<Option<HelperSpawnGuard>> {
    remaining_until(deadline)?;
    if atomic_cloexec {
        Ok(None)
    } else {
        HELPER_SPAWN_LOCK.acquire(deadline).map(Some)
    }
}

fn finish_helper(
    helper: &mut SpawnedHelper,
    result: io::Result<OwnedFd>,
    deadline: Instant,
) -> io::Result<OwnedFd> {
    let fd = match result {
        Ok(fd) => fd,
        Err(error) => {
            helper.child.reap();
            return Err(error);
        }
    };
    let remaining = remaining_until(deadline)?;
    match helper.child.as_mut().wait_timeout(remaining) {
        Ok(Some(_)) => {
            helper.child.take();
            Ok(fd)
        }
        Ok(None) | Err(_) => {
            helper.child.reap();
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "socket helper timed out",
            ))
        }
    }
}

fn remaining_until_at(deadline: Instant, now: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

fn remaining_until(deadline: Instant) -> io::Result<Duration> {
    remaining_until_at(deadline, Instant::now())
}

fn reject_success_after_deadline<T>(result: io::Result<T>, deadline: Instant) -> io::Result<T> {
    if result.is_ok() {
        remaining_until(deadline)?;
    }
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
    if !rustix::process::geteuid().is_root() {
        if rustix::process::geteuid().as_raw() == uid && rustix::process::getegid().as_raw() == gid
        {
            // An unprivileged process cannot change its supplementary groups.
            // It also cannot have inherited groups from a more privileged
            // daemon identity, so retaining its own groups adds no authority.
            return Ok(());
        }
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

fn env_u16(name: &str) -> io::Result<u16> {
    std::env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {name}")))
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
            if !control.push(SendAncillaryMessage::ScmRights(&rights)) {
                return 1;
            }
        }
    }
    match sendmsg(
        channel,
        &[IoSlice::new(&header)],
        &mut control,
        SendFlags::empty(),
    ) {
        Ok(sent) if sent == header.len() => i32::from(status != 0),
        Ok(_) => 1,
        Err(_) => 1,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_cloexec_flags() -> RecvFlags {
    RecvFlags::CMSG_CLOEXEC
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn recv_cloexec_flags() -> RecvFlags {
    RecvFlags::empty()
}

fn ensure_cloexec(fd: &OwnedFd) -> io::Result<()> {
    let flags = rustix::io::fcntl_getfd(fd)?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok(())
}

fn retry_on_intr_until<T>(
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut before_attempt: impl FnMut(Duration) -> io::Result<()>,
    mut operation: impl FnMut() -> Result<T, rustix::io::Errno>,
) -> io::Result<T> {
    loop {
        let remaining = remaining_until_at(deadline, now())?;
        before_attempt(remaining)?;
        match operation() {
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) if now() >= deadline => {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            Err(error) => return Err(error.into()),
            Ok(value) => return Ok(value),
        }
    }
}

fn recv_result_until(channel: &UnixStream, deadline: Instant) -> io::Result<OwnedFd> {
    let mut header = [0u8; 8];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = retry_on_intr_until(
        deadline,
        Instant::now,
        |remaining| channel.set_read_timeout(Some(remaining)),
        || {
            recvmsg(
                channel,
                &mut [IoSliceMut::new(&mut header)],
                &mut control,
                recv_cloexec_flags(),
            )
        },
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
                ensure_cloexec(&fd)?;
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
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileTypeExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = PathBuf::from(format!("/tmp/e{:x}{sequence:x}", std::process::id()));
            match fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
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
    fn interrupted_descriptor_receive_does_not_extend_deadline() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        let mut times = [start, deadline].into_iter();
        let attempts = std::cell::Cell::new(0);
        let configured = std::cell::RefCell::new(Vec::new());
        let result = retry_on_intr_until(
            deadline,
            || times.next().expect("one clock read per attempt"),
            |remaining| {
                configured.borrow_mut().push(remaining);
                Ok(())
            },
            || {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(rustix::io::Errno::INTR)
            },
        );

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(attempts.get(), 1);
        assert_eq!(&*configured.borrow(), &[Duration::from_secs(1)]);
    }

    #[test]
    fn fallback_helper_spawn_lock_obeys_deadline() {
        let first =
            helper_spawn_guard(false, Instant::now().checked_add(HELPER_TIMEOUT).unwrap()).unwrap();
        assert!(first.is_some());

        let error = match helper_spawn_guard(false, Instant::now()) {
            Ok(_) => panic!("contended fallback lock succeeded after deadline"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(helper_spawn_guard(true, Instant::now()).is_err());

        drop(first);
    }

    #[test]
    fn late_listener_result_is_rejected() {
        let error = reject_success_after_deadline(Ok("listener"), Instant::now()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn child_lease_reaps_on_error_and_transfers_on_success() {
        struct MockChild(std::rc::Rc<std::cell::Cell<usize>>);
        impl KillAndWait for MockChild {
            fn kill_and_wait(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let reaped = std::rc::Rc::new(std::cell::Cell::new(0));
        drop(ChildLease::new(MockChild(reaped.clone())));
        assert_eq!(reaped.get(), 1);

        let mut lease = ChildLease::new(MockChild(reaped.clone()));
        let child = lease.take().unwrap();
        drop(lease);
        assert_eq!(reaped.get(), 1);
        drop(child);
        assert_eq!(reaped.get(), 1);
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

    #[test]
    fn failed_listener_descriptor_transfer_removes_socket_path() {
        let dir = temp_dir();
        let path = dir.join("sock");
        let listener = PendingUnixListener::bind(&path).unwrap();
        let (channel, peer) = UnixStream::pair().unwrap();
        drop(peer);

        assert_eq!(listener.send_and_serve(channel.as_fd()), 1);
        assert!(!path.exists());

        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn listener_cleanup_is_anchored_to_the_bound_parent() {
        if helper_exe().is_err() {
            eprintln!("skipping helper-dependent test: et-user-socket-helper is unavailable");
            return;
        }
        let base = temp_dir();
        let live = base.join("live");
        let parked = base.join("parked");
        let target = base.join("target");
        fs::create_dir(&live).unwrap();
        fs::create_dir(&target).unwrap();
        let socket = live.join("victim");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let listener =
            run_listener_as_user(&socket, uid, gid, Instant::now() + HELPER_TIMEOUT).unwrap();

        fs::rename(&live, &parked).unwrap();
        let sentinel = target.join("victim");
        fs::write(&sentinel, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &live).unwrap();
        drop(listener);

        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
        assert!(!parked.join("victim").exists());
        fs::remove_file(&live).unwrap();
        fs::remove_file(&sentinel).unwrap();
        fs::remove_dir(&target).unwrap();
        fs::remove_dir(&parked).unwrap();
        fs::remove_dir(&base).unwrap();
    }

    #[test]
    fn older_helper_cleanup_preserves_replacement_generation() {
        if helper_exe().is_err() {
            eprintln!("skipping helper-dependent test: et-user-socket-helper is unavailable");
            return;
        }
        let dir = temp_dir();
        let path = dir.join("generation.sock");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let old = run_listener_as_user(&path, uid, gid, Instant::now() + HELPER_TIMEOUT).unwrap();

        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(old);

        let client = UnixStream::connect(&path)
            .expect("older helper cleanup unlinked the replacement generation");
        replacement.accept().unwrap();
        drop(client);
        drop(replacement);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_received_from_helper_is_not_inherited_by_next_helper() {
        let dir = temp_dir();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let first = run_listener_as_user(
            &dir.join("first"),
            uid,
            gid,
            Instant::now() + HELPER_TIMEOUT,
        )
        .unwrap();
        let received_socket =
            fs::read_link(format!("/proc/self/fd/{}", first.listener.as_raw_fd(),)).unwrap();

        let second = run_listener_as_user(
            &dir.join("second"),
            uid,
            gid,
            Instant::now() + HELPER_TIMEOUT,
        )
        .unwrap();
        let second_helper = second
            .cleanup
            .as_ref()
            .and_then(|cleanup| cleanup.child.as_ref())
            .expect("persistent listener helper");
        let inherited = fs::read_dir(format!("/proc/{}/fd", second_helper.id()))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .any(|target| target == received_socket);

        assert!(
            !inherited,
            "subsequent helper inherited received fd {received_socket:?}"
        );
        drop(second);
        drop(first);
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn tcp_destination_connect_runs_through_the_session_helper() {
        if helper_exe().is_err() {
            eprintln!("skipping helper-dependent test: et-user-socket-helper is unavailable");
            return;
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let fd = run_as_user_until_with_port(
            Op::ConnectTcp,
            OsStr::new("127.0.0.1"),
            uid,
            gid,
            Instant::now() + HELPER_TIMEOUT,
            Some(port),
        )
        .unwrap();
        let mut client = std::net::TcpStream::from(fd);
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"session-user").unwrap();
        let mut payload = [0_u8; 12];
        server.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"session-user");
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

    #[test]
    fn helper_command_clears_privileged_supplementary_groups() {
        let Some((uid, gid)) = unprivileged_drop_user() else {
            eprintln!("skipping helper group-drop test: not root or no nobody user");
            return;
        };
        let identity = HelperIdentity {
            euid: uid,
            egid: gid,
            groups: vec![gid],
        };
        assert!(helper_identity_matches((uid, gid), &[gid], &identity));
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
