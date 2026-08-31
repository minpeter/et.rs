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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

const OP_ENV: &str = "ET_RS_USER_SOCKET_OP";
const PATH_ENV: &str = "ET_RS_USER_SOCKET_PATH";
const PUBLIC_PATH_ENV: &str = "ET_RS_USER_SOCKET_PUBLIC_PATH";
const UID_ENV: &str = "ET_RS_USER_SOCKET_UID";
const GID_ENV: &str = "ET_RS_USER_SOCKET_GID";
const HELPER_ENV: &str = "ET_RS_USER_SOCKET_HELPER";
const GENERATION_ENV: &str = "ET_RS_USER_SOCKET_GENERATION";
const GENERATION_PATH_ENV: &str = "ET_RS_USER_SOCKET_GENERATION_PATH";
const HELPER_NAME: &str = "et-user-socket-helper";
/// `sockaddr_un.sun_path` on Linux, including the trailing NUL.
const UNIX_PATH_MAX: usize = 108;
static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnixSocketIdentity {
    fd_device: u64,
    fd_inode: u64,
    node_device: u64,
    node_inode: u64,
}

impl UnixSocketIdentity {
    fn from_fd_and_node(fd: BorrowedFd<'_>, node: &Path) -> io::Result<Self> {
        let stat = rustix::fs::fstat(fd)?;
        let metadata = fs::symlink_metadata(node)?;
        Ok(Self {
            fd_device: stat.st_dev as u64,
            fd_inode: stat.st_ino as u64,
            node_device: metadata.dev(),
            node_inode: metadata.ino(),
        })
    }

    fn node_matches(self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.dev() == self.node_device && metadata.ino() == self.node_inode
        })
    }
}

fn path_operations() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

pub(crate) fn remove_socket_if_owned(path: &Path, identity: UnixSocketIdentity) {
    remove_socket_if_owned_with_hook(path, identity, || {});
}

fn remove_socket_if_owned_with_hook(
    path: &Path,
    identity: UnixSocketIdentity,
    after_retire: impl FnOnce(),
) {
    let Ok(_guard) = path_operations().lock() else {
        return;
    };
    let retired = staging_path(
        path,
        &format!(
            "retired-{}",
            NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
    );
    if fs::rename(path, &retired).is_err() {
        return;
    }
    after_retire();
    if identity.node_matches(&retired) {
        let _ = fs::remove_file(retired);
        return;
    }
    // We retired a replacement rather than our generation. Restore it only
    // if no newer publisher has already occupied the public path.
    let _ = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &retired,
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    );
}

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
    let path = std::env::var(PATH_ENV).unwrap_or_default();
    match (op, path.is_empty()) {
        (Some(Op::Listen), false) => match listen_at_path(Path::new(&path)) {
            Ok(listener) => match publish_helper_generation(&listener, Path::new(&path)) {
                Ok(()) => send_result(channel, Some(listener.as_fd()), 0, 0),
                Err(error) => {
                    drop(listener);
                    let _ = fs::remove_file(&path);
                    send_error(channel, &error)
                }
            },
            Err(error) => send_error(channel, &error),
        },
        (Some(Op::Connect), false) => match connect_at_path(Path::new(&path)) {
            Ok(stream) => send_result(channel, Some(stream.as_fd()), 0, 0),
            Err(error) => send_error(channel, &error),
        },
        (Some(Op::ListenTcp), _) => match path.parse() {
            Ok(address) => match listen_tcp_at_address(address) {
                Ok(listener) => send_result(channel, Some(listener.as_fd()), 0, 0),
                Err(error) => send_error(channel, &error),
            },
            Err(_) => send_result(channel, None, -1, rustix::io::Errno::INVAL.raw_os_error()),
        },
        (Some(Op::Listen | Op::Connect), true) | (None, _) => {
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
    listen_unix_as_user_deadline(path, uid, gid, Instant::now() + Duration::from_secs(30))
}

pub fn listen_unix_as_user_deadline(
    path: impl AsRef<Path>,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<UnixListener> {
    let path = path.as_ref();
    if path_too_long(path) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::NAMETOOLONG.raw_os_error(),
        ));
    }
    ensure_deadline(deadline)?;
    Ok(listen_unix_as_user_owned_deadline(path, uid, gid, deadline)?.0)
}

/// connect() as `uid`/`gid`, returning the connected socket.
pub fn connect_unix_as_user(path: impl AsRef<Path>, uid: u32, gid: u32) -> io::Result<UnixStream> {
    let path = path.as_ref();
    if already_session_user(uid, gid) {
        return connect_at_path(path);
    }
    if path_too_long(path) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::NAMETOOLONG.raw_os_error(),
        ));
    }
    Ok(UnixStream::from(
        run_as_user(Op::Connect, path.as_os_str(), uid, gid)?.fd,
    ))
}

/// Bind one TCP address as `uid`/`gid`, returning the listening socket.
pub fn listen_tcp_as_user(address: SocketAddr, uid: u32, gid: u32) -> io::Result<TcpListener> {
    listen_tcp_as_user_deadline(address, uid, gid, Instant::now() + Duration::from_secs(30))
}

/// Bind one TCP address as `uid`/`gid` within the caller's absolute deadline.
pub fn listen_tcp_as_user_deadline(
    address: SocketAddr,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<TcpListener> {
    ensure_deadline(deadline)?;
    if already_session_user(uid, gid) {
        let listener = listen_tcp_at_address(address)?;
        ensure_deadline(deadline)?;
        return Ok(listener);
    }
    let argument = address.to_string();
    let helper = helper_exe()?;
    let received = run_as_user_deadline_argument_with_helper(
        Op::ListenTcp,
        OsStr::new(&argument),
        uid,
        gid,
        deadline,
        &helper,
    )?;
    ensure_deadline(deadline)?;
    Ok(TcpListener::from(received.fd))
}

#[doc(hidden)]
pub fn listen_tcp_as_user_deadline_with_helper(
    address: SocketAddr,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
) -> io::Result<TcpListener> {
    ensure_deadline(deadline)?;
    let argument = address.to_string();
    let received = run_as_user_deadline_argument_with_helper(
        Op::ListenTcp,
        OsStr::new(&argument),
        uid,
        gid,
        deadline,
        helper,
    )?;
    ensure_deadline(deadline)?;
    Ok(TcpListener::from(received.fd))
}

fn listen_tcp_at_address(address: SocketAddr) -> io::Result<TcpListener> {
    crate::forward_endpoint::bind_tcp_single_family(address)?
        .ok_or_else(|| io::Error::from_raw_os_error(rustix::io::Errno::AFNOSUPPORT.raw_os_error()))
}

pub(crate) fn listen_unix_as_user_owned_deadline(
    path: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<(UnixListener, UnixSocketIdentity)> {
    ensure_deadline(deadline)?;
    if already_session_user(uid, gid) {
        return bind_staged(path, deadline);
    }
    let received = run_as_user_deadline(Op::Listen, path, uid, gid, deadline)?;
    let listener = UnixListener::from(received.fd);
    let fd_stat = rustix::fs::fstat(&listener)?;
    if fd_stat.st_dev as u64 != received.identity.fd_device
        || fd_stat.st_ino as u64 != received.identity.fd_inode
    {
        return Err(io::Error::other("received listener identity changed"));
    }
    Ok((listener, received.identity))
}

fn already_session_user(uid: u32, gid: u32) -> bool {
    rustix::process::geteuid().as_raw() == uid && rustix::process::getegid().as_raw() == gid
}

#[derive(Debug)]
struct ReceivedSocket {
    fd: OwnedFd,
    identity: UnixSocketIdentity,
}

fn run_as_user(op: Op, argument: &OsStr, uid: u32, gid: u32) -> io::Result<ReceivedSocket> {
    let helper = helper_exe()?;
    run_as_user_deadline_argument_with_helper(
        op,
        argument,
        uid,
        gid,
        Instant::now() + Duration::from_secs(30),
        &helper,
    )
}

fn run_as_user_deadline(
    op: Op,
    path: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> io::Result<ReceivedSocket> {
    if path_too_long(path) {
        return Err(io::Error::from_raw_os_error(
            rustix::io::Errno::NAMETOOLONG.raw_os_error(),
        ));
    }
    let helper = helper_exe()?;
    run_as_user_deadline_with_helper(op, path, uid, gid, deadline, &helper)
}

fn run_as_user_deadline_with_helper(
    op: Op,
    path: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
) -> io::Result<ReceivedSocket> {
    run_as_user_deadline_with_helper_cancelled(
        op,
        path,
        uid,
        gid,
        deadline,
        helper,
        &AtomicBool::new(false),
    )
}

fn run_as_user_deadline_with_helper_cancelled(
    op: Op,
    path: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
    cancelled: &AtomicBool,
) -> io::Result<ReceivedSocket> {
    run_as_user_deadline_argument_with_helper_cancelled(
        op,
        path.as_os_str(),
        uid,
        gid,
        deadline,
        helper,
        cancelled,
    )
}

fn run_as_user_deadline_argument_with_helper(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
) -> io::Result<ReceivedSocket> {
    run_as_user_deadline_argument_with_helper_cancelled(
        op,
        argument,
        uid,
        gid,
        deadline,
        helper,
        &AtomicBool::new(false),
    )
}

fn run_as_user_deadline_argument_with_helper_cancelled(
    op: Op,
    argument: &OsStr,
    uid: u32,
    gid: u32,
    deadline: Instant,
    helper: &Path,
    cancelled: &AtomicBool,
) -> io::Result<ReceivedSocket> {
    let path = Path::new(argument);
    let (parent, child) = UnixStream::pair()?;
    let generation = format!(
        "{}-{}",
        std::process::id(),
        NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let generation_path = generation_path(path, &generation);
    let helper_path = if matches!(op, Op::Listen) {
        staging_path(path, &generation)
    } else {
        path.to_path_buf()
    };
    let mut command = Command::new(helper);
    command
        .env(OP_ENV, op.as_env())
        .env(PATH_ENV, &helper_path)
        .env(PUBLIC_PATH_ENV, path)
        .env(UID_ENV, uid.to_string())
        .env(GID_ENV, gid.to_string())
        .env(GENERATION_ENV, &generation)
        .env(GENERATION_PATH_ENV, &generation_path)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child_proc = command.spawn()?;
    let result = (|| {
        let result = recv_result_until(&parent, deadline, cancelled).and_then(|fd| {
            let stat = rustix::fs::fstat(&fd)?;
            let identity = if matches!(op, Op::Listen) {
                let (owner, identity) = read_generation_marker(&generation_path)
                    .ok_or_else(|| io::Error::other("user-socket helper omitted its generation"))?;
                if owner != generation
                    || identity.fd_device != stat.st_dev as u64
                    || identity.fd_inode != stat.st_ino as u64
                {
                    return Err(io::Error::other("user-socket helper identity mismatch"));
                }
                identity
            } else {
                UnixSocketIdentity {
                    fd_device: stat.st_dev as u64,
                    fd_inode: stat.st_ino as u64,
                    node_device: 0,
                    node_inode: 0,
                }
            };
            Ok(ReceivedSocket { fd, identity })
        });
        if wait_for_helper_exit(&mut child_proc, deadline, cancelled)? {
            ensure_deadline(deadline)?;
            result
        } else {
            Err(timeout_error())
        }
    })();
    let timed_out = result.as_ref().is_err_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
    });
    if timed_out {
        let _ = child_proc.kill();
    }
    let _ = child_proc.wait();
    if matches!(op, Op::Listen) {
        let _ = fs::remove_file(&helper_path);
        if result.is_err() {
            cleanup_helper_generation(path, &generation_path, &generation);
        } else {
            remove_generation_marker(&generation_path, &generation);
        }
    }
    if timed_out {
        Err(timeout_error())
    } else {
        result
    }
}

fn recv_result_until(
    channel: &UnixStream,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<OwnedFd> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(timeout_error());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        channel.set_read_timeout(Some(remaining.min(Duration::from_millis(25))))?;
        match recv_result(channel) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            result => return result,
        }
    }
}

fn wait_for_helper_exit(
    child: &mut std::process::Child,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<bool> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Ok(false);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        if child
            .wait_timeout(remaining.min(Duration::from_millis(25)))?
            .is_some()
        {
            return Ok(true);
        }
    }
}

fn staging_path(path: &Path, generation: &str) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".et-forward-{}-{generation}", std::process::id()))
}

pub(crate) fn bind_staged(
    public_path: &Path,
    deadline: Instant,
) -> io::Result<(UnixListener, UnixSocketIdentity)> {
    bind_staged_with_hook(public_path, deadline, || {})
}

fn bind_staged_with_hook(
    public_path: &Path,
    deadline: Instant,
    before_publish: impl FnOnce(),
) -> io::Result<(UnixListener, UnixSocketIdentity)> {
    let generation = format!(
        "{}-{}",
        std::process::id(),
        NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let staged = staging_path(public_path, &generation);
    let listener = listen_at_path(&staged)?;
    let identity = UnixSocketIdentity::from_fd_and_node(listener.as_fd(), &staged)?;
    ensure_deadline(deadline)?;
    let _guard = path_operations()
        .lock()
        .map_err(|_| io::Error::other("socket path lock unavailable"))?;
    ensure_deadline(deadline)?;
    before_publish();
    if let Err(error) = publish_noreplace(&staged, public_path) {
        drop(listener);
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    Ok((listener, identity))
}

fn generation_path(path: &Path, generation: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(format!(".et-generation-{generation}"));
    PathBuf::from(value)
}

fn publish_helper_generation(listener: &UnixListener, staged: &Path) -> io::Result<()> {
    publish_helper_generation_with_hook(listener, staged, || {})
}

fn publish_helper_generation_with_hook(
    listener: &UnixListener,
    staged: &Path,
    before_publish: impl FnOnce(),
) -> io::Result<()> {
    let generation = std::env::var(GENERATION_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "helper generation is missing"))?;
    let marker = std::env::var_os(GENERATION_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "helper marker path is missing")
        })?;
    let public = std::env::var_os(PUBLIC_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "public socket path is missing")
        })?;
    publish_helper_generation_paths(
        listener,
        staged,
        &public,
        &marker,
        &generation,
        before_publish,
    )
}

fn publish_helper_generation_paths(
    listener: &UnixListener,
    staged: &Path,
    public: &Path,
    marker: &Path,
    generation: &str,
    before_publish: impl FnOnce(),
) -> io::Result<()> {
    let identity = UnixSocketIdentity::from_fd_and_node(listener.as_fd(), staged)?;
    fs::write(
        marker,
        format!(
            "{generation} {} {} {} {}\n",
            identity.fd_device, identity.fd_inode, identity.node_device, identity.node_inode
        ),
    )?;
    before_publish();
    publish_noreplace(staged, public)
}

fn publish_noreplace(staged: &Path, public: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staged,
        rustix::fs::CWD,
        public,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix source socket was published by another generation",
            )
        } else {
            io::Error::from(error)
        }
    })
}

fn read_generation_marker(path: &Path) -> Option<(String, UnixSocketIdentity)> {
    let value = fs::read_to_string(path).ok()?;
    let mut fields = value.split_whitespace();
    let generation = fields.next()?.to_owned();
    let fd_device = fields.next()?.parse().ok()?;
    let fd_inode = fields.next()?.parse().ok()?;
    let node_device = fields.next()?.parse().ok()?;
    let node_inode = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some((
        generation,
        UnixSocketIdentity {
            fd_device,
            fd_inode,
            node_device,
            node_inode,
        },
    ))
}

fn cleanup_helper_generation(path: &Path, marker: &Path, generation: &str) {
    let Some((owner, identity)) = read_generation_marker(marker) else {
        return;
    };
    if owner == generation {
        remove_socket_if_owned(path, identity);
        remove_generation_marker(marker, generation);
    }
}

fn remove_generation_marker(marker: &Path, generation: &str) {
    if read_generation_marker(marker).is_some_and(|(owner, _)| owner == generation) {
        let _ = fs::remove_file(marker);
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "user-socket helper deadline elapsed",
    )
}

fn ensure_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(timeout_error())
    } else {
        Ok(())
    }
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
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::sync::atomic::AtomicU64;

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

    fn socket_helper(directory: &Path, behavior: &str) -> PathBuf {
        let helper = directory.join(format!("helper-{behavior}.py"));
        let tail = match behavior {
            "block" => "open(public + '.event', 'wb').write(b'x')\nos.read(0, 1)\n",
            "short" => "os.write(0, b'x')\n",
            "missing" => "os.write(0, struct.pack('ii', 0, 0))\n",
            "error" => "os.write(0, struct.pack('ii', -1, 5))\n",
            "handoff" => "channel=socket.socket(fileno=0)\nfds=array.array('i', [s.fileno()])\nchannel.sendmsg([struct.pack('ii', 0, 0)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])\nopen(public + '.event', 'wb').write(b'x')\nopen(public + '.release', 'rb').read(1)\n",
            _ => unreachable!(),
        };
        fs::write(
            &helper,
            format!(
                "#!/usr/bin/python3\nimport array, os, socket, struct\npath=os.environ['{PATH_ENV}']\npublic=os.environ['{PUBLIC_PATH_ENV}']\nmarker=os.environ['{GENERATION_PATH_ENV}']\ngeneration=os.environ['{GENERATION_ENV}']\ntry: os.unlink(path)\nexcept FileNotFoundError: pass\ns=socket.socket(socket.AF_UNIX)\ns.bind(path)\nfdst=os.fstat(s.fileno())\nnodest=os.stat(path)\nopen(marker, 'w').write(f'{{generation}} {{fdst.st_dev}} {{fdst.st_ino}} {{nodest.st_dev}} {{nodest.st_ino}}\\n')\nos.link(path, public)\nos.unlink(path)\n{tail}"
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        helper
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
    fn helper_no_reply_is_killed_reaped_and_socket_path_rolled_back() {
        let dir = temp_dir();
        let path = dir.join("listener.sock");
        let event = PathBuf::from(format!("{}.event", path.display()));
        assert!(Command::new("mkfifo")
            .arg(&event)
            .status()
            .unwrap()
            .success());
        let event_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&event)
            .unwrap();
        let helper = dir.join("helper.sh");
        fs::write(
            &helper,
            "#!/bin/sh\nprintf x > \"${ET_RS_USER_SOCKET_PUBLIC_PATH}.event\"\nexec cat\n",
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let worker_path = path.clone();
        std::thread::spawn(move || {
            let result = run_as_user_deadline_with_helper(
                Op::Listen,
                &worker_path,
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                Instant::now() + Duration::from_millis(100),
                &helper,
            );
            let _ = done_tx.send(result);
        });
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut event_control = event_control;
            let mut byte = [0];
            let result = event_control.read_exact(&mut byte);
            let _ = event_tx.send(result);
        });
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("helper did not enter its no-reply state")
            .unwrap();
        let error = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed-out helper was not killed and reaped")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stalled_tcp_helper_honors_caller_deadline_and_is_killed_reaped() {
        let dir = temp_dir();
        let event = dir.join("tcp-helper.event");
        assert!(Command::new("mkfifo")
            .arg(&event)
            .status()
            .unwrap()
            .success());
        let event_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&event)
            .unwrap();
        let pid_path = dir.join("tcp-helper.pid");
        let helper = dir.join("tcp-helper.py");
        fs::write(
            &helper,
            format!(
                "#!/usr/bin/python3\nimport os, socket\nhost, port = os.environ['{PATH_ENV}'].rsplit(':', 1)\ns = socket.socket(socket.AF_INET)\ns.bind((host, int(port)))\ns.listen(1)\nopen(r'{}', 'w').write(str(os.getpid()))\nopen(r'{}', 'wb').write(b'x')\nos.read(0, 1)\n",
                pid_path.display(),
                event.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let probe = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let started = Instant::now();
        let deadline = started + Duration::from_secs(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let argument = address.to_string();
            let result = run_as_user_deadline_argument_with_helper(
                Op::ListenTcp,
                OsStr::new(&argument),
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                deadline,
                &helper,
            );
            let _ = done_tx.send((Instant::now(), result));
        });
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut event_control = event_control;
            let mut byte = [0];
            let result = event_control.read_exact(&mut byte);
            let _ = event_tx.send(result);
        });
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("TCP helper did not bind and enter its no-reply state")
            .unwrap();
        let (completed, result) = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("TCP helper exceeded the caller deadline without being reaped");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(completed <= deadline + Duration::from_millis(100));
        let pid = fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD,
            "timed-out TCP helper was not killed and reaped"
        );
        TcpListener::bind(address).expect("timed-out TCP helper left its listener behind");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn older_helper_timeout_does_not_unlink_replacement_generation() {
        let dir = temp_dir();
        let path = dir.join("overlap.sock");
        let event = PathBuf::from(format!("{}.event", path.display()));
        assert!(Command::new("mkfifo")
            .arg(&event)
            .status()
            .unwrap()
            .success());
        let event_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&event)
            .unwrap();
        let helper = socket_helper(&dir, "block");
        enum HelperLifecycle {
            Published(io::Result<()>),
            Done(io::Result<ReceivedSocket>),
        }
        let (lifecycle_tx, lifecycle_rx) = std::sync::mpsc::sync_channel(2);
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let worker_tx = lifecycle_tx.clone();
        let old_path = path.clone();
        std::thread::spawn(move || {
            let result = run_as_user_deadline_with_helper_cancelled(
                Op::Listen,
                &old_path,
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                Instant::now() + Duration::from_secs(30),
                &helper,
                &worker_cancelled,
            );
            let _ = worker_tx.send(HelperLifecycle::Done(result));
        });
        std::thread::spawn(move || {
            let mut event_control = event_control;
            let mut byte = [0];
            let result = event_control.read_exact(&mut byte);
            let _ = lifecycle_tx.send(HelperLifecycle::Published(result));
        });
        match lifecycle_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(HelperLifecycle::Published(Ok(()))) => {}
            Ok(HelperLifecycle::Published(Err(error))) => {
                panic!("helper publication event failed: {error}")
            }
            Ok(HelperLifecycle::Done(Ok(_))) => {
                panic!("helper returned a listener before entering no-reply")
            }
            Ok(HelperLifecycle::Done(Err(error))) => {
                panic!("helper failed before publishing its generation: {error}")
            }
            Err(error) => panic!("helper lifecycle produced no event: {error}"),
        }
        assert!(fs::metadata(&path).unwrap().file_type().is_socket());
        let marker = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| candidate.to_string_lossy().contains(".et-generation-"))
            .expect("published helper generation has no ownership marker");
        let (_, identity) = read_generation_marker(&marker)
            .expect("published helper generation marker is malformed");
        assert!(identity.node_matches(&path));

        fs::remove_file(&path).unwrap();
        let replacement = listen_at_path(&path).unwrap();
        cancelled.store(true, Ordering::Release);
        let error = match lifecycle_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(HelperLifecycle::Done(result)) => result.unwrap_err(),
            Ok(HelperLifecycle::Published(_)) => panic!("duplicate helper publication event"),
            Err(error) => panic!("cancelled helper was not killed and reaped: {error}"),
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let client = UnixStream::connect(&path)
            .expect("older helper timeout unlinked replacement generation");
        replacement.accept().unwrap();
        drop(client);
        drop(replacement);
        let _ = fs::remove_file(&path);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn successful_handoff_does_not_adopt_replacement_before_helper_exit() {
        let dir = temp_dir();
        let path = dir.join("handoff.sock");
        for suffix in ["event", "release"] {
            assert!(Command::new("mkfifo")
                .arg(format!("{}.{}", path.display(), suffix))
                .status()
                .unwrap()
                .success());
        }
        let event = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("{}.event", path.display()))
            .unwrap();
        let mut release = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("{}.release", path.display()))
            .unwrap();
        let helper = socket_helper(&dir, "handoff");
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let worker_path = path.clone();
        std::thread::spawn(move || {
            let result = run_as_user_deadline_with_helper(
                Op::Listen,
                &worker_path,
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                Instant::now() + Duration::from_secs(2),
                &helper,
            );
            let _ = done_tx.send(result);
        });
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut event = event;
            let mut byte = [0];
            let _ = event_tx.send(event.read_exact(&mut byte));
        });
        event_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = listen_at_path(&path).unwrap();
        release.write_all(b"x").unwrap();
        let received = done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(!received.identity.node_matches(&path));
        remove_socket_if_owned(&path, received.identity);
        drop(received);
        let client = UnixStream::connect(&path)
            .expect("successful older handoff adopted replacement identity");
        replacement.accept().unwrap();
        drop(client);
        drop(replacement);
        let _ = fs::remove_file(&path);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn premarker_short_reply_leaves_no_public_or_staged_socket() {
        let dir = temp_dir();
        let path = dir.join("premarker.sock");
        let helper = dir.join("premarker.py");
        fs::write(
            &helper,
            format!(
                "#!/usr/bin/python3\nimport os,socket\np=os.environ['{PATH_ENV}']\ns=socket.socket(socket.AF_UNIX)\ns.bind(p)\nos.write(0,b'x')\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(run_as_user_deadline_with_helper(
            Op::Listen,
            &path,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            Instant::now() + Duration::from_secs(1),
            &helper,
        )
        .is_err());
        assert!(!path.exists());
        assert!(fs::read_dir(&dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".et-forward-")
        }));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_fd_and_explicit_helper_error_remove_owned_generation() {
        for behavior in ["missing", "error"] {
            let dir = temp_dir();
            let path = dir.join(format!("{behavior}.sock"));
            let helper = socket_helper(&dir, behavior);
            assert!(run_as_user_deadline_with_helper(
                Op::Listen,
                &path,
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                Instant::now() + Duration::from_secs(1),
                &helper,
            )
            .is_err());
            assert!(!path.exists(), "{behavior} left the public socket");
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn malformed_helper_reply_reaps_helper_and_removes_owned_stale_path() {
        let dir = temp_dir();
        let path = dir.join("malformed.sock");
        let helper = socket_helper(&dir, "short");
        let error = run_as_user_deadline_with_helper(
            Op::Listen,
            &path,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            Instant::now() + Duration::from_secs(1),
            &helper,
        )
        .unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!path.exists(), "malformed helper left a stale socket path");
        assert!(
            fs::read_dir(&dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("et-generation")),
            "malformed helper left a generation marker"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replacement_published_after_retirement_is_never_unlinked() {
        let dir = temp_dir();
        let path = dir.join("retire-race.sock");
        let (old, identity) = bind_staged(&path, Instant::now() + Duration::from_secs(1)).unwrap();
        fs::remove_file(&path).unwrap();
        let displaced = UnixListener::bind(&path).unwrap();
        let mut newest = None;
        remove_socket_if_owned_with_hook(&path, identity, || {
            newest = Some(UnixListener::bind(&path).unwrap());
        });
        let client = UnixStream::connect(&path)
            .expect("retirement cleanup unlinked newly published generation");
        newest.as_ref().unwrap().accept().unwrap();
        drop(client);
        drop(old);
        drop(displaced);
        drop(newest);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn helper_publication_loses_atomically_to_final_window_replacement() {
        let dir = temp_dir();
        let public = dir.join("helper-race.sock");
        let staged = dir.join("helper-race.staged");
        let marker = dir.join("helper-race.marker");
        let generation = "test-generation";
        let listener = listen_at_path(&staged).unwrap();
        let mut replacement = None;
        let error = publish_helper_generation_paths(
            &listener,
            &staged,
            &public,
            &marker,
            generation,
            || replacement = Some(listen_at_path(&public).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        drop(listener);
        let _ = fs::remove_file(&staged);
        cleanup_helper_generation(&public, &marker, generation);
        assert!(!staged.exists());
        assert!(!marker.exists());
        let client = UnixStream::connect(&public).unwrap();
        replacement.as_ref().unwrap().accept().unwrap();
        drop(client);
        drop(replacement);
        fs::remove_file(public).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn direct_bind_replacement_during_identity_capture_is_preserved() {
        let dir = temp_dir();
        let path = dir.join("direct-race.sock");
        let mut replacement = None;
        let error =
            match bind_staged_with_hook(&path, Instant::now() + Duration::from_secs(1), || {
                replacement = Some(UnixListener::bind(&path).unwrap())
            }) {
                Ok(_) => panic!("older direct bind overwrote replacement generation"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let client = UnixStream::connect(&path).unwrap();
        replacement.as_ref().unwrap().accept().unwrap();
        drop(client);
        drop(replacement);
        fs::remove_file(path).unwrap();
        fs::remove_dir_all(dir).unwrap();
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
