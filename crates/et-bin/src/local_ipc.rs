//! Bounded, same-user Unix IPC shared by the mux and control listeners.
//! Paths are literal (upstream does not expand OpenSSH ControlPath tokens).
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_FRAME: usize = 256 * 1024;
pub const MAX_REPLY: usize = 4 * 1024 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(5);

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn private_dir(path: &Path) -> io::Result<()> {
    // Permit root-managed aliases such as Darwin's /tmp -> /private/tmp,
    // but never create IPC through a user-controlled symlink ancestor.
    for ancestor in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            if metadata.file_type().is_symlink() && metadata.uid() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe IPC directory ancestor",
                ));
            }
        }
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
            if let Some(parent) = parent {
                if !parent.exists() {
                    private_dir(parent)?;
                }
            }
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local IPC directory must be owned by this user and mode 0700",
        ));
    }
    Ok(())
}

/// Stable advisory lock shared by bind/stale replacement and listener cleanup.
/// Keep the lock file: removing it would permit locking two different inodes.
pub fn lock_directory(directory: &Path) -> io::Result<fs::File> {
    private_dir(directory)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(directory.join(".et-lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe local lock",
        ));
    }
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(fs::TryLockError::WouldBlock) => return Err(io::ErrorKind::TimedOut.into()),
            Err(fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn connect_bounded(path: &Path) -> io::Result<UnixStream> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&socket2::SockAddr::unix(path)?, TIMEOUT)?;
    Ok(socket.into())
}

pub fn authorized(socket: &UnixStream) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        Ok(rustix::net::sockopt::socket_peercred(socket)?.uid == rustix::process::geteuid())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "ios"
    ))]
    {
        Ok(nix::unistd::getpeereid(socket)?.0.as_raw() == rustix::process::geteuid().as_raw())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "ios"
    )))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials unavailable on this platform",
        ))
    }
}

pub struct Listener {
    socket: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let _lock = lock_directory(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        // Never unlink a live master, symlink, regular file, or another user's socket.
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe existing IPC path",
                ));
            }
            match connect_bounded(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "local session already running",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?
                }
                Err(error) => return Err(error),
            }
        }
        let socket = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let result = Self {
            socket,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        result.socket.set_nonblocking(true)?;
        Ok(result)
    }

    pub fn accept(&self) -> io::Result<Option<UnixStream>> {
        match self.socket.accept() {
            Ok((socket, _)) => {
                if !authorized(&socket)? {
                    return Ok(None);
                }
                socket.set_nonblocking(true)?;
                Ok(Some(socket))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let Ok(_lock) = lock_directory(parent) else {
            return;
        };
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if (metadata.dev(), metadata.ino()) == self.identity {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

pub fn connect(path: &Path) -> io::Result<UnixStream> {
    private_dir(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe IPC socket",
        ));
    }
    let socket = connect_bounded(path)?;
    if !authorized(&socket)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
    }
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    Ok(socket)
}

pub struct FrameReader {
    bytes: Vec<u8>,
    control: bool,
    started: Instant,
}

impl FrameReader {
    pub fn new(control: bool) -> Self {
        Self {
            bytes: Vec::new(),
            control,
            started: Instant::now(),
        }
    }

    /// Read only the current frame: consuming the next byte here would lose SCM_RIGHTS.
    pub fn poll(&mut self, socket: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
        let header = if self.control { 5 } else { 4 };
        loop {
            let target = if self.bytes.len() < header {
                header
            } else {
                let length =
                    u32::from_be_bytes(self.bytes[header - 4..header].try_into().unwrap()) as usize;
                if length > MAX_FRAME || (!self.control && length < 4) {
                    return Err(invalid("IPC frame exceeds limit"));
                }
                header + length
            };
            if self.bytes.len() == target && target >= header {
                self.started = Instant::now();
                return Ok(Some(std::mem::take(&mut self.bytes)));
            }
            let mut chunk = [0; 8192];
            let count = chunk.len().min(target - self.bytes.len());
            match socket.read(&mut chunk[..count]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => self.bytes.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !self.bytes.is_empty() && self.started.elapsed() > TIMEOUT {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub fn control_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![opcode];
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(payload);
    result
}

pub fn mux_frame(payload: &[u8]) -> Vec<u8> {
    let mut result = (payload.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(payload);
    result
}

pub fn read_mux(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if !(4..=MAX_FRAME).contains(&length) {
        return Err(invalid("bad mux frame length"));
    }
    let mut body = vec![0; length];
    socket.read_exact(&mut body)?;
    Ok(body)
}

pub fn send_fd(socket: &UnixStream, fd: impl AsFd) -> io::Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    let mut storage = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut storage);
    let descriptors = [fd.as_fd()];
    ancillary.push(SendAncillaryMessage::ScmRights(&descriptors));
    let count = sendmsg(
        socket,
        &[io::IoSlice::new(&[0])],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    if count != 1 {
        return Err(invalid("failed to send descriptor"));
    }
    Ok(())
}

pub fn receive_fd(socket: &UnixStream) -> io::Result<Option<OwnedFd>> {
    use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
    let mut storage = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut storage);
    let mut byte = [0];
    let flags = RecvFlags::DONTWAIT;
    #[cfg(target_os = "linux")]
    let flags = flags | RecvFlags::CMSG_CLOEXEC;
    match recvmsg(
        socket,
        &mut [io::IoSliceMut::new(&mut byte)],
        &mut ancillary,
        flags,
    ) {
        Ok(message) => {
            let mut fds = Vec::new();
            for message in ancillary.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            if message.bytes != 1 || fds.len() != 1 {
                return Err(invalid("expected exactly one descriptor"));
            }
            let fd = fds.pop().unwrap();
            rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
            Ok(Some(fd))
        }
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn flush(socket: &mut impl Write, bytes: &mut Vec<u8>) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    match socket.write(bytes) {
        Ok(0) => Err(io::ErrorKind::WriteZero.into()),
        Ok(count) => {
            bytes.drain(..count);
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub struct Decoder<'a>(pub &'a [u8]);
impl<'a> Decoder<'a> {
    pub fn u32(&mut self) -> io::Result<u32> {
        if self.0.len() < 4 {
            return Err(invalid("short mux integer"));
        }
        let value = u32::from_be_bytes(self.0[..4].try_into().unwrap());
        self.0 = &self.0[4..];
        Ok(value)
    }
    pub fn string(&mut self) -> io::Result<&'a [u8]> {
        let length = self.u32()? as usize;
        if self.0.len() < length {
            return Err(invalid("short mux string"));
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }
    pub fn text(&mut self) -> io::Result<String> {
        String::from_utf8(self.string()?.to_vec()).map_err(|_| invalid("invalid mux UTF-8"))
    }
}
pub fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}
pub fn string(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}
