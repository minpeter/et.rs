use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use et_core::proto::SocketEndpoint;

use crate::forward::{ForwardResolver, ResolverExecutor};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    Tcp {
        host: String,
        port: u16,
    },
    /// Unix-socket endpoint. Upstream only forwards these on POSIX systems
    /// (`PipeSocketHandler` is guarded by `#ifndef WIN32` for chmod and is not
    /// built into the Windows client), so they are Unix-only here as well.
    #[cfg(unix)]
    Unix(PathBuf),
}

impl Endpoint {
    pub(crate) fn parse(endpoint: Option<SocketEndpoint>) -> io::Result<Self> {
        let endpoint = endpoint
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint is missing"))?;
        let name = endpoint.name.filter(|name| !name.contains('\0'));
        match endpoint.port {
            Some(port) => {
                let port = u16::try_from(port).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "endpoint port is invalid")
                })?;
                if port == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "endpoint port is invalid",
                    ));
                }
                // Upstream sends TCP endpoints with the name unset for the
                // common `port:port` tunnel form; treat those as localhost.
                Ok(Self::Tcp {
                    host: name.unwrap_or_else(|| "localhost".to_owned()),
                    port,
                })
            }
            None => match name {
                #[cfg(unix)]
                Some(name) if name.starts_with('/') => Ok(Self::Unix(PathBuf::from(name))),
                #[cfg(windows)]
                Some(name) if name.starts_with('/') => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unix-socket tunnels are not supported on Windows",
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unix endpoint path must be absolute",
                )),
            },
        }
    }

    /// Parse a `PORT_FORWARD_DESTINATION_REQUEST`, preserving explicit TCP
    /// names so resolution happens on the destination side. An absent name
    /// retains protocol-v6's localhost default.
    pub(crate) fn parse_destination(endpoint: Option<SocketEndpoint>) -> io::Result<Self> {
        let endpoint = endpoint
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint is missing"))?;
        match endpoint.port {
            Some(port) => {
                let port = u16::try_from(port).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "endpoint port is invalid")
                })?;
                if port == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "endpoint port is invalid",
                    ));
                }
                let host = endpoint
                    .name
                    .filter(|name| !name.contains('\0'))
                    .unwrap_or_else(|| "localhost".to_owned());
                Ok(Self::Tcp { host, port })
            }
            None => {
                let name = endpoint
                    .name
                    .filter(|name| name.starts_with('/') && !name.contains('\0'))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Unix endpoint path must be absolute",
                        )
                    })?;
                #[cfg(unix)]
                {
                    Ok(Self::Unix(PathBuf::from(name)))
                }
                #[cfg(windows)]
                {
                    let _ = name;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Unix-socket tunnels are not supported on Windows",
                    ))
                }
            }
        }
    }

    pub(crate) fn connect_with_user(&self, user: Option<(u32, u32)>) -> io::Result<ForwardStream> {
        match (self, user) {
            #[cfg(unix)]
            (Self::Tcp { host, port }, Some((uid, gid))) => {
                crate::user_socket_ops::connect_tcp_as_user(host, *port, uid, gid)
                    .map(ForwardStream::Tcp)
            }
            #[cfg(unix)]
            (Self::Unix(path), Some((uid, gid))) => {
                crate::user_socket_ops::connect_unix_as_user(path, uid, gid)
                    .map(ForwardStream::Unix)
            }
            _ => self.connect(),
        }
    }

    pub(crate) fn connect(&self) -> io::Result<ForwardStream> {
        match self {
            Self::Tcp { host, port } => connect_tcp(host, *port).map(ForwardStream::Tcp),
            #[cfg(unix)]
            Self::Unix(path) => UnixStream::connect(path).map(ForwardStream::Unix),
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve_for_bind(&self) -> io::Result<ResolvedEndpoint> {
        match self {
            Self::Tcp { host, port } => {
                // Mirror upstream `TcpSocketHandler::listen`: resolve the bind
                // name with getaddrinfo semantics and bind every distinct
                // address ("localhost" usually yields both loopback families).
                let addresses = if host.is_empty() {
                    vec![
                        (std::net::Ipv6Addr::UNSPECIFIED, *port).into(),
                        (std::net::Ipv4Addr::UNSPECIFIED, *port).into(),
                    ]
                } else if host == "localhost" {
                    vec![
                        (std::net::Ipv6Addr::LOCALHOST, *port).into(),
                        (std::net::Ipv4Addr::LOCALHOST, *port).into(),
                    ]
                } else {
                    (host.as_str(), *port).to_socket_addrs()?.collect()
                };
                Ok(ResolvedEndpoint::Tcp(distinct_tcp_addresses(addresses)))
            }
            #[cfg(unix)]
            Self::Unix(path) => Ok(ResolvedEndpoint::Unix(path.clone())),
        }
    }

    pub(crate) fn resolve_for_bind_deadline(
        &self,
        deadline: Instant,
        resolver: Arc<dyn ForwardResolver>,
    ) -> io::Result<ResolvedEndpoint> {
        ensure_deadline(deadline)?;
        match self {
            Self::Tcp { host, port } => {
                let addresses = if host.is_empty() {
                    vec![
                        (std::net::Ipv6Addr::UNSPECIFIED, *port).into(),
                        (std::net::Ipv4Addr::UNSPECIFIED, *port).into(),
                    ]
                } else if host == "localhost" {
                    vec![
                        (std::net::Ipv6Addr::LOCALHOST, *port).into(),
                        (std::net::Ipv4Addr::LOCALHOST, *port).into(),
                    ]
                } else {
                    ResolverExecutor::global().resolve(resolver, host.clone(), *port, deadline)?
                };
                ensure_deadline(deadline)?;
                Ok(ResolvedEndpoint::Tcp(distinct_tcp_addresses(addresses)))
            }
            #[cfg(unix)]
            Self::Unix(path) => Ok(ResolvedEndpoint::Unix(path.clone())),
        }
    }

    #[cfg(test)]
    pub(crate) fn bind(&self) -> io::Result<Vec<ForwardListener>> {
        self.resolve_for_bind()?.bind_with_user(None)
    }
}

pub(crate) fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    // Preserve upstream's dual-stack localhost ordering while allowing
    // explicitly configured destination names under the session identity.
    if host.eq_ignore_ascii_case("localhost") {
        let v6 = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
        match TcpStream::connect_timeout(&v6, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(_) => {
                let v4 = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
                return TcpStream::connect_timeout(&v4, CONNECT_TIMEOUT);
            }
        }
    }
    let mut last_error = None;
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "endpoint did not resolve")
    }))
}

#[cfg(test)]
fn collect_distinct_addresses(
    addresses: io::Result<impl Iterator<Item = std::net::SocketAddr>>,
    max_addresses: usize,
) -> io::Result<Vec<std::net::SocketAddr>> {
    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for address in addresses? {
        if seen.insert(address) {
            if resolved.len() >= max_addresses {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "forward source exceeds listener limit",
                ));
            }
            resolved.push(address);
        }
    }
    if resolved.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "endpoint did not resolve",
        ))
    } else {
        Ok(resolved)
    }
}

pub(crate) enum ResolvedEndpoint {
    Tcp(Vec<std::net::SocketAddr>),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ResolvedEndpoint {
    pub(crate) fn listener_count(&self) -> usize {
        match self {
            Self::Tcp(addresses) => addresses.len(),
            #[cfg(unix)]
            Self::Unix(_) => 1,
        }
    }

    #[cfg(test)]
    pub(crate) fn bind_with_user(
        &self,
        user: Option<(u32, u32)>,
    ) -> io::Result<Vec<ForwardListener>> {
        match (self, user) {
            #[cfg(unix)]
            (Self::Tcp(addresses), Some((uid, gid))) => {
                bind_tcp_addresses_with(addresses.iter().copied(), |address| {
                    crate::user_socket_ops::listen_tcp_as_user(address, uid, gid).map(Some)
                })
            }
            (Self::Tcp(addresses), _) => bind_tcp_addresses(addresses.iter().copied()),
            #[cfg(unix)]
            (Self::Unix(path), Some((uid, gid))) => {
                let listener = crate::user_socket_ops::listen_unix_as_user(path, uid, gid)?;
                let (listener, cleanup) = listener.into_parts();
                listener.set_nonblocking(true)?;
                let path_cleanup = cleanup.is_none().then(|| path.clone());
                Ok(vec![ForwardListener {
                    inner: ListenerKind::Unix(listener),
                    cleanup: path_cleanup,
                    user_cleanup: cleanup,
                    cleanup_dirs: Vec::new(),
                }])
            }
            #[cfg(unix)]
            (Self::Unix(path), None) => bind_unix_locally_with(path, |listener| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                listener.set_nonblocking(true)
            })
            .map(|listener| vec![listener]),
        }
    }

    pub(crate) fn bind_with_user_deadline_resolver(
        &self,
        user: Option<(u32, u32)>,
        deadline: Instant,
        _resolver: Arc<dyn ForwardResolver>,
    ) -> io::Result<Vec<ForwardListener>> {
        ensure_deadline(deadline)?;
        let listeners = match (self, user) {
            #[cfg(unix)]
            (Self::Tcp(addresses), Some((uid, gid))) => {
                bind_tcp_addresses_with(addresses.iter().copied(), |address| {
                    ensure_deadline(deadline)?;
                    _resolver
                        .listen_tcp_as_user(address, uid, gid, deadline)
                        .map(Some)
                })
            }
            (Self::Tcp(addresses), _) => {
                bind_tcp_addresses_with(addresses.iter().copied(), |address| {
                    ensure_deadline(deadline)?;
                    let listener = bind_tcp_single_family(address)?;
                    ensure_deadline(deadline)?;
                    Ok(listener)
                })
            }
            #[cfg(unix)]
            (Self::Unix(path), Some((uid, gid))) => {
                let listener =
                    crate::user_socket_ops::listen_unix_as_user_until(path, uid, gid, deadline)?;
                let (listener, cleanup) = listener.into_parts();
                listener.set_nonblocking(true)?;
                let path_cleanup = cleanup.is_none().then(|| path.clone());
                Ok(vec![ForwardListener {
                    inner: ListenerKind::Unix(listener),
                    cleanup: path_cleanup,
                    user_cleanup: cleanup,
                    cleanup_dirs: Vec::new(),
                }])
            }
            #[cfg(unix)]
            (Self::Unix(path), None) => {
                ensure_deadline(deadline)?;
                let listener = bind_unix_locally_with(path, |listener| {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    listener.set_nonblocking(true)
                })?;
                ensure_deadline(deadline)?;
                Ok(vec![listener])
            }
        }?;
        ensure_deadline(deadline)?;
        Ok(listeners)
    }
}

fn ensure_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "forwarding setup deadline elapsed",
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn bind_unix_locally_with(
    path: &Path,
    configure: impl FnOnce(&UnixListener) -> io::Result<()>,
) -> io::Result<ForwardListener> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Unix source socket already exists",
        ));
    }
    let mut parent_cleanup = None;
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            parent_cleanup = Some(create_missing_directories_with(parent, |directory| {
                fs::create_dir(directory)
            })?);
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let listener = UnixListener::bind(path)?;
    finish_unix_listener_with(listener, path, parent_cleanup, configure)
}

#[cfg(unix)]
fn finish_unix_listener_with(
    listener: UnixListener,
    path: &Path,
    mut cleanup_dirs: Option<PendingDirectories>,
    configure: impl FnOnce(&UnixListener) -> io::Result<()>,
) -> io::Result<ForwardListener> {
    let mut socket_cleanup = PendingPath::socket(path.to_path_buf());
    configure(&listener)?;
    Ok(ForwardListener {
        inner: ListenerKind::Unix(listener),
        cleanup: socket_cleanup.disarm(),
        user_cleanup: None,
        cleanup_dirs: cleanup_dirs
            .as_mut()
            .and_then(PendingDirectories::disarm)
            .unwrap_or_default(),
    })
}

#[cfg(unix)]
struct PendingPath {
    path: Option<PathBuf>,
}

#[cfg(unix)]
impl PendingPath {
    fn socket(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

#[cfg(unix)]
impl Drop for PendingPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.as_ref() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn missing_directories(parent: &Path) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    let mut current = Some(parent);
    while let Some(path) = current {
        if path.exists() {
            break;
        }
        directories.push(path.to_path_buf());
        current = path.parent();
    }
    directories
}

#[cfg(unix)]
fn create_missing_directories_with(
    parent: &Path,
    mut create: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<PendingDirectories> {
    let directories = missing_directories(parent);
    let mut cleanup = PendingDirectories(Some(Vec::with_capacity(directories.len())));
    for directory in directories.iter().rev() {
        create(directory)?;
        cleanup
            .0
            .as_mut()
            .expect("pending directory cleanup")
            .insert(0, directory.clone());
    }
    Ok(cleanup)
}

#[cfg(unix)]
struct PendingDirectories(Option<Vec<PathBuf>>);

#[cfg(unix)]
impl PendingDirectories {
    fn disarm(&mut self) -> Option<Vec<PathBuf>> {
        self.0.take()
    }
}

#[cfg(unix)]
impl Drop for PendingDirectories {
    fn drop(&mut self) {
        if let Some(paths) = self.0.take() {
            for path in paths {
                let _ = fs::remove_dir(path);
            }
        }
    }
}

#[cfg(test)]
fn bind_tcp_addresses(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> io::Result<Vec<ForwardListener>> {
    bind_tcp_addresses_with(addresses, bind_tcp_single_family)
}

fn bind_tcp_addresses_with(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    mut bind: impl FnMut(std::net::SocketAddr) -> io::Result<Option<TcpListener>>,
) -> io::Result<Vec<ForwardListener>> {
    let mut listeners = Vec::new();
    for address in addresses {
        if let Some(listener) = bind(address)? {
            listeners.push(ForwardListener {
                inner: ListenerKind::Tcp(listener),
                cleanup: None,
                #[cfg(unix)]
                user_cleanup: None,
                cleanup_dirs: Vec::new(),
            });
        }
    }
    if listeners.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "endpoint did not resolve",
        ));
    }
    Ok(listeners)
}

fn distinct_tcp_addresses(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let mut seen = HashSet::new();
    addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect()
}

/// Bind one TCP listener for exactly one address family, mirroring upstream
/// `TcpSocketHandler::listen` (which sets `IPV6_V6ONLY` and binds each
/// resolved address separately).
pub(crate) fn bind_tcp_single_family(
    address: std::net::SocketAddr,
) -> io::Result<Option<TcpListener>> {
    let domain = if address.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = match socket2::Socket::new(domain, socket2::Type::STREAM, None) {
        Ok(socket) => socket,
        Err(error) if is_address_family_unsupported(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    // Match `std::net::TcpListener`: Windows SO_REUSEADDR permits rebinding
    // sockets that are actively in use, so do not enable it there. Unix needs
    // reuse for the normal close-and-restart lifecycle.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(128)?;
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(Some(listener))
}

fn is_address_family_unsupported(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(rustix::io::Errno::AFNOSUPPORT.raw_os_error())
    }
    #[cfg(windows)]
    {
        // Winsock's stable WSAEAFNOSUPPORT value.
        error.raw_os_error() == Some(10_047)
    }
}

pub(crate) enum ForwardStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl ForwardStream {
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            #[cfg(unix)]
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
        }
    }

    pub(crate) fn shutdown(&self) {
        let _ = match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(Shutdown::Both),
        };
    }

    /// Shut down only the receive half, waking a blocked reader thread
    /// without discarding data still queued for the writer thread.
    pub(crate) fn shutdown_read(&self) {
        let _ = match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Read),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(Shutdown::Read),
        };
    }
}

impl Read for ForwardStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buffer),
        }
    }
}

impl Write for ForwardStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

enum ListenerKind {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

pub(crate) struct ForwardListener {
    inner: ListenerKind,
    cleanup: Option<PathBuf>,
    #[cfg(unix)]
    user_cleanup: Option<crate::user_socket_ops::UserSocketCleanup>,
    cleanup_dirs: Vec<PathBuf>,
}

impl ForwardListener {
    /// Also remove this directory when the listener is dropped (used for the
    /// private named-pipe directories created for environment forwards).
    #[cfg(unix)]
    pub(crate) fn also_remove_dir(&mut self, directory: PathBuf) {
        self.cleanup_dirs.push(directory);
    }

    pub(crate) fn accept(&self) -> io::Result<ForwardStream> {
        let stream = match &self.inner {
            ListenerKind::Tcp(listener) => listener.accept().map(|(stream, _)| {
                let _ = stream.set_nonblocking(false);
                ForwardStream::Tcp(stream)
            }),
            #[cfg(unix)]
            ListenerKind::Unix(listener) => listener.accept().map(|(stream, _)| {
                let _ = stream.set_nonblocking(false);
                ForwardStream::Unix(stream)
            }),
        }?;
        Ok(stream)
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for ForwardListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match &self.inner {
            ListenerKind::Tcp(listener) => listener.as_fd(),
            ListenerKind::Unix(listener) => listener.as_fd(),
        }
    }
}

impl Drop for ForwardListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        drop(self.user_cleanup.take());
        if let Some(path) = self.cleanup.as_ref() {
            let _ = fs::remove_file(path);
        }
        for path in &self.cleanup_dirs {
            let _ = fs::remove_dir(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_parser_preserves_explicit_tcp_names_and_families() {
        for name in ["127.0.0.1", "::1", "backend.internal"] {
            // Given
            let endpoint = SocketEndpoint {
                name: Some(name.to_owned()),
                port: Some(4242),
            };

            // When
            let parsed = Endpoint::parse_destination(Some(endpoint)).unwrap();

            // Then
            match parsed {
                Endpoint::Tcp { host, port } => {
                    assert_eq!(host, name);
                    assert_eq!(port, 4242);
                }
                #[cfg(unix)]
                Endpoint::Unix(_) => panic!("TCP destination parsed as Unix"),
            }
        }
    }

    #[test]
    fn destination_parser_defaults_only_absent_tcp_name_to_localhost() {
        // Given
        let endpoint = SocketEndpoint {
            name: None,
            port: Some(4242),
        };

        // When
        let parsed = Endpoint::parse_destination(Some(endpoint)).unwrap();

        // Then
        match parsed {
            Endpoint::Tcp { host, port } => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 4242);
            }
            #[cfg(unix)]
            Endpoint::Unix(_) => panic!("TCP destination parsed as Unix"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_source_bind_uses_openssh_default_owner_only_mode() {
        // Given
        let path = PathBuf::from(format!("/tmp/et-forward-mode-{}", std::process::id()));
        let endpoint = ResolvedEndpoint::Unix(path.clone());

        // When
        let listeners = endpoint.bind_with_user(None).unwrap();

        // Then
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listeners);
    }

    #[cfg(unix)]
    #[test]
    fn failed_unix_listener_setup_removes_socket_and_created_parent() {
        let base = PathBuf::from(format!(
            "/tmp/et-forward-rollback-{}",
            et_core::keys::gen_id_passkey().0
        ));
        fs::create_dir(&base).unwrap();
        let created_parent = base.join("created");
        let path = created_parent.join("source.sock");

        let error = match bind_unix_locally_with(&path, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected post-bind setup failure",
            ))
        }) {
            Ok(_) => panic!("injected listener setup failure unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists());
        assert!(!created_parent.exists());
        fs::remove_dir(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failed_directory_creation_removes_created_ancestors() {
        struct RemoveDirectory(PathBuf);

        impl Drop for RemoveDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let base = PathBuf::from(format!(
            "/tmp/et-forward-directory-rollback-{}",
            et_core::keys::gen_id_passkey().0
        ));
        fs::create_dir(&base).unwrap();
        let _cleanup = RemoveDirectory(base.clone());
        let created = base.join("created");
        let parent = created.join("nested");
        let mut calls = 0;

        let error = match create_missing_directories_with(&parent, |directory| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected directory creation failure",
                ));
            }
            fs::create_dir(directory)
        }) {
            Ok(_) => panic!("injected directory creation failure unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!created.exists());
    }

    #[test]
    fn localhost_bind_rejects_one_occupied_address_family() {
        let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let endpoint = Endpoint::Tcp {
            host: "localhost".to_owned(),
            port,
        };

        let error = match endpoint.bind() {
            Ok(_) => panic!("a partially bound localhost source must fail"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn failed_address_rolls_back_an_earlier_listener() {
        let address: std::net::SocketAddr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
        let mut earlier = None;
        let mut calls = 0;

        let error = match bind_tcp_addresses_with([address, address], |_| {
            calls += 1;
            if calls == 1 {
                let listener = TcpListener::bind(address)?;
                listener.set_nonblocking(true)?;
                earlier = Some(listener.local_addr()?);
                Ok(Some(listener))
            } else {
                Err(io::Error::new(io::ErrorKind::AddrInUse, "occupied"))
            }
        }) {
            Ok(_) => panic!("a partially bound address list must fail"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        TcpListener::bind(earlier.unwrap())
            .expect("the earlier listener must be dropped on failure");
    }

    #[test]
    fn duplicate_addresses_are_bound_once() {
        let address: std::net::SocketAddr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
        let addresses = distinct_tcp_addresses([address, address]);

        assert_eq!(bind_tcp_addresses(addresses).unwrap().len(), 1);
    }

    #[test]
    fn bounded_resolution_counts_only_distinct_addresses() {
        let first = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 1));
        let second = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 2));
        let error =
            collect_distinct_addresses(Ok(vec![first, first, second].into_iter()), 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            collect_distinct_addresses(Ok(vec![first, first].into_iter()), 1).unwrap(),
            [first]
        );
    }

    #[test]
    fn address_family_error_classifier_is_platform_specific() {
        #[cfg(unix)]
        let unsupported =
            io::Error::from_raw_os_error(rustix::io::Errno::AFNOSUPPORT.raw_os_error());
        #[cfg(windows)]
        let unsupported = io::Error::from_raw_os_error(10_047);

        assert!(is_address_family_unsupported(&unsupported));
        assert!(!is_address_family_unsupported(&io::Error::new(
            io::ErrorKind::AddrInUse,
            "occupied",
        )));
        assert!(!is_address_family_unsupported(&io::Error::new(
            io::ErrorKind::Unsupported,
            "not an address-family error",
        )));
    }
}
