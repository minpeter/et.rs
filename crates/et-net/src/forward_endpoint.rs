use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::forward::{ForwardResolver, ResolverExecutor};

use et_core::proto::SocketEndpoint;

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
            (Self::Unix(path), Some((uid, gid))) => {
                crate::user_socket_ops::connect_unix_as_user(path, uid, gid)
                    .map(ForwardStream::Unix)
            }
            _ => self.connect(),
        }
    }

    pub(crate) fn connect(&self) -> io::Result<ForwardStream> {
        match self {
            Self::Tcp { host, port } => {
                // Upstream connects to localhost destinations by trying ::1
                // first and falling back to 127.0.0.1.
                if host.eq_ignore_ascii_case("localhost") {
                    let v6 = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, *port));
                    match TcpStream::connect_timeout(&v6, CONNECT_TIMEOUT) {
                        Ok(stream) => return Ok(ForwardStream::Tcp(stream)),
                        Err(_) => {
                            let v4 =
                                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, *port));
                            return TcpStream::connect_timeout(&v4, CONNECT_TIMEOUT)
                                .map(ForwardStream::Tcp);
                        }
                    }
                }
                let mut last_error = None;
                for address in (host.as_str(), *port).to_socket_addrs()? {
                    match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                        Ok(stream) => return Ok(ForwardStream::Tcp(stream)),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "endpoint did not resolve")
                }))
            }
            #[cfg(unix)]
            Self::Unix(path) => UnixStream::connect(path).map(ForwardStream::Unix),
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve_for_bind(&self) -> io::Result<ResolvedEndpoint> {
        self.resolve_for_bind_deadline(
            Instant::now() + Duration::from_secs(30),
            Arc::new(crate::forward::SystemForwardResolver),
        )
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
                    resolve_before_deadline(resolver, host.clone(), *port, deadline)?
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
        self.bind_with_user_deadline(user, Instant::now() + Duration::from_secs(30))
    }

    #[cfg(test)]
    pub(crate) fn bind_with_user_deadline(
        &self,
        user: Option<(u32, u32)>,
        deadline: Instant,
    ) -> io::Result<Vec<ForwardListener>> {
        self.bind_with_user_deadline_resolver(
            user,
            deadline,
            Arc::new(crate::forward::SystemForwardResolver),
        )
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
                    let listener = _resolver.listen_tcp_as_user(address, uid, gid, deadline)?;
                    ensure_deadline(deadline)?;
                    Ok(Some(listener))
                })
            }
            (Self::Tcp(addresses), _) => {
                bind_tcp_addresses_deadline(addresses.iter().copied(), deadline)
            }
            #[cfg(unix)]
            (Self::Unix(path), user) => {
                let listeners = bind_unix_source_deadline(
                    path,
                    user,
                    deadline,
                    || ensure_deadline(deadline),
                    || ensure_deadline(deadline),
                )?;
                ensure_deadline(deadline)?;
                Ok(listeners)
            }
        }?;
        ensure_deadline(deadline)?;
        Ok(listeners)
    }
}

#[cfg(unix)]
fn bind_unix_source_deadline(
    path: &std::path::Path,
    user: Option<(u32, u32)>,
    deadline: Instant,
    after_directory: impl FnOnce() -> io::Result<()>,
    after_bind: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<ForwardListener>> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Unix source socket already exists",
        ));
    }
    let mut directory_guard = None;
    if user.is_none() {
        if let Some(parent) = path.parent().filter(|parent| !parent.exists()) {
            fs::create_dir_all(parent)?;
            directory_guard = Some(PathCleanup::directory(parent.to_path_buf()));
            after_directory()?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let (listener, identity) = match user {
        Some((uid, gid)) => {
            crate::user_socket_ops::listen_unix_as_user_owned_deadline(path, uid, gid, deadline)?
        }
        None => crate::user_socket_ops::bind_staged(path, deadline)?,
    };
    let setup = (|| {
        after_bind()?;
        if user.is_none() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        listener.set_nonblocking(true)?;
        Ok(())
    })();
    if let Err(error) = setup {
        drop(listener);
        crate::user_socket_ops::remove_socket_if_owned(path, identity);
        return Err(error);
    }
    Ok(vec![ForwardListener {
        inner: ListenerKind::Unix(listener),
        cleanup: Some((path.to_path_buf(), identity)),
        cleanup_dir: directory_guard.and_then(PathCleanup::disarm),
    }])
}

#[cfg(all(test, unix))]
fn bind_unix_source(
    path: &std::path::Path,
    user: Option<(u32, u32)>,
    after_directory: impl FnOnce() -> io::Result<()>,
    after_bind: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<ForwardListener>> {
    bind_unix_source_deadline(
        path,
        user,
        Instant::now() + Duration::from_secs(30),
        after_directory,
        after_bind,
    )
}

#[cfg(unix)]
struct PathCleanup {
    path: Option<PathBuf>,
}

#[cfg(unix)]
impl PathCleanup {
    fn directory(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

#[cfg(unix)]
impl Drop for PathCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.as_ref() {
            let _ = fs::remove_dir(path);
        }
    }
}

#[cfg(test)]
fn bind_tcp_addresses(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> io::Result<Vec<ForwardListener>> {
    bind_tcp_addresses_deadline(addresses, Instant::now() + Duration::from_secs(30))
}

fn bind_tcp_addresses_deadline(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    deadline: Instant,
) -> io::Result<Vec<ForwardListener>> {
    bind_tcp_addresses_with(addresses, |address| {
        ensure_deadline(deadline)?;
        let listener = bind_tcp_single_family(address)?;
        ensure_deadline(deadline)?;
        Ok(listener)
    })
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
                #[cfg(unix)]
                cleanup: None,
                cleanup_dir: None,
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

fn resolve_before_deadline(
    resolver: Arc<dyn ForwardResolver>,
    host: String,
    port: u16,
    deadline: Instant,
) -> io::Result<Vec<std::net::SocketAddr>> {
    ResolverExecutor::global().resolve(resolver, host, port, deadline)
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

#[cfg(unix)]
type ListenerCleanup = (PathBuf, crate::user_socket_ops::UnixSocketIdentity);

pub(crate) struct ForwardListener {
    inner: ListenerKind,
    #[cfg(unix)]
    cleanup: Option<ListenerCleanup>,
    cleanup_dir: Option<PathBuf>,
}

impl ForwardListener {
    /// Also remove this directory when the listener is dropped (used for the
    /// private named-pipe directories created for environment forwards).
    #[cfg(unix)]
    pub(crate) fn also_remove_dir(&mut self, directory: PathBuf) {
        self.cleanup_dir = Some(directory);
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
        if let Some((path, identity)) = self.cleanup.as_ref() {
            crate::user_socket_ops::remove_socket_if_owned(path, *identity);
        }
        if let Some(path) = self.cleanup_dir.as_ref() {
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
    fn unix_source_failure_after_directory_creation_cleans_and_retries() {
        // Given
        let root = std::env::temp_dir().join(format!("et-fwd-dir-{}", std::process::id()));
        let path = root.join("created").join("source.sock");
        let created = path.parent().unwrap().to_path_buf();

        // When
        let error = match bind_unix_source(
            &path,
            None,
            || Err(io::Error::other("injected after directory creation")),
            || Ok(()),
        ) {
            Ok(_) => panic!("injected directory failure succeeded"),
            Err(error) => error,
        };

        // Then
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!created.exists());
        let listeners = bind_unix_source(&path, None, || Ok(()), || Ok(())).unwrap();
        assert!(path.exists());
        drop(listeners);
        assert!(!path.exists());
        assert!(!created.exists());
        let _ = fs::remove_dir(root);
    }

    #[cfg(unix)]
    #[test]
    fn unix_source_failure_after_bind_cleans_socket_and_directory_then_retries() {
        // Given
        let root = std::env::temp_dir().join(format!("et-fwd-bind-{}", std::process::id()));
        let path = root.join("created").join("source.sock");
        let created = path.parent().unwrap().to_path_buf();

        // When
        let error = match bind_unix_source(
            &path,
            None,
            || Ok(()),
            || Err(io::Error::other("injected before final configuration")),
        ) {
            Ok(_) => panic!("injected post-bind failure succeeded"),
            Err(error) => error,
        };

        // Then
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!path.exists());
        assert!(!created.exists());
        let listeners = bind_unix_source(&path, None, || Ok(()), || Ok(())).unwrap();
        assert!(path.exists());
        drop(listeners);
        assert!(!path.exists());
        assert!(!created.exists());
        let _ = fs::remove_dir(root);
    }

    #[cfg(unix)]
    #[test]
    fn unix_source_bind_uses_openssh_default_owner_only_mode() {
        // Given
        let path = std::env::temp_dir().join(format!("et-forward-mode-{}", std::process::id()));
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

    struct BlockingResolver {
        started: std::sync::mpsc::Sender<String>,
        released: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl ForwardResolver for BlockingResolver {
        fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            let _ = self.started.send(host.to_owned());
            if host.starts_with("active-") {
                let (released, changed) = &*self.released;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
            }
            Ok(Vec::new())
        }
    }

    #[test]
    fn expired_queued_resolutions_are_skipped_and_fresh_work_starts() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let released = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let resolver: Arc<dyn ForwardResolver> = Arc::new(BlockingResolver {
            started: started_tx,
            released: released.clone(),
        });
        let mut active = Vec::new();
        for index in 0..crate::forward::RESOLVER_WORKERS {
            let resolver = resolver.clone();
            active.push(std::thread::spawn(move || {
                ResolverExecutor::global().resolve(
                    resolver,
                    format!("active-{index}.test"),
                    1,
                    Instant::now() + Duration::from_secs(5),
                )
            }));
        }
        for _ in 0..crate::forward::RESOLVER_WORKERS {
            assert!(started_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .starts_with("active-"));
        }

        let mut queued = Vec::new();
        for index in 0..crate::forward::RESOLVER_QUEUE_CAPACITY {
            let resolver = resolver.clone();
            queued.push(std::thread::spawn(move || {
                ResolverExecutor::global().resolve(
                    resolver,
                    format!("expired-{index}.test"),
                    1,
                    Instant::now() + Duration::from_millis(100),
                )
            }));
        }
        for caller in queued {
            assert_eq!(
                caller.join().unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert!(
            started_rx.try_recv().is_err(),
            "queued callback ran before release"
        );

        let fresh_resolver = resolver.clone();
        let fresh = std::thread::spawn(move || {
            ResolverExecutor::global().resolve(
                fresh_resolver,
                "fresh.test".to_owned(),
                1,
                Instant::now() + Duration::from_secs(1),
            )
        });
        assert!(
            started_rx.try_recv().is_err(),
            "fresh callback ran while all workers were active"
        );
        let (is_released, changed) = &*released;
        *is_released.lock().unwrap() = true;
        changed.notify_all();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "fresh.test"
        );
        for caller in active {
            caller.join().unwrap().unwrap();
        }
        fresh.join().unwrap().unwrap();
        assert!(
            started_rx.try_recv().is_err(),
            "expired queued resolver callback was invoked"
        );
    }

    struct DelayedResolver(std::net::SocketAddr);

    impl ForwardResolver for DelayedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            std::thread::sleep(Duration::from_millis(200));
            Ok(vec![self.0])
        }
    }

    #[test]
    fn delayed_resolution_times_out_without_late_listener_creation() {
        let probe = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let endpoint = Endpoint::Tcp {
            host: "delayed.valid.test".to_owned(),
            port: address.port(),
        };
        let error = match endpoint.resolve_for_bind_deadline(
            Instant::now() + Duration::from_millis(50),
            Arc::new(DelayedResolver(address)),
        ) {
            Ok(_) => panic!("delayed resolution exceeded its deadline"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(250));
        TcpListener::bind(address).expect("cancelled resolver created a late listener");
    }

    #[cfg(unix)]
    #[test]
    fn old_listener_drop_does_not_unlink_replacement_generation() {
        let directory =
            std::env::temp_dir().join(format!("et-forward-generation-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("source.sock");
        let endpoint = Endpoint::Unix(path.clone());
        let old = endpoint.bind().unwrap();
        std::fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(old);
        let client = UnixStream::connect(&path).expect("old listener unlinked replacement path");
        replacement.accept().unwrap();
        drop(client);
        drop(replacement);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
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
