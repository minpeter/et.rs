use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

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

    /// Resolve a `PORT_FORWARD_DESTINATION_REQUEST` endpoint with upstream
    /// semantics (`PortForwardHandler::createDestination`): when a port is
    /// present the name is ignored entirely and the connection always goes
    /// to localhost (`::1` first, then `127.0.0.1`); otherwise the name is a
    /// Unix socket path.
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
                Ok(Self::Tcp {
                    host: "localhost".to_owned(),
                    port,
                })
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
                if host == "localhost" || host == "127.0.0.1" || host == "::1" || host.is_empty() {
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
                listener.set_nonblocking(true)?;
                Ok(vec![ForwardListener {
                    inner: ListenerKind::Unix(listener),
                    cleanup: Some(path.clone()),
                    cleanup_dir: None,
                }])
            }
            #[cfg(unix)]
            (Self::Unix(path), None) => {
                if path.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "Unix source socket already exists",
                    ));
                }
                let cleanup_dir = if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent)?;
                        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                        Some(parent.to_path_buf())
                    } else {
                        None
                    }
                } else {
                    None
                };
                let listener = UnixListener::bind(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                listener.set_nonblocking(true)?;
                Ok(vec![ForwardListener {
                    inner: ListenerKind::Unix(listener),
                    cleanup: Some(path.clone()),
                    cleanup_dir,
                }])
            }
        }
    }
}

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
        if let Some(path) = self.cleanup.as_ref() {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = self.cleanup_dir.as_ref() {
            let _ = fs::remove_dir(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
