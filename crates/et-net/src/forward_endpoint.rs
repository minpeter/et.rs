use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use et_core::proto::SocketEndpoint;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    Tcp { host: String, port: u16 },
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
                let host = name.filter(|name| !name.is_empty());
                Ok(Self::Tcp {
                    host: host.unwrap_or_else(|| "localhost".to_owned()),
                    port,
                })
            }
            None => match name {
                Some(name) if name.starts_with('/') => Ok(Self::Unix(PathBuf::from(name))),
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
                Ok(Self::Unix(PathBuf::from(name)))
            }
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
            Self::Unix(path) => UnixStream::connect(path).map(ForwardStream::Unix),
        }
    }

    pub(crate) fn bind(&self) -> io::Result<Vec<ForwardListener>> {
        match self {
            Self::Tcp { host, port } => {
                // Mirror upstream `TcpSocketHandler::listen`: resolve the bind
                // name with getaddrinfo semantics and bind every distinct
                // address ("localhost" usually yields both ::1 and 127.0.0.1;
                // an empty name binds the wildcard addresses).
                let addresses: Vec<std::net::SocketAddr> = if host.is_empty() {
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
                let mut listeners = Vec::new();
                let mut last_error = None;
                for address in addresses {
                    match bind_tcp_single_family(address) {
                        Ok(listener) => listeners.push(ForwardListener {
                            inner: ListenerKind::Tcp(listener),
                            cleanup: None,
                            cleanup_dir: None,
                        }),
                        Err(error) => last_error = Some(error),
                    }
                }
                if listeners.is_empty() {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "endpoint did not resolve")
                    }));
                }
                Ok(listeners)
            }
            Self::Unix(path) => {
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

/// Bind one TCP listener for exactly one address family, mirroring upstream
/// `TcpSocketHandler::listen` (which sets `IPV6_V6ONLY` and binds each
/// resolved address separately).
fn bind_tcp_single_family(address: std::net::SocketAddr) -> io::Result<TcpListener> {
    let domain = if address.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(128)?;
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(crate) enum ForwardStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl ForwardStream {
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
        }
    }

    pub(crate) fn shutdown(&self) {
        let _ = match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Self::Unix(stream) => stream.shutdown(Shutdown::Both),
        };
    }
}

impl Read for ForwardStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
        }
    }
}

impl Write for ForwardStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Unix(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Unix(stream) => stream.flush(),
        }
    }
}

enum ListenerKind {
    Tcp(TcpListener),
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
    pub(crate) fn also_remove_dir(&mut self, directory: PathBuf) {
        self.cleanup_dir = Some(directory);
    }

    pub(crate) fn accept(&self) -> io::Result<ForwardStream> {
        let stream = match &self.inner {
            ListenerKind::Tcp(listener) => listener.accept().map(|(stream, _)| {
                let _ = stream.set_nonblocking(false);
                ForwardStream::Tcp(stream)
            }),
            ListenerKind::Unix(listener) => listener.accept().map(|(stream, _)| {
                let _ = stream.set_nonblocking(false);
                ForwardStream::Unix(stream)
            }),
        }?;
        Ok(stream)
    }
}

impl AsFd for ForwardListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
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
