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
        let name = endpoint
            .name
            .filter(|name| !name.is_empty() && !name.contains('\0'))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "endpoint name is invalid")
            })?;
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
                Ok(Self::Tcp { host: name, port })
            }
            None if name.starts_with('/') => Ok(Self::Unix(PathBuf::from(name))),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix endpoint path must be absolute",
            )),
        }
    }

    pub(crate) fn connect(&self) -> io::Result<ForwardStream> {
        match self {
            Self::Tcp { host, port } => {
                // Keep family aligned with bind(): "localhost" is IPv4 loopback only.
                // Preferring getaddrinfo order can try ::1 first and fail against a
                // 127.0.0.1 listener (or race the wrong family under load).
                if host == "localhost" || host == "127.0.0.1" {
                    let address =
                        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, *port));
                    return TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
                        .map(ForwardStream::Tcp);
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

    pub(crate) fn to_proto(&self) -> SocketEndpoint {
        match self {
            Self::Tcp { host, port } => SocketEndpoint {
                name: Some(host.clone()),
                port: Some(i32::from(*port)),
            },
            Self::Unix(path) => SocketEndpoint {
                name: Some(path.to_string_lossy().into_owned()),
                port: None,
            },
        }
    }

    pub(crate) fn bind(&self) -> io::Result<ForwardListener> {
        match self {
            Self::Tcp { host, port } => {
                let listener = if host == "localhost" {
                    TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, *port))?
                } else {
                    TcpListener::bind((host.as_str(), *port))?
                };
                listener.set_nonblocking(true)?;
                Ok(ForwardListener {
                    inner: ListenerKind::Tcp(listener),
                    cleanup: None,
                    cleanup_dir: None,
                })
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
                Ok(ForwardListener {
                    inner: ListenerKind::Unix(listener),
                    cleanup: Some(path.clone()),
                    cleanup_dir,
                })
            }
        }
    }
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
