//! Safe TCP listener construction with separate IPv4 and IPv6 sockets.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

/// Depth of the kernel accept queue passed to `listen(2)`.
///
/// Matches EternalTerminal #798 (`TcpSocketHandler::DEFAULT_LISTEN_BACKLOG`).
/// The previous hardcoded 32 was small enough that a burst of reconnects
/// filled the queue and new clients hung with nothing in the server log.
pub const DEFAULT_LISTEN_BACKLOG: i32 = 128;

/// Historical name for [`DEFAULT_LISTEN_BACKLOG`].
pub const LISTEN_BACKLOG: i32 = DEFAULT_LISTEN_BACKLOG;

/// Apply the #798 fallback: non-positive values are implementation-defined
/// for `listen(2)`, so they become the default instead of being passed through.
pub fn listen_backlog_or_default(backlog: i32) -> i32 {
    if backlog > 0 {
        backlog
    } else {
        DEFAULT_LISTEN_BACKLOG
    }
}

#[derive(Debug)]
pub struct BoundTcpListeners {
    ipv4: Option<TcpListener>,
    ipv6: Option<TcpListener>,
    port: u16,
    listen_backlog: i32,
}

impl BoundTcpListeners {
    pub fn ipv4(&self) -> Option<&TcpListener> {
        self.ipv4.as_ref()
    }

    pub fn ipv6(&self) -> Option<&TcpListener> {
        self.ipv6.as_ref()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept-queue depth actually passed to `listen(2)`.
    pub fn listen_backlog(&self) -> i32 {
        self.listen_backlog
    }

    pub fn iter(&self) -> impl Iterator<Item = &TcpListener> {
        self.ipv4.iter().chain(self.ipv6.iter())
    }

    pub fn into_listeners(self) -> Vec<TcpListener> {
        self.ipv4.into_iter().chain(self.ipv6).collect()
    }
}

#[derive(Debug)]
pub struct ListenerError {
    address: SocketAddr,
    source: io::Error,
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not bind TCP listener at {}: {}",
            self.address, self.source
        )
    }
}

impl std::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub fn bind_tcp(bind_ip: IpAddr, port: u16) -> Result<BoundTcpListeners, ListenerError> {
    bind_tcp_with_backlog(bind_ip, port, DEFAULT_LISTEN_BACKLOG)
}

pub fn bind_tcp_with_backlog(
    bind_ip: IpAddr,
    port: u16,
    backlog: i32,
) -> Result<BoundTcpListeners, ListenerError> {
    let listen_backlog = listen_backlog_or_default(backlog);
    if bind_ip.is_unspecified() {
        return bind_wildcard(port, listen_backlog);
    }

    let address = SocketAddr::new(bind_ip, port);
    let listener = bind_one(address, listen_backlog)?;
    let actual_port = listener
        .local_addr()
        .map_err(|source| ListenerError { address, source })?
        .port();
    let (ipv4, ipv6) = match bind_ip {
        IpAddr::V4(_) => (Some(listener), None),
        IpAddr::V6(_) => (None, Some(listener)),
    };
    Ok(BoundTcpListeners {
        ipv4,
        ipv6,
        port: actual_port,
        listen_backlog,
    })
}

fn bind_wildcard(port: u16, listen_backlog: i32) -> Result<BoundTcpListeners, ListenerError> {
    let ipv4_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let ipv4 = bind_one(ipv4_address, listen_backlog)?;
    let actual_port = ipv4
        .local_addr()
        .map_err(|source| ListenerError {
            address: ipv4_address,
            source,
        })?
        .port();

    let ipv6 = if ipv6_available() {
        Some(bind_one(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), actual_port),
            listen_backlog,
        )?)
    } else {
        None
    };
    Ok(BoundTcpListeners {
        ipv4: Some(ipv4),
        ipv6,
        port: actual_port,
        listen_backlog,
    })
}

fn ipv6_available() -> bool {
    let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    bind_one(address, DEFAULT_LISTEN_BACKLOG).is_ok()
}

fn bind_one(address: SocketAddr, listen_backlog: i32) -> Result<TcpListener, ListenerError> {
    let domain = Domain::for_address(address);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|source| ListenerError { address, source })?;
    socket
        .set_reuse_address(true)
        .map_err(|source| ListenerError { address, source })?;
    if address.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(|source| ListenerError { address, source })?;
    }
    socket
        .bind(&address.into())
        .map_err(|source| ListenerError { address, source })?;
    socket
        .listen(listen_backlog)
        .map_err(|source| ListenerError { address, source })?;
    Ok(socket.into())
}
