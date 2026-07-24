//! Safe TCP listener construction with separate IPv4 and IPv6 sockets.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

pub const LISTEN_BACKLOG: i32 = 32;

#[derive(Debug)]
pub struct BoundTcpListeners {
    ipv4: Option<TcpListener>,
    ipv6: Option<TcpListener>,
    port: u16,
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
    if bind_ip.is_unspecified() {
        return bind_wildcard(port);
    }

    let address = SocketAddr::new(bind_ip, port);
    let listener = bind_one(address)?;
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
    })
}

fn bind_wildcard(port: u16) -> Result<BoundTcpListeners, ListenerError> {
    let ipv4_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let ipv4 = bind_one(ipv4_address)?;
    let actual_port = ipv4
        .local_addr()
        .map_err(|source| ListenerError {
            address: ipv4_address,
            source,
        })?
        .port();

    let ipv6 = if ipv6_available() {
        Some(bind_one(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            actual_port,
        ))?)
    } else {
        None
    };
    Ok(BoundTcpListeners {
        ipv4: Some(ipv4),
        ipv6,
        port: actual_port,
    })
}

fn ipv6_available() -> bool {
    let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    bind_one(address).is_ok()
}

fn bind_one(address: SocketAddr) -> Result<TcpListener, ListenerError> {
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
        .listen(LISTEN_BACKLOG)
        .map_err(|source| ListenerError { address, source })?;
    Ok(socket.into())
}
