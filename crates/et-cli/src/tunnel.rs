//! Tunnel argument parsing, matching upstream `TunnelUtils.cpp`
//! (`parseRangesToRequests`, `processEtStyleTunnelArg`, `parseSshTunnelArg`).
//!
//! Supported forms:
//! - `port:port` (comma-separated lists allowed)
//! - `startPort-endPort:startPort-endPort` inclusive ranges
//! - Unix sockets: `/local.sock:/remote.sock`, `8080:/remote.sock`,
//!   `/local.sock:8080`
//! - Named-pipe forwarding through an environment variable: `ENVVAR:name`
//! - ssh-style `-L`/`-R`: `bind_address:port:host:hostport` with IPv6
//!   addresses inside square brackets
//!
//! Wire shape mirrors upstream exactly: plain TCP destinations carry only a
//! port (no name), Unix endpoints carry only a name, and the ssh-style form
//! carries both names verbatim (an empty bind address stays empty).

use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};

pub const MAX_TUNNEL_REQUESTS: usize = 65_535;
const MAX_UNIX_SOCKET_PATH: usize = 107;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelError {
    InvalidSyntax(String),
    InvalidEndpoint(String),
    MismatchedRanges,
    TooManyRequests,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSyntax(value) => write!(formatter, "invalid tunnel syntax: {value}"),
            Self::InvalidEndpoint(value) => write!(formatter, "invalid tunnel endpoint: {value}"),
            Self::MismatchedRanges => {
                write!(formatter, "tunnel port ranges must have equal length")
            }
            Self::TooManyRequests => write!(formatter, "tunnel expands to too many requests"),
        }
    }
}

impl std::error::Error for TunnelError {}

pub fn parse_tunnels(arguments: &[String]) -> Result<Vec<PortForwardSourceRequest>, TunnelError> {
    let mut requests = Vec::new();
    for argument in arguments {
        parse_argument(argument, &mut requests)?;
    }
    Ok(requests)
}

/// One `-t`/`-r` value, mirroring upstream `parseRangesToRequests`: an
/// argument with commas is a list of et-style tunnels; a single argument with
/// three or more colon-separated parts is an ssh-style tunnel.
fn parse_argument(
    argument: &str,
    requests: &mut Vec<PortForwardSourceRequest>,
) -> Result<(), TunnelError> {
    let elements: Vec<&str> = argument.split(',').collect();
    if elements.len() > 1 {
        for element in elements {
            let parts: Vec<&str> = element.split(':').collect();
            parse_et_style(&parts, element, requests)?;
        }
        return Ok(());
    }
    let parts: Vec<&str> = argument.split(':').collect();
    if parts.len() <= 2 {
        parse_et_style(&parts, argument, requests)
    } else {
        parse_ssh_style(argument, requests)
    }
}

/// Upstream `processEtStyleTunnelArg`.
fn parse_et_style(
    parts: &[&str],
    input: &str,
    requests: &mut Vec<PortForwardSourceRequest>,
) -> Result<(), TunnelError> {
    let [source, destination] = match parts {
        [source, destination, ..] => [*source, *destination],
        _ => return Err(TunnelError::InvalidSyntax(input.to_owned())),
    };
    let source_is_socket = source.starts_with('/');
    let source_is_numeric = source
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'-');
    let destination_is_socket = destination.starts_with('/');
    let destination_is_numeric = destination
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'-');

    if source_is_socket || (destination_is_socket && source_is_numeric) {
        let source_endpoint = if source_is_socket {
            unix_endpoint(source)?
        } else {
            tcp_endpoint("localhost", parse_single_port(source)?)
        };
        let destination_endpoint = if destination_is_socket {
            unix_endpoint(destination)?
        } else {
            tcp_port_endpoint(parse_single_port(destination)?)
        };
        return push_request(
            requests,
            PortForwardSourceRequest {
                source: Some(source_endpoint),
                destination: Some(destination_endpoint),
                environmentvariable: None,
            },
        );
    }

    if !source_is_numeric && !destination_is_numeric {
        // Named-pipe forwarding through an environment variable: the source
        // stays unset and is chosen by the remote side.
        return push_request(
            requests,
            PortForwardSourceRequest {
                source: None,
                destination: Some(SocketEndpoint {
                    name: Some(destination.to_owned()),
                    port: None,
                }),
                environmentvariable: Some(source.to_owned()),
            },
        );
    }

    let source_has_range = source.contains('-');
    let destination_has_range = destination.contains('-');
    if source_has_range != destination_has_range {
        return Err(TunnelError::InvalidSyntax(input.to_owned()));
    }
    let source_range = parse_port_range(source)?;
    let destination_range = parse_port_range(destination)?;
    if source_range.count() != destination_range.count() {
        return Err(TunnelError::MismatchedRanges);
    }
    ensure_capacity(requests.len(), source_range.count())?;
    for offset in 0..source_range.count() {
        requests.push(PortForwardSourceRequest {
            source: Some(tcp_endpoint("localhost", source_range.at(offset))),
            destination: Some(tcp_port_endpoint(destination_range.at(offset))),
            environmentvariable: None,
        });
    }
    Ok(())
}

/// Upstream `parseSshTunnelArg`: split on colons outside square brackets and
/// require exactly the four ssh parts `bind_address:port:host:hostport`.
fn parse_ssh_style(
    input: &str,
    requests: &mut Vec<PortForwardSourceRequest>,
) -> Result<(), TunnelError> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_brackets = false;
    for character in input.chars() {
        match character {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            ':' if !in_brackets => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }
    parts.push(current);
    if parts.len() != 4 {
        return Err(TunnelError::InvalidSyntax(input.to_owned()));
    }
    push_request(
        requests,
        PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(parts[0].clone()),
                port: Some(i32::from(parse_single_port(&parts[1])?)),
            }),
            destination: Some(SocketEndpoint {
                name: Some(parts[2].clone()),
                port: Some(i32::from(parse_single_port(&parts[3])?)),
            }),
            environmentvariable: None,
        },
    )
}

fn tcp_endpoint(name: &str, port: u16) -> SocketEndpoint {
    SocketEndpoint {
        name: Some(name.to_owned()),
        port: Some(i32::from(port)),
    }
}

/// Plain TCP destinations carry only the port on the wire, like upstream.
fn tcp_port_endpoint(port: u16) -> SocketEndpoint {
    SocketEndpoint {
        name: None,
        port: Some(i32::from(port)),
    }
}

fn unix_endpoint(path: &str) -> Result<SocketEndpoint, TunnelError> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.len() > MAX_UNIX_SOCKET_PATH
        || path == "/"
    {
        return Err(TunnelError::InvalidEndpoint(path.to_owned()));
    }
    Ok(SocketEndpoint {
        name: Some(path.to_owned()),
        port: None,
    })
}

fn parse_single_port(value: &str) -> Result<u16, TunnelError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| TunnelError::InvalidEndpoint(value.to_owned()))?;
    if port == 0 {
        return Err(TunnelError::InvalidEndpoint(value.to_owned()));
    }
    Ok(port)
}

#[derive(Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn count(self) -> usize {
        usize::from(self.end - self.start) + 1
    }

    fn at(self, offset: usize) -> u16 {
        self.start + u16::try_from(offset).unwrap_or(u16::MAX)
    }
}

fn parse_port_range(value: &str) -> Result<PortRange, TunnelError> {
    let mut parts = value.split('-');
    let start = parse_single_port(parts.next().unwrap_or_default())?;
    let end = match parts.next() {
        Some(raw) => parse_single_port(raw)?,
        None => start,
    };
    if parts.next().is_some() || start > end {
        return Err(TunnelError::InvalidEndpoint(value.to_owned()));
    }
    Ok(PortRange { start, end })
}

fn push_request(
    requests: &mut Vec<PortForwardSourceRequest>,
    request: PortForwardSourceRequest,
) -> Result<(), TunnelError> {
    ensure_capacity(requests.len(), 1)?;
    requests.push(request);
    Ok(())
}

fn ensure_capacity(current: usize, additional: usize) -> Result<(), TunnelError> {
    if current
        .checked_add(additional)
        .is_none_or(|total| total > MAX_TUNNEL_REQUESTS)
    {
        return Err(TunnelError::TooManyRequests);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;
