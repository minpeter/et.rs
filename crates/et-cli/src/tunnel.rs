use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};

pub const MAX_TUNNEL_REQUESTS: usize = 1024;
const MAX_UNIX_SOCKET_PATH: usize = 100;

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
        for raw in argument.split(',') {
            let input = raw.trim();
            if input.is_empty() {
                return Err(TunnelError::InvalidSyntax(argument.clone()));
            }
            parse_one(input, &mut requests)?;
        }
    }
    Ok(requests)
}

fn parse_one(input: &str, requests: &mut Vec<PortForwardSourceRequest>) -> Result<(), TunnelError> {
    let parts: Vec<_> = input.split(':').collect();
    match parts.as_slice() {
        [source, destination] => parse_et_style(source, destination, requests),
        [source_name, source_port, destination_name, destination_port] => push_request(
            requests,
            tcp_endpoint(source_name, parse_single_port(source_port)?)?,
            tcp_endpoint(destination_name, parse_single_port(destination_port)?)?,
        ),
        _ => Err(TunnelError::InvalidSyntax(input.to_owned())),
    }
}

fn parse_et_style(
    source: &str,
    destination: &str,
    requests: &mut Vec<PortForwardSourceRequest>,
) -> Result<(), TunnelError> {
    if source.starts_with('/') {
        return push_request(
            requests,
            unix_endpoint(source)?,
            parse_single_endpoint(destination)?,
        );
    }
    if destination.starts_with('/') {
        return push_request(
            requests,
            tcp_endpoint("localhost", parse_single_port(source)?)?,
            unix_endpoint(destination)?,
        );
    }
    let source = parse_port_range(source)?;
    let destination = parse_port_range(destination)?;
    if source.count() != destination.count() {
        return Err(TunnelError::MismatchedRanges);
    }
    ensure_capacity(requests.len(), source.count())?;
    for offset in 0..source.count() {
        requests.push(PortForwardSourceRequest {
            source: Some(tcp_endpoint("localhost", source.at(offset))?),
            destination: Some(tcp_endpoint("localhost", destination.at(offset))?),
            environmentvariable: None,
        });
    }
    Ok(())
}

fn parse_single_endpoint(value: &str) -> Result<SocketEndpoint, TunnelError> {
    if value.starts_with('/') {
        unix_endpoint(value)
    } else {
        tcp_endpoint("localhost", parse_single_port(value)?)
    }
}

fn tcp_endpoint(name: &str, port: u16) -> Result<SocketEndpoint, TunnelError> {
    if name.is_empty() || name.contains('\0') || name.chars().any(char::is_whitespace) {
        return Err(TunnelError::InvalidEndpoint(name.to_owned()));
    }
    Ok(SocketEndpoint {
        name: Some(name.to_owned()),
        port: Some(i32::from(port)),
    })
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
    let range = parse_port_range(value)?;
    if range.count() != 1 {
        return Err(TunnelError::InvalidEndpoint(value.to_owned()));
    }
    Ok(range.start)
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
    let start = parse_port(parts.next().unwrap_or_default(), value)?;
    let end = match parts.next() {
        Some(raw) => parse_port(raw, value)?,
        None => start,
    };
    if parts.next().is_some() || start > end {
        return Err(TunnelError::InvalidEndpoint(value.to_owned()));
    }
    Ok(PortRange { start, end })
}

fn parse_port(raw: &str, original: &str) -> Result<u16, TunnelError> {
    let port = raw
        .parse::<u16>()
        .map_err(|_| TunnelError::InvalidEndpoint(original.to_owned()))?;
    if port == 0 {
        return Err(TunnelError::InvalidEndpoint(original.to_owned()));
    }
    Ok(port)
}

fn push_request(
    requests: &mut Vec<PortForwardSourceRequest>,
    source: SocketEndpoint,
    destination: SocketEndpoint,
) -> Result<(), TunnelError> {
    ensure_capacity(requests.len(), 1)?;
    requests.push(PortForwardSourceRequest {
        source: Some(source),
        destination: Some(destination),
        environmentvariable: None,
    });
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
