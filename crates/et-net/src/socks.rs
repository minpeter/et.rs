//! SOCKS4/SOCKS5 CONNECT parsing for dynamic (`-D`) forwards.
//!
//! OpenSSH-compatible: SOCKS5 no-auth and SOCKS4/4a CONNECT only. The CONNECT
//! success reply is deferred until the remote destination accepts.

use std::io::{self, Read, Write};
use std::net::Ipv6Addr;

use et_core::proto::SocketEndpoint;

const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CONNECT: u8 = 0x01;
const SOCKS4_GRANTED: u8 = 0x5a;
const SOCKS4_REJECTED: u8 = 0x5b;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NOAUTH: u8 = 0x00;
const SOCKS5_NO_ACCEPTABLE: u8 = 0xff;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_IPV4: u8 = 0x01;
const SOCKS5_DOMAIN: u8 = 0x03;
const SOCKS5_IPV6: u8 = 0x04;
const SOCKS5_SUCCESS: u8 = 0x00;
const SOCKS5_CONN_REFUSED: u8 = 0x05;

const MAX_HANDSHAKE: usize = 4096;
const MAX_IDENT: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocksParseStatus {
    NeedMore,
    Complete,
    Error,
}

#[derive(Debug, Default)]
pub struct SocksHandshake {
    pub input: Vec<u8>,
    pub reply: Vec<u8>,
    pub destination: SocketEndpoint,
    pub error: String,
    socks5_auth_done: bool,
    pub complete: bool,
    pub version: u8,
    pub early_data: Vec<u8>,
}

pub struct CompletedSocks {
    pub destination: SocketEndpoint,
    pub version: u8,
    pub early_data: Vec<u8>,
}

/// CONNECT reply. Success is deferred until the remote destination accepts.
pub fn connect_reply(version: u8, success: bool) -> Vec<u8> {
    if version == SOCKS4_VERSION {
        let mut reply = vec![0u8; 8];
        reply[1] = if success {
            SOCKS4_GRANTED
        } else {
            SOCKS4_REJECTED
        };
        return reply;
    }
    let mut reply = vec![
        SOCKS5_VERSION,
        if success {
            SOCKS5_SUCCESS
        } else {
            SOCKS5_CONN_REFUSED
        },
        0,
        SOCKS5_IPV4,
    ];
    reply.extend_from_slice(&[0u8; 6]);
    reply
}

pub fn feed(state: &mut SocksHandshake) -> SocksParseStatus {
    if state.complete {
        if !state.input.is_empty() {
            state.early_data.append(&mut state.input);
        }
        return SocksParseStatus::Complete;
    }
    if state.input.len() > MAX_HANDSHAKE {
        state.error = "SOCKS handshake too large".to_owned();
        return SocksParseStatus::Error;
    }
    if state.input.is_empty() {
        return SocksParseStatus::NeedMore;
    }
    match state.input[0] {
        SOCKS4_VERSION => parse_socks4(state),
        SOCKS5_VERSION => {
            if !state.socks5_auth_done {
                let status = parse_socks5_auth(state);
                let auth_reply = std::mem::take(&mut state.reply);
                if status == SocksParseStatus::Error {
                    state.reply = auth_reply;
                    return status;
                }
                if state.input.is_empty() {
                    state.reply = auth_reply;
                    return SocksParseStatus::NeedMore;
                }
                let status = parse_socks5_request(state);
                state.reply.splice(0..0, auth_reply);
                return status;
            }
            parse_socks5_request(state)
        }
        _ => {
            state.error = "Unsupported SOCKS version".to_owned();
            SocksParseStatus::Error
        }
    }
}

/// Read a handshake from `stream`, writing any intermediate auth reply.
pub fn read_handshake(stream: &mut (impl Read + Write)) -> io::Result<CompletedSocks> {
    let mut state = SocksHandshake::default();
    let mut buffer = [0u8; 512];
    loop {
        if state.complete {
            return Ok(CompletedSocks {
                destination: state.destination,
                version: state.version,
                early_data: state.early_data,
            });
        }
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            let message = if state.error.is_empty() {
                "SOCKS client closed during handshake"
            } else {
                &state.error
            };
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, message.to_owned()));
        }
        state.input.extend_from_slice(&buffer[..count]);
        let status = feed(&mut state);
        if !state.reply.is_empty() {
            stream.write_all(&state.reply)?;
            state.reply.clear();
        }
        match status {
            SocksParseStatus::NeedMore => {}
            SocksParseStatus::Complete => {
                return Ok(CompletedSocks {
                    destination: state.destination,
                    version: state.version,
                    early_data: state.early_data,
                });
            }
            SocksParseStatus::Error => {
                let message = if state.error.is_empty() {
                    "SOCKS handshake failed"
                } else {
                    &state.error
                };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    message.to_owned(),
                ));
            }
        }
    }
}

pub fn parse_dynamic_forward_arg(input: &str) -> Result<SocketEndpoint, String> {
    if input.is_empty() {
        return Err("Dynamic forward (-D) requires [bind:]port".to_owned());
    }
    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err("Dynamic forward IPv6 bind must look like [::1]:1080".to_owned());
        };
        if host.is_empty() {
            return Err("Dynamic forward IPv6 bind must look like [::1]:1080".to_owned());
        }
        return Ok(SocketEndpoint {
            name: Some(host.to_owned()),
            port: Some(parse_tcp_port(port, input)?),
        });
    }
    match input.rfind(':') {
        None => Ok(SocketEndpoint {
            name: Some("127.0.0.1".to_owned()),
            port: Some(parse_tcp_port(input, input)?),
        }),
        Some(colon) => {
            let mut host = &input[..colon];
            if host.is_empty() {
                host = "0.0.0.0";
            }
            Ok(SocketEndpoint {
                name: Some(host.to_owned()),
                port: Some(parse_tcp_port(&input[colon + 1..], input)?),
            })
        }
    }
}

pub fn parse_stdio_forward_arg(input: &str) -> Result<SocketEndpoint, String> {
    if input.is_empty() {
        return Err("Stdio forward (-W) requires host:port".to_owned());
    }
    if is_socket_path(input) {
        return Ok(SocketEndpoint {
            name: Some(input.to_owned()),
            port: None,
        });
    }
    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err("Stdio forward IPv6 destination must look like [::1]:8080".to_owned());
        };
        if host.is_empty() {
            return Err("Stdio forward IPv6 destination must look like [::1]:8080".to_owned());
        }
        return Ok(SocketEndpoint {
            name: Some(host.to_owned()),
            port: Some(parse_tcp_port(port, input)?),
        });
    }
    let Some(colon) = input.rfind(':') else {
        return Err("Stdio forward (-W) requires host:port or a Unix path".to_owned());
    };
    let host = &input[..colon];
    if host.is_empty() {
        return Err("Stdio forward host must not be empty".to_owned());
    }
    Ok(SocketEndpoint {
        name: Some(host.to_owned()),
        port: Some(parse_tcp_port(&input[colon + 1..], input)?),
    })
}

fn parse_tcp_port(token: &str, context: &str) -> Result<i32, String> {
    if token.is_empty() {
        return Err(format!("Invalid port in {context}"));
    }
    let value: i64 = token
        .parse()
        .map_err(|_| format!("Invalid port in {context}"))?;
    if !(1..=65535).contains(&value) {
        return Err(format!("Invalid port in {context}"));
    }
    Ok(value as i32)
}

fn is_socket_path(value: &str) -> bool {
    value.starts_with('/')
}

fn parse_socks4(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 8 {
        return SocksParseStatus::NeedMore;
    }
    if input[1] != SOCKS4_CONNECT {
        state.error = "SOCKS4 only supports CONNECT".to_owned();
        return SocksParseStatus::Error;
    }
    let port = u16::from_be_bytes([input[2], input[3]]);
    let ip = &input[4..8];
    let socks4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
    let mut userid_end = 8usize;
    while userid_end < input.len() && input[userid_end] != 0 {
        if userid_end - 8 >= MAX_IDENT {
            state.error = "SOCKS4 userid too long".to_owned();
            return SocksParseStatus::Error;
        }
        userid_end += 1;
    }
    if userid_end >= input.len() {
        if input.len() > MAX_IDENT + 8 {
            state.error = "SOCKS4 userid too long".to_owned();
            return SocksParseStatus::Error;
        }
        return SocksParseStatus::NeedMore;
    }
    userid_end += 1;
    let (host, consumed) = if socks4a {
        let mut domain_end = userid_end;
        while domain_end < input.len() && input[domain_end] != 0 {
            if domain_end - userid_end >= MAX_IDENT {
                state.error = "SOCKS4a domain too long".to_owned();
                return SocksParseStatus::Error;
            }
            domain_end += 1;
        }
        if domain_end >= input.len() {
            if input.len() - userid_end > MAX_IDENT {
                state.error = "SOCKS4a domain too long".to_owned();
                return SocksParseStatus::Error;
            }
            return SocksParseStatus::NeedMore;
        }
        let host = String::from_utf8_lossy(&input[userid_end..domain_end]).into_owned();
        (host, domain_end + 1)
    } else {
        (
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            userid_end,
        )
    };
    finish_destination(state, host, port, consumed, SOCKS4_VERSION);
    SocksParseStatus::Complete
}

fn parse_socks5_auth(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 2 {
        return SocksParseStatus::NeedMore;
    }
    let nmethods = input[1] as usize;
    if input.len() < 2 + nmethods {
        return SocksParseStatus::NeedMore;
    }
    let found = input[2..2 + nmethods].contains(&SOCKS5_NOAUTH);
    state.reply.clear();
    state.reply.push(SOCKS5_VERSION);
    if !found {
        state.reply.push(SOCKS5_NO_ACCEPTABLE);
        state.error = "SOCKS5 client did not offer no-auth".to_owned();
        return SocksParseStatus::Error;
    }
    state.reply.push(SOCKS5_NOAUTH);
    state.input.drain(..2 + nmethods);
    state.socks5_auth_done = true;
    SocksParseStatus::NeedMore
}

fn parse_socks5_request(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 4 {
        return SocksParseStatus::NeedMore;
    }
    if input[0] != SOCKS5_VERSION {
        state.error = "Invalid SOCKS5 request version".to_owned();
        return SocksParseStatus::Error;
    }
    if input[1] != SOCKS5_CONNECT {
        state.error = "SOCKS5 only supports CONNECT".to_owned();
        return SocksParseStatus::Error;
    }
    let atyp = input[3];
    let (host, port_offset) = if atyp == SOCKS5_IPV4 {
        if input.len() < 10 {
            return SocksParseStatus::NeedMore;
        }
        let ip = &input[4..8];
        (
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            8usize,
        )
    } else if atyp == SOCKS5_DOMAIN {
        if input.len() < 5 {
            return SocksParseStatus::NeedMore;
        }
        let len = input[4] as usize;
        if input.len() < 5 + len + 2 {
            return SocksParseStatus::NeedMore;
        }
        (
            String::from_utf8_lossy(&input[5..5 + len]).into_owned(),
            5 + len,
        )
    } else if atyp == SOCKS5_IPV6 {
        if input.len() < 22 {
            return SocksParseStatus::NeedMore;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&input[4..20]);
        (Ipv6Addr::from(octets).to_string(), 20usize)
    } else {
        state.error = "Unsupported SOCKS5 address type".to_owned();
        return SocksParseStatus::Error;
    };
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    finish_destination(state, host, port, port_offset + 2, SOCKS5_VERSION);
    SocksParseStatus::Complete
}

fn finish_destination(
    state: &mut SocksHandshake,
    host: String,
    port: u16,
    consumed: usize,
    version: u8,
) {
    if is_socket_path(&host) {
        state.destination = SocketEndpoint {
            name: Some(host),
            port: None,
        };
    } else {
        state.destination = SocketEndpoint {
            name: Some(host),
            port: Some(i32::from(port)),
        };
    }
    state.version = version;
    state.early_data = state.input.split_off(consumed);
    state.input.clear();
    state.complete = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks5_auth() -> Vec<u8> {
        vec![0x05, 0x01, 0x00]
    }

    fn socks5_ipv4(octets: [u8; 4], port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend(octets);
        request.extend(port.to_be_bytes());
        request
    }

    fn socks5_domain(host: &str, port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend(host.as_bytes());
        request.extend(port.to_be_bytes());
        request
    }

    #[test]
    fn dynamic_and_stdio_argument_shapes_match_upstream() {
        let port_only = parse_dynamic_forward_arg("1080").unwrap();
        assert_eq!(port_only.name.as_deref(), Some("127.0.0.1"));
        assert_eq!(port_only.port, Some(1080));
        let bound = parse_dynamic_forward_arg("localhost:9050").unwrap();
        assert_eq!(bound.name.as_deref(), Some("localhost"));
        assert_eq!(bound.port, Some(9050));
        let v6 = parse_dynamic_forward_arg("[::1]:1080").unwrap();
        assert_eq!(v6.name.as_deref(), Some("::1"));
        assert_eq!(v6.port, Some(1080));
        let wildcard = parse_dynamic_forward_arg(":1080").unwrap();
        assert_eq!(wildcard.name.as_deref(), Some("0.0.0.0"));

        let tcp = parse_stdio_forward_arg("example.com:443").unwrap();
        assert_eq!(tcp.name.as_deref(), Some("example.com"));
        assert_eq!(tcp.port, Some(443));
        let unix = parse_stdio_forward_arg("/tmp/remote.sock").unwrap();
        assert_eq!(unix.name.as_deref(), Some("/tmp/remote.sock"));
        assert_eq!(unix.port, None);
        assert!(parse_stdio_forward_arg("onlyhost")
            .unwrap_err()
            .contains("host:port"));
        for bad in ["1080junk", "0", "65536"] {
            assert!(parse_dynamic_forward_arg(bad)
                .unwrap_err()
                .contains("Invalid port"));
        }
        assert!(parse_stdio_forward_arg("example.com:443junk")
            .unwrap_err()
            .contains("Invalid port"));
        assert!(parse_stdio_forward_arg("example.com:0")
            .unwrap_err()
            .contains("Invalid port"));
    }

    #[test]
    fn socks5_ipv4_connect_keeps_auth_reply_and_early_bytes() {
        let mut state = SocksHandshake {
            input: socks5_auth(),
            ..Default::default()
        };
        state.input.extend(socks5_ipv4([127, 0, 0, 1], 8080));
        assert_eq!(feed(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.destination.name.as_deref(), Some("127.0.0.1"));
        assert_eq!(state.destination.port, Some(8080));
        assert_eq!(state.version, 5);
        assert!(state.early_data.is_empty());
        assert_eq!(state.reply, vec![0x05, 0x00]);

        let mut pipelined = SocksHandshake {
            input: socks5_auth(),
            ..Default::default()
        };
        pipelined.input.extend(socks5_ipv4([1, 2, 3, 4], 80));
        pipelined.input.extend(b"EARLY");
        assert_eq!(feed(&mut pipelined), SocksParseStatus::Complete);
        assert_eq!(pipelined.early_data, b"EARLY");
        assert_eq!(pipelined.destination.port, Some(80));
    }

    #[test]
    fn socks5_domain_can_name_a_unix_socket_and_later_bytes_append() {
        let mut state = SocksHandshake {
            input: socks5_auth(),
            ..Default::default()
        };
        assert_eq!(feed(&mut state), SocksParseStatus::NeedMore);
        assert_eq!(state.reply, vec![0x05, 0x00]);
        state.reply.clear();
        state.input = socks5_domain("/tmp/app.sock", 0);
        assert_eq!(feed(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.destination.name.as_deref(), Some("/tmp/app.sock"));
        assert_eq!(state.destination.port, None);

        let mut later = SocksHandshake {
            input: socks5_auth(),
            ..Default::default()
        };
        later.input.extend(socks5_ipv4([1, 2, 3, 4], 80));
        assert_eq!(feed(&mut later), SocksParseStatus::Complete);
        assert!(later.early_data.is_empty());
        later.input = b"LATER".to_vec();
        assert_eq!(feed(&mut later), SocksParseStatus::Complete);
        assert_eq!(later.early_data, b"LATER");
        assert!(later.input.is_empty());
    }

    #[test]
    fn socks4_connect_preserves_trailing_payload_and_rejects_long_userids() {
        let mut state = SocksHandshake {
            input: b"\x04\x01\x00\x50\x01\x02\x03\x04user\x00".to_vec(),
            ..Default::default()
        };
        assert_eq!(feed(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.destination.name.as_deref(), Some("1.2.3.4"));
        assert_eq!(state.destination.port, Some(80));
        assert_eq!(state.version, 4);
        assert!(state.reply.is_empty());

        let mut early = SocksHandshake {
            input: b"\x04\x01\x00\x50\x01\x02\x03\x04user\x00PING".to_vec(),
            ..Default::default()
        };
        assert_eq!(feed(&mut early), SocksParseStatus::Complete);
        assert_eq!(early.early_data, b"PING");

        let mut huge = SocksHandshake {
            input: b"\x04\x01\x00\x50\x01\x02\x03\x04"
                .iter()
                .copied()
                .chain(std::iter::repeat_n(b'u', 300))
                .collect(),
            ..Default::default()
        };
        assert_eq!(feed(&mut huge), SocksParseStatus::Error);
        assert!(huge.error.contains("userid"));
    }

    #[test]
    fn connect_reply_uses_upstream_success_and_failure_bytes() {
        let socks4 = connect_reply(4, true);
        assert_eq!(socks4.len(), 8);
        assert_eq!(socks4[1], 0x5a);
        assert_eq!(connect_reply(4, false)[1], 0x5b);
        let socks5 = connect_reply(5, true);
        assert_eq!(socks5, vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(connect_reply(5, false)[1], 0x05);
    }
}
