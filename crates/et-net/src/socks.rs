//! SOCKS4/SOCKS5 CONNECT parsing for `et -D`, matching EternalTerminal #849.
//!
//! OpenSSH-compatible: SOCKS5 no-auth and SOCKS4/4a CONNECT only. Bytes that
//! arrive with or after the CONNECT request are `early_data` and must be
//! forwarded once the remote destination accepts.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocksParseStatus {
    NeedMore,
    Complete,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct SocksHandshake {
    pub(crate) input: Vec<u8>,
    pub(crate) reply: Vec<u8>,
    pub(crate) destination: SocketEndpoint,
    pub(crate) error: Option<&'static str>,
    socks5_auth_done: bool,
    pub(crate) complete: bool,
    pub(crate) version: u8,
    pub(crate) early_data: Vec<u8>,
}

impl SocksHandshake {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.input.extend_from_slice(bytes);
    }
}

/// CONNECT reply. Success is deferred until the remote destination accepts.
pub(crate) fn socks_connect_reply(version: u8, success: bool) -> Vec<u8> {
    if version == SOCKS4_VERSION {
        let mut reply = vec![0; 8];
        reply[1] = if success {
            SOCKS4_GRANTED
        } else {
            SOCKS4_REJECTED
        };
        return reply;
    }
    let mut reply = Vec::with_capacity(10);
    reply.push(SOCKS5_VERSION);
    reply.push(if success {
        SOCKS5_SUCCESS
    } else {
        SOCKS5_CONN_REFUSED
    });
    reply.push(0);
    reply.push(SOCKS5_IPV4);
    reply.extend_from_slice(&[0; 6]);
    reply
}

pub(crate) fn feed_socks_handshake(state: &mut SocksHandshake) -> SocksParseStatus {
    if state.complete {
        // Bytes may arrive after CONNECT while the fd is still awaiting the
        // destination response. Preserve them for forwarding.
        if !state.input.is_empty() {
            state.early_data.append(&mut state.input);
        }
        return SocksParseStatus::Complete;
    }
    if state.input.len() > MAX_HANDSHAKE {
        state.error = Some("SOCKS handshake too large");
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
                let mut reply = auth_reply;
                reply.append(&mut state.reply);
                state.reply = reply;
                return status;
            }
            parse_socks5_request(state)
        }
        _ => {
            state.error = Some("Unsupported SOCKS version");
            SocksParseStatus::Error
        }
    }
}

fn parse_socks4(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 8 {
        return SocksParseStatus::NeedMore;
    }
    if input[1] != SOCKS4_CONNECT {
        state.error = Some("SOCKS4 only supports CONNECT");
        return SocksParseStatus::Error;
    }
    let port = u16::from_be_bytes([input[2], input[3]]);
    let ip = &input[4..8];
    let socks4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
    let mut userid_end = 8usize;
    while userid_end < input.len() && input[userid_end] != 0 {
        if userid_end - 8 >= MAX_IDENT {
            state.error = Some("SOCKS4 userid too long");
            return SocksParseStatus::Error;
        }
        userid_end += 1;
    }
    if userid_end >= input.len() {
        if input.len() > MAX_IDENT + 8 {
            state.error = Some("SOCKS4 userid too long");
            return SocksParseStatus::Error;
        }
        return SocksParseStatus::NeedMore;
    }
    userid_end += 1;
    let (host, consumed) = if socks4a {
        let mut domain_end = userid_end;
        while domain_end < input.len() && input[domain_end] != 0 {
            if domain_end - userid_end >= MAX_IDENT {
                state.error = Some("SOCKS4a domain too long");
                return SocksParseStatus::Error;
            }
            domain_end += 1;
        }
        if domain_end >= input.len() {
            if input.len() - userid_end > MAX_IDENT {
                state.error = Some("SOCKS4a domain too long");
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
    finish_destination(state, host, port, SOCKS4_VERSION, consumed)
}

fn parse_socks5_auth(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 2 {
        return SocksParseStatus::NeedMore;
    }
    let methods = usize::from(input[1]);
    if input.len() < 2 + methods {
        return SocksParseStatus::NeedMore;
    }
    let found = input[2..2 + methods].contains(&SOCKS5_NOAUTH);
    state.reply.clear();
    state.reply.push(SOCKS5_VERSION);
    if !found {
        state.reply.push(SOCKS5_NO_ACCEPTABLE);
        state.error = Some("SOCKS5 client did not offer no-auth");
        return SocksParseStatus::Error;
    }
    state.reply.push(SOCKS5_NOAUTH);
    state.input.drain(..2 + methods);
    state.socks5_auth_done = true;
    SocksParseStatus::NeedMore
}

fn parse_socks5_request(state: &mut SocksHandshake) -> SocksParseStatus {
    let input = &state.input;
    if input.len() < 4 {
        return SocksParseStatus::NeedMore;
    }
    if input[0] != SOCKS5_VERSION {
        state.error = Some("Invalid SOCKS5 request version");
        return SocksParseStatus::Error;
    }
    if input[1] != SOCKS5_CONNECT {
        state.error = Some("SOCKS5 only supports CONNECT");
        return SocksParseStatus::Error;
    }
    let atyp = input[3];
    let (host, port_offset) = if atyp == SOCKS5_IPV4 {
        if input.len() < 10 {
            return SocksParseStatus::NeedMore;
        }
        let ip = &input[4..8];
        (format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), 8usize)
    } else if atyp == SOCKS5_DOMAIN {
        if input.len() < 5 {
            return SocksParseStatus::NeedMore;
        }
        let len = usize::from(input[4]);
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
        (std::net::Ipv6Addr::from(octets).to_string(), 20usize)
    } else {
        state.error = Some("Unsupported SOCKS5 address type");
        return SocksParseStatus::Error;
    };
    if input.len() < port_offset + 2 {
        return SocksParseStatus::NeedMore;
    }
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    finish_destination(state, host, port, SOCKS5_VERSION, port_offset + 2)
}

fn finish_destination(
    state: &mut SocksHandshake,
    host: String,
    port: u16,
    version: u8,
    consumed: usize,
) -> SocksParseStatus {
    if host.starts_with('/') {
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
    SocksParseStatus::Complete
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_pipelined_connect_keeps_bytes_after_the_request() {
        let mut state = SocksHandshake::default();
        // Auth methods (no-auth) plus a domain CONNECT for example.com:80,
        // followed by HTTP bytes that arrived in the same buffer.
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&[0x00, 80]);
        bytes.extend_from_slice(b"GET / HTTP/1.0\r\n");
        state.push(&bytes);
        assert_eq!(feed_socks_handshake(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.reply, vec![0x05, 0x00]);
        assert_eq!(state.destination.name.as_deref(), Some("example.com"));
        assert_eq!(state.destination.port, Some(80));
        assert_eq!(state.early_data, b"GET / HTTP/1.0\r\n");
        // A later read while still awaiting the destination response is kept.
        state.push(b"more");
        assert_eq!(feed_socks_handshake(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.early_data, b"GET / HTTP/1.0\r\nmore");
    }

    #[test]
    fn socks4a_connect_parses_the_domain() {
        let mut state = SocksHandshake::default();
        let mut bytes = vec![0x04, 0x01, 0x00, 22, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(b"example.com");
        bytes.push(0);
        state.push(&bytes);
        assert_eq!(feed_socks_handshake(&mut state), SocksParseStatus::Complete);
        assert_eq!(state.version, SOCKS4_VERSION);
        assert_eq!(state.destination.name.as_deref(), Some("example.com"));
        assert_eq!(state.destination.port, Some(22));
        assert!(state.early_data.is_empty());
    }

    #[test]
    fn connect_replies_match_upstream_lengths() {
        assert_eq!(socks_connect_reply(SOCKS4_VERSION, true)[1], SOCKS4_GRANTED);
        assert_eq!(
            socks_connect_reply(SOCKS5_VERSION, false),
            vec![5, SOCKS5_CONN_REFUSED, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }
}
