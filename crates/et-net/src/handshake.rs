//! Connect handshake: the first unencrypted exchange that negotiates protocol
//! version and assigns session status (NEW_CLIENT / RETURNING_CLIENT /
//! INVALID_KEY / MISMATCHED_PROTOCOL).

use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use et_core::proto::{ConnectRequest, ConnectResponse, ConnectStatus};
use et_core::PROTOCOL_VERSION;

use crate::framing_io::{read_proto_limited, write_proto};

/// Max length for pre-auth / handshake protos (ConnectRequest, ConnectResponse,
/// SequenceHeader). Matches EternalTerminal `MAX_HANDSHAKE_PROTO_LENGTH` from
/// #784 (ANT-2026-5PETM5BV): a large declared length would pin memory on a
/// handler thread before any auth.
pub const MAX_HANDSHAKE_PROTO_LEN: i64 = 4 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn client_request(client_id: &str) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
    }
}

pub fn read_request<R: io::Read>(r: &mut R) -> io::Result<ConnectRequest> {
    read_proto_limited(r, MAX_HANDSHAKE_PROTO_LEN)
}

pub fn read_request_deadline(
    stream: &mut TcpStream,
    deadline: Instant,
) -> io::Result<ConnectRequest> {
    crate::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)
}

pub fn write_response<W: io::Write>(w: &mut W, response: &ConnectResponse) -> io::Result<()> {
    write_proto(w, response)
}

pub fn protocol_matches(req: &ConnectRequest) -> bool {
    req.version == Some(PROTOCOL_VERSION)
}

pub fn response_status(status: ConnectStatus) -> ConnectResponse {
    ConnectResponse {
        status: Some(status as i32),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing_io::{read_proto, write_proto};
    use std::io::Cursor;
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    #[test]
    fn request_carries_protocol_version() {
        let req = client_request("abc123");
        assert_eq!(req.version, Some(6));
        assert_eq!(req.client_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn request_response_roundtrip() {
        let req = client_request("client-7");
        let mut buf = Vec::new();
        write_proto(&mut buf, &req).unwrap();
        let back: ConnectRequest = read_proto(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(back.client_id.as_deref(), Some("client-7"));
    }

    #[test]
    fn version_gate_rejects_mismatch() {
        let good = client_request("x");
        assert!(protocol_matches(&good));
        let bad = ConnectRequest {
            client_id: Some("x".into()),
            version: Some(5),
        };
        assert!(!protocol_matches(&bad));
        let unset = ConnectRequest {
            client_id: Some("x".into()),
            version: None,
        };
        assert!(!protocol_matches(&unset));
    }

    #[test]
    fn oversized_request_is_rejected_before_allocation() {
        for length in [
            MAX_HANDSHAKE_PROTO_LEN + 1,
            64 * 1024 + 1,
            128 * 1024 * 1024,
        ] {
            let error = read_request(&mut Cursor::new(length.to_le_bytes())).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn all_statuses_constructible() {
        let s = [
            ConnectStatus::NewClient,
            ConnectStatus::ReturningClient,
            ConnectStatus::InvalidKey,
            ConnectStatus::MismatchedProtocol,
        ];
        for st in s {
            let r = response_status(st);
            assert_eq!(r.status, Some(st as i32));
        }
    }

    #[test]
    fn request_deadline_expires_before_reading_an_idle_peer() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let connector = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (mut server, _) = listener.accept().unwrap();
        let _client = connector.join().unwrap();
        let error = read_request_deadline(&mut server, Instant::now()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
