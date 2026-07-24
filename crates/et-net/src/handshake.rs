//! Connect handshake: the first unencrypted exchange that negotiates protocol
//! version and assigns session status (NEW_CLIENT / RETURNING_CLIENT /
//! INVALID_KEY / MISMATCHED_PROTOCOL).

use std::io;

use et_core::proto::{ConnectRequest, ConnectResponse, ConnectStatus};
use et_core::PROTOCOL_VERSION;

use crate::framing_io::{read_proto, write_proto};

pub fn client_request(client_id: &str) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
    }
}

pub fn read_request<R: io::Read>(r: &mut R) -> io::Result<ConnectRequest> {
    read_proto(r)
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
    use std::io::Cursor;

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
}
