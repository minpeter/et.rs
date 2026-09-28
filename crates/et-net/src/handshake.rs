//! Connect handshake: the first unencrypted exchange that negotiates protocol
//! version and assigns session status (NEW_CLIENT / RETURNING_CLIENT /
//! INVALID_KEY / MISMATCHED_PROTOCOL).

use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use et_core::crypto::{
    connection_proof, verify_reset_decision_proof, AUTH_CHALLENGE_BYTES, EPOCH_SALT_BYTES, KEY_LEN,
};
use et_core::proto::{ConnectAuth, ConnectRequest, ConnectResponse, ConnectStatus};
use et_core::PROTOCOL_VERSION;

use crate::framing_io::{read_proto_limited, write_proto};

/// Max length for pre-auth / handshake protos (ConnectRequest, ConnectResponse,
/// SequenceHeader). Matches EternalTerminal `MAX_HANDSHAKE_PROTO_LENGTH` from
/// #784 (ANT-2026-5PETM5BV): a large declared length would pin memory on a
/// handler thread before any auth.
pub const MAX_HANDSHAKE_PROTO_LEN: i64 = 4 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Legacy protocol-6 request. Peers that omit `supportsChallenge` keep the
/// original one-round handshake.
pub fn client_request(client_id: &str) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
        reset_intent: None,
        supports_challenge: None,
    }
}

/// Authenticated handshake. `reset_intent` asks the server to zero sequence
/// history, used when a fresh process resumes a live named session.
pub fn client_request_challenge(client_id: &str, reset_intent: bool) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
        reset_intent: reset_intent.then_some(true),
        supports_challenge: Some(true),
    }
}

pub fn supports_challenge(request: &ConnectRequest) -> bool {
    request.supports_challenge.unwrap_or(false)
}

pub fn reset_intent(request: &ConnectRequest) -> bool {
    supports_challenge(request) && request.reset_intent.unwrap_or(false)
}

/// Write `request`, then complete either the legacy response or the
/// challenge/`ConnectAuth` exchange. A response without `authChallenge` is the
/// protocol-6 legacy handshake and is returned as-is.
pub fn client_handshake(
    stream: &mut TcpStream,
    client_id: &str,
    key: &[u8; KEY_LEN],
    reset_intent: bool,
    deadline: Instant,
) -> io::Result<ConnectResponse> {
    crate::framing_io::write_proto_limited_deadline(
        stream,
        &client_request_challenge(client_id, reset_intent),
        MAX_HANDSHAKE_PROTO_LEN,
        deadline,
    )?;
    let first: ConnectResponse =
        crate::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)?;
    let Some(challenge) = first.auth_challenge.clone() else {
        let mut legacy = first;
        legacy.reset_required = None;
        legacy.reset_salt = None;
        legacy.reset_proof = None;
        return Ok(legacy);
    };
    if challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server sent an invalid authentication challenge",
        ));
    }
    let proof = connection_proof(key, client_id, PROTOCOL_VERSION, &challenge, reset_intent)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not build the connection proof",
            )
        })?;
    crate::framing_io::write_proto_limited_deadline(
        stream,
        &ConnectAuth {
            proof: Some(proof.to_vec()),
        },
        MAX_HANDSHAKE_PROTO_LEN,
        deadline,
    )?;
    let response: ConnectResponse =
        crate::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)?;
    let status = response.status.unwrap_or_default();
    let accepted = status == ConnectStatus::NewClient as i32
        || status == ConnectStatus::ReturningClient as i32;
    if accepted {
        let reset_required = response.reset_required.unwrap_or(false);
        let salt = response.reset_salt.clone().unwrap_or_default();
        if reset_required && salt.len() != EPOCH_SALT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid reset decision salt",
            ));
        }
        let proof_ok = response.reset_proof.as_deref().is_some_and(|proof| {
            verify_reset_decision_proof(
                proof,
                key,
                client_id,
                PROTOCOL_VERSION,
                &challenge,
                status,
                reset_required,
                &salt,
            )
        });
        if !proof_ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connect success is missing a valid reset decision proof",
            ));
        }
    }
    Ok(response)
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
        auth_challenge: None,
        reset_required: None,
        reset_proof: None,
        reset_salt: None,
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
            reset_intent: None,
            supports_challenge: None,
        };
        assert!(!protocol_matches(&bad));
        let unset = ConnectRequest {
            client_id: Some("x".into()),
            version: None,
            reset_intent: None,
            supports_challenge: None,
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
            ConnectStatus::RetryLater,
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
