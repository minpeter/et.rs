//! Connect handshake: the first unencrypted exchange that negotiates protocol
//! version and assigns session status (NEW_CLIENT / RETURNING_CLIENT /
//! INVALID_KEY / MISMATCHED_PROTOCOL).

use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use et_core::crypto::{
    connection_proof, verify_connection_proof, verify_reset_decision_proof, AUTH_CHALLENGE_BYTES,
    EPOCH_SALT_BYTES, KEY_LEN,
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

pub const LEGACY_SERVER_REATTACH: &str =
    "Server does not support session reattach; upgrade etserver";

/// Legacy single-response request. Peers that omit `supportsChallenge` keep
/// the original protocol-6 handshake.
pub fn client_request(client_id: &str) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
        reset_intent: None,
        supports_challenge: None,
    }
}

/// Modern et.rs client. Sets `supportsChallenge` inside protocol 6.
pub fn client_request_modern(client_id: &str, reset_intent: bool) -> ConnectRequest {
    ConnectRequest {
        client_id: Some(client_id.to_string()),
        version: Some(PROTOCOL_VERSION),
        reset_intent: Some(reset_intent),
        supports_challenge: Some(true),
    }
}

pub fn supports_challenge(request: &ConnectRequest) -> bool {
    request.supports_challenge.unwrap_or(false)
}

pub fn reset_intent(request: &ConnectRequest) -> bool {
    supports_challenge(request) && request.reset_intent.unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshake {
    pub status: ConnectStatus,
    pub error: Option<String>,
    pub reset_required: bool,
    pub reset_salt: Vec<u8>,
}

/// Write a modern ConnectRequest and finish the challenge exchange.
///
/// A response without `authChallenge` is the legacy single ConnectResponse.
/// `resetIntent` against that legacy `RETURNING_CLIENT` fails closed.
pub fn client_handshake(
    stream: &mut TcpStream,
    client_id: &str,
    key: &[u8; KEY_LEN],
    reset_intent_flag: bool,
    deadline: Instant,
) -> io::Result<ClientHandshake> {
    write_proto(stream, &client_request_modern(client_id, reset_intent_flag))?;
    let first: ConnectResponse =
        crate::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)?;
    let Some(challenge) = first.auth_challenge.clone() else {
        if reset_intent_flag && first.status == Some(ConnectStatus::ReturningClient as i32) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LEGACY_SERVER_REATTACH,
            ));
        }
        return Ok(status_from_response(first, false));
    };
    if challenge.len() != AUTH_CHALLENGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server sent an invalid authentication challenge",
        ));
    }
    let proof = connection_proof(
        key,
        client_id,
        PROTOCOL_VERSION,
        &challenge,
        reset_intent_flag,
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "could not build connection proof",
        )
    })?;
    write_proto(stream, &ConnectAuth { proof: Some(proof) })?;
    let final_response: ConnectResponse =
        crate::framing_io::read_proto_limited_deadline(stream, MAX_HANDSHAKE_PROTO_LEN, deadline)?;
    let status = final_response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok());
    if matches!(
        status,
        Some(ConnectStatus::NewClient | ConnectStatus::ReturningClient)
    ) {
        let reset_required = final_response.reset_required.unwrap_or(false);
        let salt = final_response.reset_salt.clone().unwrap_or_default();
        if reset_required && salt.len() != EPOCH_SALT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid reset decision salt",
            ));
        }
        let proof = final_response.reset_proof.clone().unwrap_or_default();
        if !verify_reset_decision_proof(
            &proof,
            key,
            client_id,
            PROTOCOL_VERSION,
            &challenge,
            final_response.status.unwrap_or(0),
            reset_required,
            &salt,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Connect success is missing a valid reset decision proof",
            ));
        }
    }
    Ok(status_from_response(final_response, true))
}

fn status_from_response(response: ConnectResponse, challenged: bool) -> ClientHandshake {
    let status = response
        .status
        .and_then(|raw| ConnectStatus::try_from(raw).ok())
        .unwrap_or(ConnectStatus::InvalidKey);
    let reset_required = challenged && response.reset_required.unwrap_or(false);
    let reset_salt = if reset_required {
        response.reset_salt.unwrap_or_default()
    } else {
        Vec::new()
    };
    ClientHandshake {
        status,
        error: response.error,
        reset_required,
        reset_salt,
    }
}

pub fn verify_client_auth(
    auth: &ConnectAuth,
    key: &[u8; KEY_LEN],
    client_id: &str,
    protocol_version: i32,
    challenge: &[u8],
    reset_intent_flag: bool,
) -> bool {
    let Some(proof) = auth.proof.as_deref() else {
        return false;
    };
    verify_connection_proof(
        proof,
        key,
        client_id,
        protocol_version,
        challenge,
        reset_intent_flag,
    )
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
            ..Default::default()
        };
        assert!(!protocol_matches(&bad));
        let unset = ConnectRequest {
            client_id: Some("x".into()),
            version: None,
            ..Default::default()
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
