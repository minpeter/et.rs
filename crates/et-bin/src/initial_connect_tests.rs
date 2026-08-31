use super::{accept_initial_response, accept_reconnect_response, accept_response, ReconnectStatus};
use crate::error::ClientError;
use et_core::proto::{ConnectResponse, ConnectStatus, InitialResponse};

#[test]
fn initial_response_without_error_is_accepted() {
    assert!(accept_initial_response(InitialResponse { error: None }).is_ok());
}

#[test]
fn every_initial_response_error_is_fatal() {
    for message in [
        "reverse forwarding failed",
        "ETRS-RF-SKIP/1 0 13",
        "anything else",
    ] {
        assert!(matches!(
            accept_initial_response(InitialResponse {
                error: Some(message.to_owned()),
            }),
            Err(ClientError::InitialResponseRejected(error)) if error == message
        ));
    }
}

#[test]
fn fresh_bootstrap_rejects_returning_status() {
    let response = ConnectResponse {
        status: Some(ConnectStatus::ReturningClient as i32),
        error: None,
    };
    assert!(matches!(
        accept_response(response),
        Err(ClientError::ReturningSessionRequiresRecovery)
    ));
}

#[test]
fn reconnect_accepts_only_returning_or_ended_sessions() {
    assert_eq!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::ReturningClient as i32),
            error: None,
        })
        .unwrap(),
        ReconnectStatus::Recover
    );
    assert_eq!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::InvalidKey as i32),
            error: None,
        })
        .unwrap(),
        ReconnectStatus::SessionEnded
    );
    assert!(matches!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::NewClient as i32),
            error: None,
        }),
        Err(ClientError::ServerRejected { .. })
    ));
    assert!(matches!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::MismatchedProtocol as i32),
            error: Some("wrong".to_owned()),
        }),
        Err(ClientError::ProtocolMismatch(_))
    ));
}
