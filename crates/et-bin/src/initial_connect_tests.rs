use et_core::proto::{ConnectResponse, ConnectStatus};

use super::{accept_reconnect_response, accept_response, ReconnectStatus};
use crate::error::ClientError;

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
