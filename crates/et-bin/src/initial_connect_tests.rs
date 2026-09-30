use std::time::Duration;

use et_core::proto::{ConnectResponse, ConnectStatus, InitialResponse};

use super::{
    accept_initial_response, accept_reconnect_response, accept_response,
    initialization_admission_deadline, ReconnectStatus,
};
use crate::deadline::Deadline;
use crate::error::ClientError;

#[test]
fn expired_handshake_deadline_keeps_the_os_error_detail() {
    let error = super::connect_error(
        Deadline::after(Duration::ZERO),
        "completing the ET handshake",
        std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset detail"),
    );
    assert_eq!(error.to_string(), "ET connection failed while completing the ET handshake: Operation timed out: peer reset detail");
    assert!(error.is_retryable_initial_connect());
}

#[test]
fn short_outer_budget_is_rejected_before_connection_admission() {
    assert!(matches!(
        initialization_admission_deadline(Deadline::after(Duration::from_secs(3))),
        Err(ClientError::BootstrapTimeout(
            "reserving the ET initialization budget"
        ))
    ));
    let outer = Deadline::after(Duration::from_secs(10));
    let admission = initialization_admission_deadline(outer).unwrap();
    assert!(admission.expires_at() < outer.expires_at());
}

#[test]
fn initial_response_without_error_is_accepted() {
    assert!(accept_initial_response(InitialResponse { error: None }).is_ok());
}

#[test]
fn every_non_timeout_initial_response_error_is_fatal() {
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
fn forwarding_timeout_uses_bootstrap_timeout_classification() {
    let message = et_net::forward::encode_forward_timeout("deadline elapsed");
    assert!(matches!(
        accept_initial_response(InitialResponse {
            error: Some(message),
        }),
        Err(ClientError::BootstrapTimeout("setting up forwarding"))
    ));
}

#[test]
fn fresh_bootstrap_rejects_returning_status() {
    let response = ConnectResponse {
        status: Some(ConnectStatus::ReturningClient as i32),
        error: None,
        auth_challenge: None,
        reset_proof: None,
        reset_required: None,
        reset_salt: None,
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
            auth_challenge: None,
            reset_proof: None,
            reset_required: None,
            reset_salt: None,
        })
        .unwrap(),
        ReconnectStatus::Recover { salt: None }
    );
    assert_eq!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::InvalidKey as i32),
            error: None,
            auth_challenge: None,
            reset_proof: None,
            reset_required: None,
            reset_salt: None,
        })
        .unwrap(),
        ReconnectStatus::SessionEnded
    );
    assert!(matches!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::NewClient as i32),
            error: None,
            auth_challenge: None,
            reset_proof: None,
            reset_required: None,
            reset_salt: None,
        }),
        Err(ClientError::ServerRejected { .. })
    ));
    assert!(matches!(
        accept_reconnect_response(ConnectResponse {
            status: Some(ConnectStatus::MismatchedProtocol as i32),
            error: Some("wrong".to_owned()),
            auth_challenge: None,
            reset_proof: None,
            reset_required: None,
            reset_salt: None,
        }),
        Err(ClientError::ProtocolMismatch(_))
    ));
}
