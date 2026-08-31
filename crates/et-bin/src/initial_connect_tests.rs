use et_core::proto::{ConnectResponse, ConnectStatus, InitialResponse};
use et_net::forward::ForwardOrigin;
use et_net::reverse_report::{encode_skipped_rows, SkipReason, SkippedRow};

use super::{accept_initial_response, accept_reconnect_response, accept_response, ReconnectStatus};
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
fn config_only_skip_report_continues_but_explicit_report_is_fatal() {
    let report = encode_skipped_rows(&[SkippedRow {
        index: 0,
        reason: SkipReason::Bind,
    }])
    .unwrap();

    assert!(accept_initial_response(
        InitialResponse {
            error: Some(report.clone()),
        },
        &[ForwardOrigin::SshConfig { strict: false }],
    )
    .is_ok());
    for origin in [
        ForwardOrigin::Explicit,
        ForwardOrigin::SshConfig { strict: true },
        ForwardOrigin::Reported(0),
    ] {
        assert!(matches!(
            accept_initial_response(
                InitialResponse {
                    error: Some(report.clone()),
                },
                &[origin],
            ),
            Err(ClientError::InitialResponseRejected(message))
                if message == "required reverse forwarding row could not bind"
        ));
    }
}

#[test]
fn old_server_error_and_malformed_reserved_report_fail_closed() {
    assert!(matches!(
        accept_initial_response(
            InitialResponse {
                error: Some("port forwarding I/O: address in use".to_owned()),
            },
            &[ForwardOrigin::SshConfig { strict: false }],
        ),
        Err(ClientError::InitialResponseRejected(_))
    ));
    assert!(matches!(
        accept_initial_response(
            InitialResponse {
                error: Some("ETRS-RF-SKIP/2;0:B".to_owned()),
            },
            &[ForwardOrigin::SshConfig { strict: false }],
        ),
        Err(ClientError::InitialResponseRejected(message))
            if message == "malformed reverse forwarding skip report"
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
