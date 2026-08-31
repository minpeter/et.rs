use et_core::proto::{ConnectResponse, ConnectStatus, InitialResponse};
use et_net::forward::ForwardOrigin;
use et_net::reverse_report::{encode_skipped_rows, SkipReason, SkippedRow};

use super::{
    accept_initial_response, accept_reconnect_response, accept_response,
    classify_initial_response_error, ensure_initialization_budget,
    initialization_admission_deadline, ReconnectStatus,
};
use crate::deadline::Deadline;
use crate::error::ClientError;
use std::time::Duration;

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
    assert!(matches!(
        ensure_initialization_budget(Deadline::after(Duration::from_secs(9))),
        Err(ClientError::BootstrapTimeout(
            "reserving the ET initialization budget"
        ))
    ));
}

#[test]
fn forwarding_timeout_sentinel_maps_to_bootstrap_timeout_variant() {
    let encoded = et_net::forward::encode_forward_timeout("legacy-readable detail");
    assert_eq!(
        et_net::forward::decode_forward_timeout(&encoded),
        Some("legacy-readable detail")
    );
    assert!(matches!(
        classify_initial_response_error(encoded),
        ClientError::BootstrapTimeout("setting up forwarding")
    ));
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
