use std::net::{Ipv4Addr, TcpListener, TcpStream};

use et_core::crypto::KEY_LEN;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::connection::{ConnError, Connection, WritePacketError};
use prost::Message;

use super::{
    command_payload, recover_initial_transport, recover_transport, write_owned_recovering_with,
    OwnedWriteOutcome, TerminalModeState, TerminalReset, GRACEFUL_TERMINAL_MODE_RESET,
    TERMINAL_MODE_RESET,
};
use crate::client_terminal::{connection_ended, RemoteLines};
use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

#[test]
fn command_exit_suffix_matches_no_exit_flag_and_remote_shell() {
    for (lines, no_exit, expected) in [
        (RemoteLines::Posix, false, b"printf ok; exit\n".as_slice()),
        (RemoteLines::Posix, true, b"printf ok\n".as_slice()),
        // cmd.exe needs `&` and CRLF, otherwise the line is never executed.
        (RemoteLines::Cmd, false, b"printf ok & exit\r\n".as_slice()),
        (RemoteLines::Cmd, true, b"printf ok\r\n".as_slice()),
    ] {
        let payload = command_payload("printf ok", no_exit, lines).unwrap();
        assert_eq!(
            TerminalBuffer::decode(payload.as_slice())
                .unwrap()
                .buffer
                .as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn before_replay_client_write_retries_plaintext_once_after_recovery() {
    let (stream, _peer) = tcp_pair();
    let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
    let payload = command_payload("echo once", false, RemoteLines::Posix).unwrap();
    let mut writes = 0;
    let mut recoveries = 0;
    let outcome = write_owned_recovering_with(
        &mut connection,
        TerminalPacketType::TerminalBuffer as u8,
        &payload,
        &mut |_| {
            recoveries += 1;
            Ok(ReconnectOutcome::Recovered)
        },
        false,
        |_, _, actual| {
            writes += 1;
            assert_eq!(actual, payload);
            if writes == 1 {
                Err(WritePacketError::BeforeReplay(ConnError::Io(
                    std::io::ErrorKind::ConnectionReset.into(),
                )))
            } else {
                Ok(())
            }
        },
    )
    .unwrap();

    assert!(matches!(outcome, OwnedWriteOutcome::Recovered));
    assert_eq!((writes, recoveries), (2, 1));
}

#[test]
fn replay_owned_client_write_recovers_without_plaintext_retry() {
    let (stream, _peer) = tcp_pair();
    let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
    let payload = TerminalBuffer {
        buffer: Some(b"input-once".to_vec()),
    }
    .encode_to_vec();
    let mut writes = 0;
    let mut recoveries = 0;
    let outcome = write_owned_recovering_with(
        &mut connection,
        TerminalPacketType::TerminalBuffer as u8,
        &payload,
        &mut |_| {
            recoveries += 1;
            Ok(ReconnectOutcome::Recovered)
        },
        false,
        |_, _, _| {
            writes += 1;
            Err(WritePacketError::ReplayOwned(ConnError::Io(
                std::io::ErrorKind::ConnectionReset.into(),
            )))
        },
    )
    .unwrap();

    assert!(matches!(outcome, OwnedWriteOutcome::Recovered));
    assert_eq!((writes, recoveries), (1, 1));
}

#[test]
fn every_socket_error_reconnects_including_sleep_timeout() {
    // macOS reports a stale post-sleep TCP flow as ETIMEDOUT (os error 60).
    // It must not become `terminal transport: io: Operation timed out`.
    for kind in [
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::HostUnreachable,
        std::io::ErrorKind::NetworkUnreachable,
    ] {
        assert!(connection_ended(&ConnError::Io(kind.into())), "{kind:?}");
    }
    assert!(!connection_ended(&ConnError::Backpressure));
}

#[test]
fn initial_socket_timeout_enters_recovery_instead_of_exiting() {
    let (stream, _peer) = tcp_pair();
    let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
    let mut attempts = 0;
    let recovered = recover_initial_transport(
        &mut connection,
        &mut |_| {
            attempts += 1;
            Ok(ReconnectOutcome::SessionEnded)
        },
        true,
        Err(ClientError::Transport(ConnError::Io(
            std::io::ErrorKind::TimedOut.into(),
        ))),
    )
    .unwrap();
    assert!(!recovered);
    assert_eq!(attempts, 1);
}

#[test]
fn recovery_rechecks_terminal_setup_before_returning_to_the_pump() {
    let (stream, _peer) = tcp_pair();
    let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
    let mut attempts = 0;
    let recovered = recover_transport(
        &mut connection,
        &mut |_| {
            attempts += 1;
            Ok(ReconnectOutcome::Recovered)
        },
        true,
    )
    .unwrap();
    // Unit-test stdout is not a TTY, so the terminal-size operation is a
    // successful no-op. The important invariant is that recovery owns that
    // operation before it declares the socket usable to the pump.
    assert!(recovered);
    assert_eq!(attempts, 1);
}

#[test]
fn abrupt_terminal_mode_reset_leaves_the_alternate_screen() {
    assert!(TERMINAL_MODE_RESET
        .windows(b"\x1b[?1049l".len())
        .any(|window| window == b"\x1b[?1049l"));
}

#[test]
fn graceful_terminal_mode_reset_keeps_the_main_screen() {
    assert!(!GRACEFUL_TERMINAL_MODE_RESET
        .windows(b"\x1b[?1049l".len())
        .any(|window| window == b"\x1b[?1049l"));
    for sequence in [
        b"\x1b[<64u".as_slice(),
        b"\x1b[=0;1u".as_slice(),
        b"\x1b[>4;0m".as_slice(),
        b"\x1b[?2004l".as_slice(),
        b"\x1b[?1004l".as_slice(),
        b"\x1b[?1000l".as_slice(),
        b"\x1b[?1002l".as_slice(),
        b"\x1b[?1003l".as_slice(),
        b"\x1b[?1006l".as_slice(),
        b"\x1b[?25h".as_slice(),
    ] {
        assert!(GRACEFUL_TERMINAL_MODE_RESET
            .windows(sequence.len())
            .any(|window| window == sequence));
    }
}

#[test]
fn observed_alternate_screen_selects_graceful_or_abrupt_reset() {
    assert_eq!(
        TerminalReset::for_alternate_screen(false),
        TerminalReset::KeepCurrentScreen
    );
    assert_eq!(
        TerminalReset::for_alternate_screen(true),
        TerminalReset::LeaveAlternate
    );
}

#[test]
fn alternate_screen_tracking_handles_split_enter_and_leave_sequences() {
    let modes = TerminalModeState::default();
    modes.observe(b"before\x1b[?10");
    assert!(!modes.alternate_screen());
    modes.observe(b"49hinside");
    assert!(modes.alternate_screen());
    modes.observe(b"\x1b[?104");
    assert!(modes.alternate_screen());
    modes.observe(b"9lafter");
    assert!(!modes.alternate_screen());
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}
