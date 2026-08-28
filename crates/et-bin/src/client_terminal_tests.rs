use std::net::{Ipv4Addr, TcpListener, TcpStream};

use et_core::crypto::KEY_LEN;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::connection::{ConnError, Connection};
use prost::Message;

use super::{
    recover_initial_transport, recover_transport, send_command, TerminalModeState, TerminalReset,
    GRACEFUL_TERMINAL_MODE_RESET, TERMINAL_MODE_RESET,
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
        let (client_stream, server_stream) = tcp_pair();
        let key = [7u8; KEY_LEN];
        let worker = std::thread::spawn(move || {
            let mut server = Connection::new_server(server_stream, &key);
            server.read_packet().unwrap()
        });
        let mut client = Connection::new_client(client_stream, &key);
        send_command(&mut client, "printf ok", no_exit, lines).unwrap();
        let packet = worker.join().unwrap();
        assert_eq!(packet.header(), TerminalPacketType::TerminalBuffer as u8);
        assert_eq!(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .as_deref(),
            Some(expected)
        );
    }
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
    let mut modes = TerminalModeState::default();
    modes.observe(b"before\x1b[?10");
    assert!(!modes.alternate_screen);
    modes.observe(b"49hinside");
    assert!(modes.alternate_screen);
    modes.observe(b"\x1b[?104");
    assert!(modes.alternate_screen);
    modes.observe(b"9lafter");
    assert!(!modes.alternate_screen);
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}
