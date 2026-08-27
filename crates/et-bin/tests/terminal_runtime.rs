#![forbid(unsafe_code)]

#[path = "terminal_runtime_support/mod.rs"]
mod terminal_runtime_support;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{
    TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType, TerminalUserInfo,
};
use et_net::local_packet::{read_local_packet, write_local_packet};
use prost::Message;
use terminal_runtime_support::{
    collect_until, contains, read_line_timeout, write_credentials, Fixture, LOGIN_COLOR_MARKER,
    NON_LOGIN_MARKER,
};
use wait_timeout::ChildExt;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn bootstrap_parent_reports_marker_and_leaves_registered_session_running() {
    let fixture = Fixture::new("bootstrap-parent");
    let mut parent = fixture.spawn_parent();
    write_credentials(&mut parent);
    let (mut router, _) = fixture.listener.accept().unwrap();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = read_local_packet(&mut router).unwrap();
    assert_eq!(
        registration.header(),
        TerminalPacketType::TerminalUserInfo as u8
    );
    assert_eq!(
        read_line_timeout(parent.stdout.take().unwrap()),
        format!("IDPASSKEY:{ID}/{KEY}\n")
    );
    assert!(parent.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"printf 'DETACHED-PTY\\n'; exit\n".to_vec()),
        },
    );
    let mut output = Vec::new();
    while !output
        .windows(b"DETACHED-PTY".len())
        .any(|window| window == b"DETACHED-PTY")
    {
        let packet = read_local_packet(&mut router).unwrap();
        output.extend(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .unwrap(),
        );
    }
}

#[test]
fn real_terminal_registers_runs_shell_and_resizes_pty() {
    let fixture = Fixture::new("shell");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let (mut router, _) = fixture.listener.accept().unwrap();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = read_local_packet(&mut router).unwrap();
    assert_eq!(
        registration.header(),
        TerminalPacketType::TerminalUserInfo as u8
    );
    let user = TerminalUserInfo::decode(registration.payload()).unwrap();
    assert_eq!(user.id.as_deref(), Some(ID));
    assert_eq!(user.passkey.as_deref(), Some(KEY));
    fixture.wait_ready();

    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: vec!["G004_VALUE".to_owned()],
            environmentvalues: vec!["literal-value".to_owned()],
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalInfo,
        &TerminalInfo {
            id: None,
            row: Some(40),
            column: Some(100),
            width: Some(800),
            height: Some(600),
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(
                b"printf 'ETPTY:%s:%s\\n' \"$TERM\" \"$G004_VALUE\"; stty size; exit 7\n".to_vec(),
            ),
        },
    );

    let mut output = Vec::new();
    while !output
        .windows(b"ETPTY:xterm-256color:literal-value".len())
        .any(|window| window == b"ETPTY:xterm-256color:literal-value")
        || !output
            .windows(b"40 100".len())
            .any(|window| window == b"40 100")
    {
        let packet = read_local_packet(&mut router).unwrap();
        assert_eq!(packet.header(), TerminalPacketType::TerminalBuffer as u8);
        let buffer = TerminalBuffer::decode(packet.payload()).unwrap();
        output.extend(buffer.buffer.unwrap());
    }
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert_eq!(status.code(), Some(7));
}

#[test]
fn malformed_credentials_fail_before_router_connection() {
    let fixture = Fixture::new("bad-credentials");
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .args(["terminal", "--serverfifo", fixture.socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(b"bad\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected id/passkey_TERM"));
    fixture.listener.set_nonblocking(true).unwrap();
    assert!(fixture.listener.accept().is_err());
}

#[test]
fn router_disconnect_terminates_the_shell() {
    let fixture = Fixture::new("disconnect");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let (mut router, _) = fixture.listener.accept().unwrap();
    let _ = read_local_packet(&mut router).unwrap();
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
        },
    );
    drop(router);
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(!status.success());
}

#[test]
fn real_terminal_starts_login_shell_and_loads_profile_color() {
    let fixture = Fixture::new("login-color");
    let shell = fixture.login_probe_shell();
    let mut child = fixture.spawn_with_shell(shell.to_str().unwrap());
    write_credentials(&mut child);
    let (mut router, _) = fixture.listener.accept().unwrap();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _ = read_local_packet(&mut router).unwrap();
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"exit\n".to_vec()),
        },
    );
    let output = collect_until(&mut router, |output| {
        contains(output, LOGIN_COLOR_MARKER) || contains(output, NON_LOGIN_MARKER)
    });
    let _ = child.wait_timeout(TIMEOUT).unwrap();
    assert!(
        contains(&output, LOGIN_COLOR_MARKER),
        "expected ANSI login-shell color marker when SHELL receives -l; got {:?}",
        String::from_utf8_lossy(&output),
    );
    assert!(
        !contains(&output, NON_LOGIN_MARKER),
        "login-shell color marker must be emitted only when SHELL receives -l; got {:?}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
fn real_terminal_login_shell_preserves_term_without_colorterm() {
    let fixture = Fixture::new("login-term");
    let shell = fixture.login_probe_shell();
    let mut child = fixture.spawn_with_shell(shell.to_str().unwrap());
    write_credentials(&mut child);
    let (mut router, _) = fixture.listener.accept().unwrap();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _ = read_local_packet(&mut router).unwrap();
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(
                b"printf 'TERM=%s\nCOLORTERM=%s\n' \"$TERM\" \"${COLORTERM-}\"; exit\n".to_vec(),
            ),
        },
    );
    let output = collect_until(&mut router, |output| {
        (contains(output, LOGIN_COLOR_MARKER) || contains(output, NON_LOGIN_MARKER))
            && contains(output, b"TERM=xterm-256color")
            && contains(output, b"COLORTERM=")
    });
    let _ = child.wait_timeout(TIMEOUT).unwrap();
    assert!(
        contains(&output, LOGIN_COLOR_MARKER),
        "expected ANSI login-shell color marker when SHELL receives -l; got {:?}",
        String::from_utf8_lossy(&output),
    );
    assert!(
        contains(&output, b"TERM=xterm-256color\r\nCOLORTERM=\r\n"),
        "TERM=xterm-256color must survive empty TermInit with COLORTERM unset; got {:?}",
        String::from_utf8_lossy(&output),
    );
    assert!(
        !contains(&output, b"COLORTERM=truecolor"),
        "COLORTERM must remain unset under empty TermInit; got {:?}",
        String::from_utf8_lossy(&output),
    );
}

fn send<M: Message>(router: &mut impl Write, kind: TerminalPacketType, message: &M) {
    write_local_packet(router, &Packet::new(kind as u8, message.encode_to_vec())).unwrap();
}
