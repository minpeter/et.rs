#![forbid(unsafe_code)]

#[path = "terminal_runtime_support/mod.rs"]
mod terminal_runtime_support;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{
    TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType, TerminalUserInfo,
};
use et_net::local_packet::{
    parse_status, read_local_packet, status_packet, write_local_packet, REGISTRATION_STATUS,
    STARTUP_STATUS,
};
use prost::Message;
use terminal_runtime_support::{
    collect_until, contains, write_credentials, Fixture, LOGIN_COLOR_MARKER, NON_LOGIN_MARKER,
};
use wait_timeout::ChildExt;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);
const LOGIN_TERM_COMPLETION: &[u8] = b"__ET_LOGIN_TERM_COMPLETE__\r\n";
const MOTD_MARKER: &[u8] = b"ET-MOTD-MARKER";
const PROMPT_MARKER: &[u8] = b"ET-PROMPT> ";

fn assert_motd_prompt_spacing(
    fixture_name: &str,
    shell_factory: fn(&Fixture) -> std::path::PathBuf,
) {
    let fixture = Fixture::new(fixture_name);
    let motd = fixture.file("motd", b"ET-MOTD-MARKER\n");
    let shell = shell_factory(&fixture);
    let mut child = fixture.spawn_session(
        shell.to_str().unwrap(),
        &[("ET_MOTD_PATH", motd.as_os_str())],
    );
    write_credentials(&mut child);
    let mut router = fixture.accept();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();

    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
    let output = collect_until(&mut router, |output| contains(output, PROMPT_MARKER));

    let motd_at = find(&output, MOTD_MARKER).unwrap();
    let prompt_at = find(&output, PROMPT_MARKER).unwrap();
    assert_eq!(
        &output[motd_at + MOTD_MARKER.len()..prompt_at],
        b"\r\n",
        "expected prompt directly below MOTD; got {:?}",
        String::from_utf8_lossy(&output),
    );

    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"exit\n".to_vec()),
        },
    );
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(status.success());
}

#[test]
fn bootstrap_parent_reports_marker_and_leaves_registered_session_running() {
    let fixture = Fixture::new("bootstrap-parent");
    let mut parent = fixture.spawn_parent();
    write_credentials(&mut parent);
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = read_local_packet(&mut router).unwrap();
    assert_eq!(
        registration.header(),
        TerminalPacketType::TerminalUserInfo as u8
    );
    let (marker_tx, marker_rx) = std::sync::mpsc::sync_channel(1);
    let stdout = parent.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = marker_tx.send(result);
    });
    assert!(matches!(
        marker_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    acknowledge_registration(&mut router);
    assert_eq!(
        marker_rx.recv_timeout(TIMEOUT).unwrap().unwrap(),
        format!("IDPASSKEY:{ID}/{KEY}\n")
    );
    assert!(parent.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
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
fn registration_delayed_beyond_ten_seconds_still_completes_before_absolute_deadline() {
    let fixture = Fixture::new("delayed-registration");
    let mut parent = fixture.spawn_parent();
    write_credentials(&mut parent);
    let mut router = fixture.accept();
    let _registration = read_local_packet(&mut router).unwrap();
    let (marker_tx, marker_rx) = std::sync::mpsc::sync_channel(1);
    let stdout = parent.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = marker_tx.send(result);
    });
    assert!(matches!(
        marker_rx.recv_timeout(Duration::from_secs(11)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    acknowledge_registration(&mut router);
    assert_eq!(
        marker_rx.recv_timeout(TIMEOUT).unwrap().unwrap(),
        format!("IDPASSKEY:{ID}/{KEY}\n")
    );
    assert!(parent.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    drop(router);
}

#[cfg(target_os = "linux")]
#[test]
fn detached_terminal_is_session_leader_and_closes_inherited_descriptors() {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let sentinel_path = std::env::temp_dir().join(format!(
        "et-rs-inherited-fd-sentinel-{}",
        std::process::id()
    ));
    let sentinel = std::fs::File::create(&sentinel_path).unwrap();
    fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();

    let fixture = Fixture::new("session-leader");
    let mut parent = fixture.spawn_parent();
    write_credentials(&mut parent);
    let mut router = fixture.accept();
    let credentials = getsockopt(&router, PeerCredentials).unwrap();
    let pid = credentials.pid();
    let _registration = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    assert!(parent.wait_timeout(TIMEOUT).unwrap().unwrap().success());

    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat[stat.rfind(')').unwrap() + 2..]
        .split_whitespace()
        .collect();
    let session: i32 = fields[3].parse().unwrap();
    assert_eq!(session, pid, "detached terminal must satisfy sid == pid");
    let inherited = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .any(|target| target == sentinel_path);
    assert!(
        !inherited,
        "detached terminal inherited sentinel descriptor"
    );

    drop(router);
    drop(sentinel);
    let _ = std::fs::remove_file(sentinel_path);
}

#[test]
fn new_terminal_uses_legacy_sequence_with_old_router() {
    let fixture = Fixture::new_legacy("old-router-new-terminal");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = read_local_packet(&mut router).unwrap();
    let user = TerminalUserInfo::decode(registration.payload()).unwrap();
    assert_eq!(user.fd, None);
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"printf 'MIXED-OLD-ROUTER\\n'; exit\n".to_vec()),
        },
    );
    let output = collect_until(&mut router, |output| contains(output, b"MIXED-OLD-ROUTER"));
    assert!(contains(&output, b"MIXED-OLD-ROUTER"));
    assert!(child.wait_timeout(TIMEOUT).unwrap().unwrap().success());
}

#[test]
fn real_terminal_registers_runs_shell_and_resizes_pty() {
    let fixture = Fixture::new("shell");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let registration = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
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
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
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
fn pty_output_backpressure_longer_than_two_seconds_preserves_session_and_order() {
    let fixture = Fixture::new("pty-backpressure");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _registration = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"stty -echo; printf 'PTY-BACKPRESSURE-%s\\n' READY\n".to_vec()),
        },
    );
    let _ = collect_until(&mut router, |output| {
        contains(output, b"PTY-BACKPRESSURE-READY")
    });
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(
                b"head -c 1048576 /dev/zero | tr '\\000' x; printf 'PTY-BACKPRESSURE-%s\\n' MARKER; exit\n"
                    .to_vec(),
            ),
        },
    );

    assert!(
        child
            .wait_timeout(Duration::from_secs(3))
            .unwrap()
            .is_none(),
        "terminal exited instead of backpressuring PTY output"
    );
    let output = collect_until(&mut router, |output| {
        contains(output, b"PTY-BACKPRESSURE-MARKER")
    });
    assert!(contains(&output, b"PTY-BACKPRESSURE-MARKER"));
    assert!(child.wait_timeout(TIMEOUT).unwrap().unwrap().success());
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
fn bootstrap_parent_reports_terminal_child_startup_failure() {
    let missing_router =
        std::env::temp_dir().join(format!("et-rs-missing-router-{}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_et"))
        .args(["terminal", "--serverfifo"])
        .arg(&missing_router)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{ID}/{KEY}_xterm-256color").unwrap();
    let status = child
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("terminal bootstrap did not exit within its bounded test deadline");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert_eq!(status.code(), Some(2));
    assert!(
        stderr.contains("could not connect terminal router"),
        "{stderr}"
    );
}

#[test]
fn router_disconnect_terminates_the_shell() {
    let fixture = Fixture::new("disconnect");
    let mut child = fixture.spawn();
    write_credentials(&mut child);
    let mut router = fixture.accept();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
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
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
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
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(status.success());
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
    let mut router = fixture.accept();
    router.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(
                b"printf '\\nTERM=%s\\nCOLORTERM=%s\\n' \"$TERM\" \"${COLORTERM-}\"; printf '__ET_LOGIN_TERM_%s__\\n' COMPLETE; exit\n".to_vec(),
            ),
        },
    );
    let output = collect_until(&mut router, |output| {
        contains(output, LOGIN_TERM_COMPLETION)
    });
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(status.success());
    assert!(
        contains(&output, LOGIN_COLOR_MARKER),
        "expected ANSI login-shell color marker when SHELL receives -l; got {:?}",
        String::from_utf8_lossy(&output),
    );
    let lines: Vec<&[u8]> = output
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect();
    assert!(
        lines.windows(3).any(|record| {
            record
                == [
                    b"TERM=xterm-256color".as_slice(),
                    b"COLORTERM=".as_slice(),
                    b"__ET_LOGIN_TERM_COMPLETE__".as_slice(),
                ]
        }),
        "expected complete TERM/COLORTERM record; got {:?}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
fn real_terminal_emits_motd_before_login_shell_output() {
    // Given: a server-side MOTD file the session is told to display.
    let fixture = Fixture::new("motd-before-shell");
    let motd = fixture.file("motd", b"ET-MOTD-MARKER\n");
    let shell = fixture.login_probe_shell();
    let mut child = fixture.spawn_session(
        shell.to_str().unwrap(),
        &[("ET_MOTD_PATH", motd.as_os_str())],
    );
    write_credentials(&mut child);
    let mut router = fixture.accept();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();

    // When: the session initializes and the login shell starts producing output.
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"exit\n".to_vec()),
        },
    );
    let output = collect_until(&mut router, |output| contains(output, LOGIN_COLOR_MARKER));
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(status.success());

    // Then: the MOTD reached the client before any shell output.
    let motd_at = find(&output, MOTD_MARKER);
    let shell_at = find(&output, LOGIN_COLOR_MARKER);
    assert!(
        motd_at.is_some_and(|motd_at| shell_at.is_some_and(|shell_at| motd_at < shell_at)),
        "expected MOTD before login shell output; got {:?}",
        String::from_utf8_lossy(&output),
    );
    assert!(
        contains(&output, b"ET-MOTD-MARKER\r\n"),
        "expected MOTD lines terminated with CRLF; got {:?}",
        String::from_utf8_lossy(&output),
    );
    assert_eq!(
        count(&output, MOTD_MARKER),
        1,
        "expected MOTD exactly once; got {:?}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
fn real_terminal_places_prompt_on_line_after_motd() {
    assert_motd_prompt_spacing("motd-prompt-spacing", Fixture::prompt_probe_shell);
}

#[test]
fn real_terminal_does_not_stack_motd_newline_with_shell_startup_newline() {
    assert_motd_prompt_spacing(
        "motd-leading-shell-newline",
        Fixture::leading_newline_prompt_shell,
    );
}

#[test]
fn real_terminal_suppresses_motd_when_home_has_hushlogin() {
    // Given: a MOTD file plus a HOME containing .hushlogin.
    let fixture = Fixture::new("motd-hushlogin");
    let motd = fixture.file("motd", b"ET-MOTD-MARKER\n");
    let home = fixture.file(".hushlogin", b"");
    let home = home.parent().unwrap().to_owned();
    let shell = fixture.login_probe_shell();
    let mut child = fixture.spawn_session(
        shell.to_str().unwrap(),
        &[
            ("ET_MOTD_PATH", motd.as_os_str()),
            ("HOME", home.as_os_str()),
        ],
    );
    write_credentials(&mut child);
    let mut router = fixture.accept();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();

    // When: the session runs to the point the login shell has produced output.
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    expect_startup(&mut router);
    send(
        &mut router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(b"exit\n".to_vec()),
        },
    );
    let output = collect_until(&mut router, |output| contains(output, LOGIN_COLOR_MARKER));
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(status.success());

    // Then: no MOTD was ever sent.
    assert!(
        !contains(&output, MOTD_MARKER),
        "expected .hushlogin to suppress the MOTD; got {:?}",
        String::from_utf8_lossy(&output),
    );
}

fn find(output: &[u8], marker: &[u8]) -> Option<usize> {
    output
        .windows(marker.len())
        .position(|window| window == marker)
}

fn count(output: &[u8], marker: &[u8]) -> usize {
    output
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count()
}

fn acknowledge_registration(router: &mut impl Write) {
    write_local_packet(router, &status_packet(REGISTRATION_STATUS, Ok(()))).unwrap();
}

fn expect_startup(router: &mut impl std::io::Read) {
    let packet = read_local_packet(router).unwrap();
    parse_status(&packet, STARTUP_STATUS).unwrap_or_else(|error| {
        panic!(
            "expected startup status, got header={} payload={:?}: {error}",
            packet.header(),
            packet.payload()
        )
    });
}

fn send<M: Message>(router: &mut impl Write, kind: TerminalPacketType, message: &M) {
    write_local_packet(router, &Packet::new(kind as u8, message.encode_to_vec())).unwrap();
}
