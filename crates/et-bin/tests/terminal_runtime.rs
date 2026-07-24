#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{
    TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType, TerminalUserInfo,
};
use et_net::local_packet::{read_local_packet, write_local_packet};
use prost::Message;
use wait_timeout::ChildExt;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);

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

    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: vec!["G004_VALUE".to_owned()],
            environmentvalues: vec!["literal-value".to_owned()],
        },
    );
    let marker = read_marker(&mut child);
    assert_eq!(marker, format!("IDPASSKEY:{ID}/{KEY}\n"));
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
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
        },
    );
    let _ = read_marker(&mut child);
    drop(router);
    let status = child.wait_timeout(TIMEOUT).unwrap().unwrap();
    assert!(!status.success());
}

fn send<M: Message>(router: &mut impl Write, kind: TerminalPacketType, message: &M) {
    write_local_packet(router, &Packet::new(kind as u8, message.encode_to_vec())).unwrap();
}

fn write_credentials(child: &mut std::process::Child) {
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{ID}/{KEY}_xterm-256color").unwrap();
}

fn read_marker(child: &mut std::process::Child) -> String {
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    receiver.recv_timeout(TIMEOUT).unwrap().unwrap()
}

struct Fixture {
    directory: std::path::PathBuf,
    socket: std::path::PathBuf,
    listener: UnixListener,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("et-rs-terminal-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("router.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        Self {
            directory,
            socket,
            listener,
        }
    }

    fn spawn(&self) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_et"))
            .args(["terminal", "--serverfifo"])
            .arg(&self.socket)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
