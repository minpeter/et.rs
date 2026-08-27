#![forbid(unsafe_code)]

use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use et_core::keys::{parse_id_passkey, passkey_to_key};
use et_core::proto::{ConnectStatus, EtPacketType, InitialPayload, InitialResponse};
use et_net::connection::Connection;
use et_net::handshake::{read_request, response_status, write_response};
use prost::Message;

const SERVER_ID: &str = "abcdefghijklmnop";
const SERVER_KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const VALID_MARKER: &str = "IDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n";
const RESOLVED_CONFIG: &str = "host server-alias\nuser config-user\nhostname 127.0.0.1\nport 22\n";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("et-rs-{label}-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeSsh {
    dir: TestDir,
    argv: PathBuf,
    stdin: PathBuf,
}

impl FakeSsh {
    fn new() -> Self {
        let dir = TestDir::new("ssh");
        let script = dir.0.join("ssh");
        let argv = dir.0.join("argv");
        let stdin = dir.0.join("stdin");
        fs::write(
            &script,
            r#"#!/bin/sh
for arg in "$@"; do printf "%s\0" "$arg" >> "$ET_FAKE_ARGV"; done
printf "\0" >> "$ET_FAKE_ARGV"
if [ "$1" = "-G" ]; then
  printf "%s" "$ET_FAKE_CONFIG"
  exit 0
fi
last=
for arg in "$@"; do last=$arg; done
case "$last" in
  *"__ET_COMSPEC__"*)
    printf "%s" "$ET_FAKE_PROBE_STDOUT"
    exit "$ET_FAKE_PROBE_EXIT"
    ;;
esac
/bin/cat > "$ET_FAKE_STDIN"
printf "%s" "$ET_FAKE_STDOUT"
printf "%s" "$ET_FAKE_STDERR" >&2
exit "$ET_FAKE_EXIT"
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(script, permissions).unwrap();
        fs::write(&argv, []).unwrap();
        Self { dir, argv, stdin }
    }

    fn command(&self, config: &str, stdout: &str, exit: i32, stderr: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
        command
            .env("PATH", &self.dir.0)
            .env("ET_FAKE_ARGV", &self.argv)
            .env("ET_FAKE_STDIN", &self.stdin)
            .env("ET_FAKE_CONFIG", config)
            .env("ET_FAKE_STDOUT", stdout)
            .env("ET_FAKE_STDERR", stderr)
            .env("ET_FAKE_EXIT", exit.to_string())
            .env("ET_FAKE_PROBE_STDOUT", "__ET_COMSPEC__%ComSpec%\n")
            .env("ET_FAKE_PROBE_EXIT", "0")
            .stdin(Stdio::null());
        command
    }

    fn invocations(&self) -> Vec<Vec<String>> {
        let bytes = fs::read(&self.argv).unwrap();
        let mut invocations = Vec::new();
        let mut invocation = Vec::new();
        for field in bytes.split(|byte| *byte == 0) {
            if field.is_empty() {
                if !invocation.is_empty() {
                    invocations.push(std::mem::take(&mut invocation));
                }
            } else {
                invocation.push(String::from_utf8(field.to_vec()).unwrap());
            }
        }
        invocations
    }
}

fn bound(stream: &TcpStream) {
    let timeout = Some(Duration::from_secs(3));
    stream.set_read_timeout(timeout).unwrap();
    stream.set_write_timeout(timeout).unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn cli_proves_exact_ssh_bootstrap_v6_and_encrypted_initial_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        let request = read_request(&mut stream).unwrap();
        assert_eq!(request.client_id.as_deref(), Some(SERVER_ID));
        assert_eq!(request.version, Some(6));
        write_response(&mut stream, &response_status(ConnectStatus::NewClient)).unwrap();
        let key = passkey_to_key(SERVER_KEY).unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        assert_eq!(packet.header(), EtPacketType::InitialPayload as u8);
        let payload = InitialPayload::decode(packet.payload()).unwrap();
        assert_eq!(payload.jumphost, Some(false));
        assert!(payload.reversetunnels.is_empty());
        assert!(payload.environmentvariables.is_empty());
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("TERM", "xterm-test")
        .args([
            "-N",
            // Upstream takes an explicit verbosity level, not a repeat count.
            "-v",
            "2",
            "--terminal-path",
            "/opt/et terminal",
            "--serverfifo",
            "/tmp/server fifo",
            "--ssh-option",
            "StrictHostKeyChecking=no",
            &format!("test-user@server-alias:{}", address.port()),
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(fs::read(&fake.stdin).unwrap().is_empty());

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 3);
    assert_eq!(
        invocations[0],
        ["-G", "-oStrictHostKeyChecking=no", "test-user@server-alias"]
    );
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let argv = &invocations[2];
    assert_eq!(
        &argv[..2],
        ["test-user@server-alias", "-oStrictHostKeyChecking=no"]
    );
    let prefix = "printf '%s\\n' '";
    let value = argv[2].strip_prefix(prefix).unwrap();
    let provisional = value.split_once("_xterm-test'").unwrap().0;
    let (id, key) = parse_id_passkey(provisional).unwrap();
    assert!(id.starts_with("XXX"));
    assert_eq!(id.len(), 16);
    assert_eq!(key.len(), 32);
    assert_eq!(
        argv[2],
        format!(
            "printf '%s\\n' '{provisional}_xterm-test' | '/opt/et terminal' '--verbose=2' '--serverfifo=/tmp/server fifo'"
        )
    );
}

#[test]
fn bare_windows_login_shell_is_detected_before_bootstrap() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        assert_eq!(read_request(&mut stream).unwrap().version, Some(6));
        write_response(&mut stream, &response_status(ConnectStatus::NewClient)).unwrap();
        let key = passkey_to_key(SERVER_KEY).unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        assert_eq!(packet.header(), EtPacketType::InitialPayload as u8);
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env(
            "ET_FAKE_PROBE_STDOUT",
            "__ET_COMSPEC__C:\\WINDOWS\\system32\\cmd.exe\r\n",
        )
        .env("ET_FAKE_PROBE_EXIT", "0")
        .args(["-N".to_owned(), address.to_string()])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 3, "{invocations:?}");
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let bootstrap = invocations[2].last().unwrap();
    assert!(bootstrap.starts_with("echo "), "{bootstrap}");
    assert!(bootstrap.contains("\"et.exe\""), "{bootstrap}");
    assert!(!bootstrap.contains("printf"), "{bootstrap}");
}

#[test]
fn explicit_posix_shell_skips_probe_and_uses_exact_posix_bootstrap() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        assert_eq!(read_request(&mut stream).unwrap().version, Some(6));
        write_response(&mut stream, &response_status(ConnectStatus::NewClient)).unwrap();
        let key = passkey_to_key(SERVER_KEY).unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        assert_eq!(packet.header(), EtPacketType::InitialPayload as u8);
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("TERM", "xterm-256color")
        .env(
            "ET_FAKE_PROBE_STDOUT",
            "__ET_COMSPEC__C:\\WINDOWS\\system32\\cmd.exe\r\n",
        )
        .args([
            "-N".to_owned(),
            "--remote-shell=posix".to_owned(),
            address.to_string(),
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 2, "{invocations:?}");
    assert_eq!(invocations[0], ["-G", "127.0.0.1"]);
    let bootstrap = &invocations[1];
    assert_eq!(bootstrap[0], "config-user@127.0.0.1");
    let input = bootstrap[1]
        .strip_prefix("printf '%s\\n' '")
        .unwrap()
        .strip_suffix("_xterm-256color' | 'etterminal' '--verbose=0'")
        .unwrap();
    let (id, passkey) = parse_id_passkey(input).unwrap();
    assert!(id.starts_with("XXX"));
    assert_eq!(id.len(), 16);
    assert_eq!(passkey.len(), 32);
}

#[test]
fn ssh_process_failures_are_typed() {
    let no_ssh = TestDir::new("no-ssh");
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .args(["-N", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("could not start system ssh"));

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, "", 42, "fake ssh failure\n")
        .args(["-N", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("system ssh exited with status 42"));
}

#[test]
fn marker_id_and_key_errors_are_distinct() {
    let cases = [
        ("banner", "missing the IDPASSKEY marker"),
        ("IDPASSKEY:short", "malformed IDPASSKEY marker"),
        (
            "IDPASSKEY:abcdefghijklmno!/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            "session id must be 16 ASCII alphanumeric bytes",
        ),
        (
            "IDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcde!",
            "passkey must be 32 ASCII alphanumeric bytes",
        ),
    ];
    for (stdout, message) in cases {
        let fake = FakeSsh::new();
        let output = fake
            .command(RESOLVED_CONFIG, stdout, 0, "")
            .args(["-N", "127.0.0.1:1"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
    }
}

#[test]
fn fresh_bootstrap_rejects_returning_without_sending_initial_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        assert_eq!(read_request(&mut stream).unwrap().version, Some(6));
        write_response(
            &mut stream,
            &response_status(ConnectStatus::ReturningClient),
        )
        .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N".to_string(), address.to_string()])
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("returning recovery belongs to a live reconnect"));
}

#[test]
fn protocol_rejection_and_unreachable_endpoint_are_typed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        assert_eq!(read_request(&mut stream).unwrap().version, Some(6));
        write_response(
            &mut stream,
            &response_status(ConnectStatus::MismatchedProtocol),
        )
        .unwrap();
    });
    let fake = FakeSsh::new();
    let rejected = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N".to_string(), address.to_string()])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(stderr(&rejected).contains("rejected protocol version 6"));

    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let fake = FakeSsh::new();
    let unreachable = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N".to_string(), address.to_string()])
        .output()
        .unwrap();
    assert!(stderr(&unreachable).contains("could not reach the ET server"));
}

#[test]
fn leading_hyphen_destination_components_are_rejected_before_spawn() {
    let no_ssh = TestDir::new("invalid-destination");
    for args in [
        vec!["-N", "--", "-oProxyCommand=bad"],
        vec!["-N", "--username=-oProxyCommand=bad", "server-alias"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_et"))
            .env("PATH", &no_ssh.0)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("must not begin with a hyphen"));
    }
}

#[test]
fn invalid_client_modes_fail_before_ssh_bootstrap() {
    let no_ssh = TestDir::new("honest");
    for args in [
        vec!["-N", "-t", "0:80", "example.test"],
        vec!["--no-exit", "example.test"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_et"))
            .env("PATH", &no_ssh.0)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            stderr(&output).contains("invalid tunnel endpoint")
                || stderr(&output).contains("--no-exit requires --command")
        );
    }
}

#[test]
fn jumphost_starts_a_jump_terminal_and_connects_to_the_jumphost() {
    // Upstream `--jumphost` is an ET-native relay: the destination terminal is
    // started through `ssh -J`, a second `etterminal --jump` is started on the
    // jumphost, and the ET session is established against the jumphost's
    // etserver with `jumphost = true` in the initial payload.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        let request = read_request(&mut stream).unwrap();
        assert_eq!(request.version, Some(6));
        write_response(&mut stream, &response_status(ConnectStatus::NewClient)).unwrap();
        let key = passkey_to_key(SERVER_KEY).unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
        assert_eq!(packet.header(), EtPacketType::InitialPayload as u8);
        let payload = InitialPayload::decode(packet.payload()).unwrap();
        assert_eq!(payload.jumphost, Some(true));
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse { error: None }.encode_to_vec(),
            )
            .unwrap();
    });

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env(
            "ET_FAKE_PROBE_STDOUT",
            "__ET_COMSPEC__C:\\WINDOWS\\system32\\cmd.exe\r\n",
        )
        .args([
            "-N",
            "--jumphost",
            "jump.example",
            "--jport",
            &address.port().to_string(),
            "--jserverfifo=/tmp/jump.fifo",
            "test-user@server-alias:2022",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    // -G dst, login-shell probe, dst bootstrap through -J, -G jumphost,
    // jump bootstrap.
    assert_eq!(invocations.len(), 5, "{invocations:?}");
    assert_eq!(invocations[0], ["-G", "test-user@server-alias"]);
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let destination = &invocations[2];
    assert_eq!(destination[0], "-J");
    assert_eq!(destination[1], "jump.example");
    assert_eq!(destination[2], "test-user@server-alias");
    assert!(destination[3].starts_with("echo "), "{:?}", destination[3]);
    assert!(
        destination[3].contains("\"et.exe\""),
        "{:?}",
        destination[3]
    );
    assert_eq!(invocations[3], ["-G", "jump.example"]);
    let jump = &invocations[4];
    assert_eq!(jump[0], "jump.example");
    // The jumphost remains POSIX even when the destination probe selects Cmd.
    assert!(jump[1].contains("'etterminal'"), "{:?}", jump[1]);
    assert!(!jump[1].contains("et.exe"), "{:?}", jump[1]);
    assert!(jump[1].contains("'--jump'"), "{:?}", jump[1]);
    assert!(jump[1].contains("'--dsthost=127.0.0.1'"), "{:?}", jump[1]);
    assert!(jump[1].contains("'--dstport=2022'"), "{:?}", jump[1]);
    assert!(
        jump[1].contains("'--serverfifo=/tmp/jump.fifo'"),
        "{:?}",
        jump[1]
    );
}

#[test]
fn malformed_jumphost_and_jserverfifo_fail_before_ssh() {
    let no_ssh = TestDir::new("jump-fail");
    // Use `--jumphost=value` form so values starting with `-` reach validation.
    let cases: &[(&[&str], &str)] = &[
        (
            &["-N", "--jumphost=", "example.test"],
            "empty --jumphost value",
        ),
        (
            &["-N", "--jumphost=-oProxyCommand=bad", "example.test"],
            "must not begin with a hyphen",
        ),
        (
            &["-N", "--jumphost=good,-evil", "example.test"],
            "must not begin with a hyphen",
        ),
        (
            // `--jserverfifo` only makes sense together with `--jumphost`.
            &["-N", "--jserverfifo=/tmp/fifo", "example.test"],
            "--jserverfifo requires --jumphost",
        ),
    ];
    for (args, message) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_et"))
            .env("PATH", &no_ssh.0)
            .args(*args)
            .output()
            .unwrap();
        assert_ne!(output.status.code(), Some(0), "args={args:?}");
        let err = stderr(&output);
        assert!(
            err.contains(message),
            "args={args:?} expected `{message}` in stderr={err}"
        );
    }
}
