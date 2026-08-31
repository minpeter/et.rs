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
use et_core::packet::Packet;
use et_core::proto::{
    ConnectStatus, EtPacketType, InitialPayload, InitialResponse, TermInit, TerminalPacketType,
};
use et_net::connection::Connection;
use et_net::handshake::{read_request, response_status, write_response};
use et_net::local_packet::MAX_LOCAL_PACKET_LEN;
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
            .env_clear()
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

fn initial_payload_server() -> (u16, thread::JoinHandle<InitialPayload>) {
    initial_payload_server_with_error(None)
}

fn initial_payload_server_with_error(
    error: Option<&'static str>,
) -> (u16, thread::JoinHandle<InitialPayload>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
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
        connection
            .write_packet(
                EtPacketType::InitialResponse as u8,
                &InitialResponse {
                    error: error.map(str::to_owned),
                }
                .encode_to_vec(),
            )
            .unwrap();
        payload
    });
    (port, server)
}

#[test]
fn ssh_config_local_and_remote_forwards_become_et_tunnels() {
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
        "localforward 10022 [127.0.0.1]:22\n",
        "remoteforward 1492 [127.0.0.1]:1492\n",
    );

    let _output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    let payload = server.join().unwrap();

    assert_eq!(payload.reversetunnels.len(), 1);
    let reverse = &payload.reversetunnels[0];
    assert_eq!(
        reverse.source.as_ref().and_then(|source| source.port),
        Some(1492)
    );
    assert_eq!(
        reverse
            .destination
            .as_ref()
            .and_then(|destination| destination.port),
        Some(1492)
    );
    assert_eq!(fake.invocations()[0], ["-G", "-T", "server-alias"]);
}

#[test]
fn ssh_config_forwards_apply_on_the_unspecified_axis() {
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
        "localforward 10022 [127.0.0.1]:22\n",
        "remoteforward 1492 [127.0.0.1]:1492\n",
    );

    let _output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["-N", "-t", "5555:22", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    let payload = server.join().unwrap();

    assert_eq!(payload.reversetunnels.len(), 1);
    assert_eq!(
        payload.reversetunnels[0]
            .source
            .as_ref()
            .and_then(|source| source.port),
        Some(1492)
    );
}

#[test]
fn ssh_config_hardening_nonlocal_destinations_warn_and_other_rows_continue() {
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "localforward 15432 db.internal:5432\n",
        "localforward 15433 127.0.0.2:5432\n",
        "remoteforward 25432 db.internal:5432\n",
        "remoteforward 25433 [::1]:5432\n",
        "remoteforward []:25434 localhost:5432\n",
    );

    let output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["--logtostdout", "-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    if output.status.code() == Some(2) {
        let _ = TcpStream::connect(("127.0.0.1", port));
        let _ = server.join();
        panic!(
            "expected unsupported rows to preserve the base session, got exit 2: {}",
            stderr(&output)
        );
    }
    let payload = server.join().unwrap();

    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(payload.reversetunnels.len(), 1);
    assert_eq!(
        payload.reversetunnels[0]
            .source
            .as_ref()
            .and_then(|source| source.port),
        Some(25433)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("WARNING"))
            .count(),
        4
    );
}

#[test]
fn ssh_config_hardening_unsupported_records_warn_and_base_session_continues() {
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias
",
        "user config-user
",
        "hostname 127.0.0.1
",
        "streamlocalbindunlink yes
",
        "streamlocalbindmask 0077
",
        "dynamicforward [*]:1080
",
        "remoteforward 2080 [socks]:0
",
        "remoteforward 0 [localhost]:22
",
        "localforward relative/source.sock /tmp/destination.sock
",
        "localforward /tmp/source path /tmp/destination path
",
        "localforward /tmp/source.sock /tmp/destination.sock
",
        "localforward 15433 [localhost]:5432
",
        "remoteforward 25433 [localhost]:5432
",
    );

    let output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["--logtostdout", "-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    if output.status.code() == Some(2) {
        let _ = TcpStream::connect(("127.0.0.1", port));
        let _ = server.join();
        panic!(
            "expected unsupported rows to preserve the base session, got exit 2: {}",
            stderr(&output)
        );
    }
    let payload = server.join().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(payload.reversetunnels.len(), 1);
    assert_eq!(
        payload.reversetunnels[0]
            .source
            .as_ref()
            .and_then(|source| source.port),
        Some(25433)
    );
    for reason in [
        "dynamic forwarding is unsupported",
        "allocated remote port 0 is unsupported",
        "relative stream-local path is unsupported",
        "ambiguous stream-local path is unsupported",
        "stream-local bind policy is unsupported",
    ] {
        assert!(stdout.contains(reason), "missing {reason:?} in {stdout}");
    }
}

#[test]
fn ssh_config_malformed_forward_is_rejected() {
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
        "localforward none\n",
    );

    let output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["-N", "server-alias:1"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("malformed localforward"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fake.invocations(), [["-G", "-T", "server-alias"]]);
}

#[test]
fn ssh_config_extra_forward_field_is_rejected_before_bootstrap() {
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
        "localforward 10022 [127.0.0.1]:22 unexpected\n",
    );

    let output = fake
        .command(config, VALID_MARKER, 0, "")
        .args(["-N", "server-alias:1"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("malformed localforward"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fake.invocations(), [["-G", "-T", "server-alias"]]);
}

#[test]
fn ssh_config_malformed_axis_is_rejected_even_with_explicit_forward() {
    // Given
    let base_config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
    );

    for (option, value, malformed, row) in [
        (
            "-t",
            "5555:22",
            "localforward",
            "localforward unsupported\n",
        ),
        (
            "-r",
            "3000:4000",
            "remoteforward",
            "remoteforward 1492 [127.0.0.1]:1492 unexpected\n",
        ),
    ] {
        let fake = FakeSsh::new();
        let config = format!("{base_config}{row}");

        // When
        let output = fake
            .command(&config, VALID_MARKER, 0, "")
            .args(["-N", option, value, "server-alias:1"])
            .output()
            .unwrap();
        let error = stderr(&output);

        // Then
        assert_eq!(output.status.code(), Some(2), "{option}: {error}");
        assert!(error.contains(&format!("malformed {malformed}")), "{error}");
        assert_eq!(fake.invocations(), [["-G", "-T", "server-alias"]]);
    }
}

#[test]
fn ssh_config_and_cli_remote_forwards_are_cumulative_and_exactly_deduplicated() {
    // Given
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
        "localforward 10022 [127.0.0.1]:22\n",
        "remoteforward 1492 [127.0.0.1]:1492\n",
        "remoteforward 1492 [127.0.0.1]:1492\n",
        "remoteforward 1492 [127.0.0.1]:1493\n",
    );

    // When
    let _output = fake
        .command(config, VALID_MARKER, 0, "")
        .args([
            "-N",
            "-r",
            "localhost:3000:127.0.0.1:4000",
            "-r",
            "localhost:3000:127.0.0.1:4000",
            "-r",
            "localhost:1492:127.0.0.1:1492",
            &format!("server-alias:{port}"),
        ])
        .output()
        .unwrap();
    let payload = server.join().unwrap();

    // Then
    let ports = payload
        .reversetunnels
        .iter()
        .map(|request| {
            (
                request.source.as_ref().and_then(|source| source.port),
                request
                    .destination
                    .as_ref()
                    .and_then(|destination| destination.port),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ports,
        [
            (Some(3000), Some(4000)),
            (Some(1492), Some(1492)),
            (Some(1492), Some(1493)),
        ]
    );
}

#[test]
fn cli_proves_exact_ssh_bootstrap_v6_and_encrypted_initial_payload() {
    let (port, server) = initial_payload_server();

    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .env("LANG", "C.UTF-8")
        .env("LC_CTYPE", "C.UTF-8")
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
            &format!("test-user@server-alias:{port}"),
        ])
        .output()
        .unwrap();
    let payload = server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(fs::read(&fake.stdin).unwrap().is_empty());
    assert_eq!(payload.jumphost, Some(false));
    assert!(payload.reversetunnels.is_empty());
    assert_eq!(
        payload.environmentvariables.get("LANG").map(String::as_str),
        Some("C.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_CTYPE")
            .map(String::as_str),
        Some("C.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("COLORTERM")
            .map(String::as_str),
        Some("truecolor")
    );
    assert_eq!(payload.environmentvariables.len(), 3);

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 3);
    assert_eq!(
        invocations[0],
        [
            "-G",
            "-T",
            "-oStrictHostKeyChecking=no",
            "test-user@server-alias"
        ]
    );
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let argv = &invocations[2];
    assert_eq!(
        &argv[..3],
        [
            "-oClearAllForwardings=yes",
            "-oStrictHostKeyChecking=no",
            "test-user@server-alias",
        ]
    );
    let prefix = "printf '%s\\n' '";
    let value = argv[3].strip_prefix(prefix).unwrap();
    let provisional = value.split_once("_xterm-256color'").unwrap().0;
    let (id, key) = parse_id_passkey(provisional).unwrap();
    assert!(id.starts_with("XXX"));
    assert_eq!(id.len(), 16);
    assert_eq!(key.len(), 32);
    assert_eq!(
        argv[3],
        format!(
            "printf '%s\\n' '{provisional}_xterm-256color' | '/opt/et terminal' '--verbose=2' '--serverfifo=/tmp/server fifo'"
        )
    );
}

#[test]
fn posix_client_forwards_only_ssh_locale_environment() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("TERM", "xterm-test")
        .env("LANG", "ko_KR.UTF-8")
        .env("LC_TEST_SENTINEL", "C.UTF-8")
        .env("LANGUAGE", "do-not-forward")
        .env("ET_SECRET", "do-not-forward")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    let payload = server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        payload.environmentvariables.get("LANG").map(String::as_str),
        Some("ko_KR.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_TEST_SENTINEL")
            .map(String::as_str),
        Some("C.UTF-8")
    );
    assert!(!payload.environmentvariables.contains_key("LANGUAGE"));
    assert!(!payload.environmentvariables.contains_key("ET_SECRET"));
    assert_eq!(payload.environmentvariables.len(), 2);

    let (windows_port, windows_server) = initial_payload_server();
    let windows_fake = FakeSsh::new();
    let windows_output = windows_fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("TERM", "xterm256color")
        .env("LANG", "ko_KR.UTF-8")
        .env("LC_TEST_SENTINEL", "C.UTF-8")
        .args(["-N", "--winserver", &format!("server-alias:{windows_port}")])
        .output()
        .unwrap();
    let windows_payload = windows_server.join().unwrap();
    assert!(
        windows_output.status.success(),
        "{}",
        stderr(&windows_output)
    );
    assert!(windows_payload.environmentvariables.is_empty());
}

#[test]
fn posix_client_filters_locale_to_terminal_environment_limits() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let mut command = fake.command(RESOLVED_CONFIG, VALID_MARKER, 0, "");
    command
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .env("LANG", "ko_KR.UTF-8")
        .env("LC_ALL", "C")
        .env("LC_\u{1f4a5}", "C.UTF-8")
        .env("LC_OVERSIZED", "x".repeat(4097));
    for index in 0..130 {
        command.env(format!("LC_BOUNDARY_{index:03}"), "C.UTF-8");
    }
    let output = command
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    let payload = server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(
        payload.environmentvariables.get("LANG").map(String::as_str),
        Some("ko_KR.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_ALL")
            .map(String::as_str),
        Some("C")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("COLORTERM")
            .map(String::as_str),
        Some("truecolor")
    );
    assert!(!payload.environmentvariables.contains_key("LC_\u{1f4a5}"));
    assert!(!payload.environmentvariables.contains_key("LC_OVERSIZED"));
    assert_eq!(payload.environmentvariables.len(), 128);
    assert!(payload.environmentvariables.iter().all(|(name, value)| {
        let mut bytes = name.bytes();
        matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && value.len() <= 4096
    }));
}

#[test]
fn posix_client_counts_duplicate_tunnel_environment_names_once() {
    let (port, server) = initial_payload_server_with_error(Some("stop after payload"));
    let fake = FakeSsh::new();
    let mut command = fake.command(RESOLVED_CONFIG, VALID_MARKER, 0, "");
    command
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .env("LANG", "ko_KR.UTF-8")
        .env("LC_ALL", "C");
    for index in 0..130 {
        command.env(format!("LC_BOUNDARY_{index:03}"), "C.UTF-8");
    }
    let mut arguments = vec!["-N".to_owned()];
    for index in 0..128 {
        arguments.extend([
            "--reversetunnel".to_owned(),
            format!("ET_PIPE:remote-{index}"),
        ]);
    }
    arguments.push(format!("server-alias:{port}"));

    let output = command.args(arguments).output().unwrap();
    let payload = server.join().unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("stop after payload"));
    assert_eq!(payload.reversetunnels.len(), 128);
    assert!(payload
        .reversetunnels
        .iter()
        .all(|request| { request.environmentvariable.as_deref() == Some("ET_PIPE") }));
    assert_eq!(
        payload.environmentvariables.get("LANG").map(String::as_str),
        Some("ko_KR.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_ALL")
            .map(String::as_str),
        Some("C")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("COLORTERM")
            .map(String::as_str),
        Some("truecolor")
    );
    assert_eq!(payload.environmentvariables.len(), 127);
}

#[test]
fn posix_client_bounds_locale_to_local_terminal_packet() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let mut command = fake.command(RESOLVED_CONFIG, VALID_MARKER, 0, "");
    command
        .env("TERM", "xterm-256color")
        .env("LANG", "ko_KR.UTF-8")
        .env("LC_ALL", "C")
        .env("LC_CTYPE", "C.UTF-8");
    for index in 0..20 {
        command.env(format!("LC_000_{index:03}"), "x".repeat(4096));
    }
    let output = command
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    let payload = server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        payload.environmentvariables.get("LANG").map(String::as_str),
        Some("ko_KR.UTF-8")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_ALL")
            .map(String::as_str),
        Some("C")
    );
    assert_eq!(
        payload
            .environmentvariables
            .get("LC_CTYPE")
            .map(String::as_str),
        Some("C.UTF-8")
    );
    let environment: std::collections::BTreeMap<_, _> =
        payload.environmentvariables.into_iter().collect();
    let term_init = TermInit {
        environmentnames: environment.keys().cloned().collect(),
        environmentvalues: environment.values().cloned().collect(),
        flowcontrol: None,
    };
    let packet = Packet::new(
        TerminalPacketType::TerminalInit as u8,
        term_init.encode_to_vec(),
    );
    assert!(
        packet.wire_len() <= MAX_LOCAL_PACKET_LEN,
        "{} > {MAX_LOCAL_PACKET_LEN}",
        packet.wire_len()
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
        .env("TERM", "xterm-ghostty")
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
    assert!(bootstrap.contains("_xterm-256color|"), "{bootstrap}");
    assert!(!bootstrap.contains("_xterm-ghostty"), "{bootstrap}");
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
        .env("TERM", "xterm-ghostty")
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
    assert_eq!(invocations[0], ["-G", "-T", "127.0.0.1"]);
    let bootstrap = &invocations[1];
    assert_eq!(bootstrap[0], "-oClearAllForwardings=yes");
    assert_eq!(bootstrap[1], "config-user@127.0.0.1");
    let input = bootstrap[2]
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
    for (args, message) in [
        (
            vec!["-N", "-t", "0:80", "example.test"],
            "invalid tunnel endpoint",
        ),
        (
            vec!["--no-exit", "example.test"],
            "--no-exit requires --command",
        ),
        (
            vec!["-N", "-r", "BAD-NAME:remote", "example.test"],
            "invalid reverse-tunnel environment variable name",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_et"))
            .env("PATH", &no_ssh.0)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
    }
}

#[test]
fn excessive_unique_tunnel_environment_names_fail_before_ssh_bootstrap() {
    let no_ssh = TestDir::new("honest");
    let mut arguments = vec!["-N".to_owned()];
    for index in 0..129 {
        arguments.extend([
            "-r".to_owned(),
            format!("ET_PIPE_{index:03}:remote-{index}"),
        ]);
    }
    arguments.push("example.test".to_owned());
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("terminal environment has 129 reserved names; maximum is 128"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn colorterm_counts_toward_the_tunnel_environment_limit() {
    let no_ssh = TestDir::new("honest");
    let mut arguments = vec!["-N".to_owned()];
    for index in 0..128 {
        arguments.extend([
            "-r".to_owned(),
            format!("ET_PIPE_{index:03}:remote-{index}"),
        ]);
    }
    arguments.push("server-alias:1".to_owned());
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("terminal environment has 129 reserved names; maximum is 128"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn non_posix_colorterm_does_not_reserve_an_unsent_environment_name() {
    let no_ssh = TestDir::new("honest");
    let mut arguments = vec![
        "-N".to_owned(),
        "--winserver".to_owned(),
        "--jumphost".to_owned(),
        "jump-alias".to_owned(),
    ];
    for index in 0..128 {
        arguments.extend([
            "-r".to_owned(),
            format!("ET_PIPE_{index:03}:remote-{index}"),
        ]);
    }
    arguments.push("example.test".to_owned());

    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .args(arguments)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not start system ssh"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn oversized_tunnel_environment_name_exceeds_local_packet_limit() {
    let no_ssh = TestDir::new("honest");
    let environment_name = format!("E{}", "T".repeat(MAX_LOCAL_PACKET_LEN));
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .env("TERM", "xterm-256color")
        .args([
            "-N",
            "-r",
            &format!("{environment_name}:remote"),
            "server-alias:1",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("terminal environment packet needs at least"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn oversized_jumphost_initialization_fails_before_ssh_bootstrap() {
    let no_ssh = TestDir::new("honest");
    let mut arguments = vec![
        "-N".to_owned(),
        "--jumphost".to_owned(),
        "jump-alias".to_owned(),
    ];
    let destination = format!("remote-{}", "x".repeat(500));
    for _ in 0..128 {
        arguments.extend(["-r".to_owned(), format!("ET_PIPE:{destination}")]);
    }
    arguments.push("example.test".to_owned());
    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .env("TERM", "xterm-256color")
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("jumphost initialization packet needs at least"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn non_posix_jumphost_ignores_unsent_colorterm_in_packet_budget() {
    let no_ssh = TestDir::new("honest");
    let mut arguments = vec![
        "-N".to_owned(),
        "--winserver".to_owned(),
        "--jumphost".to_owned(),
        "jump-alias".to_owned(),
    ];
    let destination = format!("remote-{}", "x".repeat(486));
    for _ in 0..127 {
        arguments.extend(["-r".to_owned(), format!("ET_PIPE:{destination}")]);
    }
    let boundary_destination = format!("remote-{}", "x".repeat(587));
    arguments.extend(["-r".to_owned(), format!("ET_PIPE:{boundary_destination}")]);
    arguments.push("example.test".to_owned());

    let output = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &no_ssh.0)
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .args(arguments)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not start system ssh"),
        "{}",
        stderr(&output)
    );
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
        .env("TERM", "xterm-ghostty")
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
    assert_eq!(invocations[0], ["-G", "-T", "test-user@server-alias"]);
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let destination = &invocations[2];
    assert_eq!(destination[0], "-J");
    assert_eq!(destination[1], "jump.example");
    assert_eq!(destination[2], "-oClearAllForwardings=yes");
    assert_eq!(destination[3], "test-user@server-alias");
    let destination_command = &destination[4];
    assert!(
        destination_command.starts_with("echo "),
        "{destination_command:?}"
    );
    assert!(
        destination_command.contains("\"et.exe\""),
        "{destination_command:?}"
    );
    assert!(
        destination_command.contains("_xterm-256color|"),
        "{destination_command:?}"
    );
    assert!(
        !destination_command.contains("_xterm-ghostty"),
        "{destination_command:?}"
    );
    assert_eq!(invocations[3], ["-G", "-T", "jump.example"]);
    let jump = &invocations[4];
    assert_eq!(jump[0], "-oClearAllForwardings=yes");
    assert_eq!(jump[1], "jump.example");
    let jump_command = &jump[2];
    // The jumphost remains POSIX even when the destination probe selects Cmd.
    assert!(jump_command.contains("'etterminal'"), "{jump_command:?}");
    assert!(!jump_command.contains("et.exe"), "{jump_command:?}");
    assert!(
        jump_command.contains("_xterm-256color'"),
        "{jump_command:?}"
    );
    assert!(!jump_command.contains("_xterm-ghostty"), "{jump_command:?}");
    assert!(jump_command.contains("'--jump'"), "{jump_command:?}");
    assert!(
        jump_command.contains("'--dsthost=127.0.0.1'"),
        "{jump_command:?}"
    );
    assert!(
        jump_command.contains("'--dstport=2022'"),
        "{jump_command:?}"
    );
    assert!(
        jump_command.contains("'--serverfifo=/tmp/jump.fifo'"),
        "{jump_command:?}"
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
