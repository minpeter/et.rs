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

#[test]
fn logging_initialization_errors_reach_each_role_cli_boundary() {
    let directory = TestDir::new("logging-errors");
    let blocker = directory.0.join("blocker");
    fs::write(&blocker, "untouched").unwrap();
    let config = directory.0.join("et.cfg");
    fs::write(&config, "").unwrap();
    for role in ["client", "server", "terminal"] {
        for mirror in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
            command
                .env_remove("ET_DEBUG")
                .arg(role)
                .arg("--logdir")
                .arg(blocker.join("logs"));
            if mirror {
                command.arg("--logtostdout");
            }
            match role {
                "client" => {
                    command.arg("example.invalid");
                }
                "server" => {
                    command.arg("--cfgfile").arg(&config);
                }
                "terminal" => {
                    command.args([
                        "--idpasskey",
                        "abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_xterm",
                    ]);
                }
                _ => unreachable!(),
            }
            let output = command.output().unwrap();
            assert!(!output.status.success(), "{role}: {output:?}");
            assert!(output.stdout.is_empty(), "{role}: {output:?}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains("could not create directory log"),
                "{role}: {stderr}"
            );
        }
    }
    // SSH configuration may be resolved before bootstrap option validation.
    // Keep this logging test independent of that ordering and the host's SSH.
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, "", 0, "")
        .args(["--silent", "--logtostdout", "--no-exit", "--logdir"])
        .arg(blocker.join("logs"))
        .arg("example.invalid")
        .output()
        .unwrap();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--no-exit requires --command"), "{stderr}");
    assert!(!stderr.contains("log"), "{stderr}");
    assert_eq!(fs::read_to_string(blocker).unwrap(), "untouched");
}

struct FakeSsh {
    dir: TestDir,
    argv: PathBuf,
    stdin: PathBuf,
    client_pids: PathBuf,
}

impl Drop for FakeSsh {
    fn drop(&mut self) {
        for invocation in self.invocations() {
            for argument in invocation {
                if let Some(path) = argument.strip_prefix("-oControlPath=") {
                    let path = std::path::Path::new(path);
                    let _ = fs::remove_file(path);
                    if let Some(parent) = path.parent() {
                        let _ = fs::remove_dir(parent);
                    }
                }
            }
        }
    }
}

impl FakeSsh {
    fn new() -> Self {
        let dir = TestDir::new("ssh");
        let script = dir.0.join("ssh");
        let argv = dir.0.join("argv");
        let stdin = dir.0.join("stdin");
        let client_pids = dir.0.join("client_pids");
        fs::write(
            &script,
            r#"#!/bin/sh
control_path=
for arg in "$@"; do
  printf "%s\0" "$arg" >> "$ET_FAKE_ARGV"
  case "$arg" in -oControlPath=*) control_path=${arg#-oControlPath=} ;; esac
done
printf "\0" >> "$ET_FAKE_ARGV"
# Record the invoking `et` client's pid so tests can assert the ControlPath
# carries no per-process component. $PPID is that client, not this shell's own
# pid, which is what makes the assertion meaningful.
if [ -n "$ET_FAKE_CLIENT_PIDS" ]; then
  echo "$PPID" >> "$ET_FAKE_CLIENT_PIDS"
fi
if [ "$1" = "-O" ] && [ "$2" = "check" ]; then
  printf "%s" "$ET_FAKE_MASTER_STDERR" >&2
  if [ -n "$control_path" ]; then
    [ -e "$control_path" ] && exit 0
    exit 255
  fi
  exit "${ET_FAKE_USER_MASTER_EXIT:-255}"
fi
if [ "$1" = "-MNf" ]; then
  if [ "${ET_FAKE_MASTER_EXIT:-0}" -ne 0 ]; then
    exit "$ET_FAKE_MASTER_EXIT"
  fi
  if [ -n "$control_path" ]; then
    # Real ssh -MNf creates a UNIX SOCKET, and the client refuses anything
    # else, so a regular file here would make every later session fall back.
    "$ET_FAKE_MKSOCKET" "$control_path" || exit 255
  fi
fi
if [ "$1" = "-G" ]; then
  for arg in "$@"; do
    if [ "$arg" = "-oSetEnv=ET_RS_CONFIG_SENTINEL=1" ]; then
      printf "%s" "$ET_FAKE_BASELINE_CONFIG"
      exit 0
    fi
  done
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
        fs::write(&client_pids, []).unwrap();
        Self {
            dir,
            argv,
            stdin,
            client_pids,
        }
    }

    fn command(&self, config: &str, stdout: &str, exit: i32, stderr: &str) -> Command {
        let mut baseline = String::new();
        let mut inserted = false;
        for line in config.split_inclusive('\n') {
            if line.starts_with("setenv ") {
                if !inserted {
                    baseline.push_str("setenv ET_RS_CONFIG_SENTINEL=1\n");
                    inserted = true;
                }
            } else {
                baseline.push_str(line);
            }
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
        command
            .env_clear()
            .env("PATH", &self.dir.0)
            .env("TMPDIR", &self.dir.0)
            .env("ET_FAKE_ARGV", &self.argv)
            .env("ET_FAKE_STDIN", &self.stdin)
            .env("ET_FAKE_CONFIG", config)
            .env("ET_FAKE_BASELINE_CONFIG", baseline)
            .env("ET_FAKE_STDOUT", stdout)
            .env("ET_FAKE_STDERR", stderr)
            .env("ET_FAKE_EXIT", exit.to_string())
            .env("ET_FAKE_PROBE_STDOUT", "__ET_COMSPEC__%ComSpec%\n")
            .env("ET_FAKE_PROBE_EXIT", "0")
            .env("ET_FAKE_MASTER_EXIT", "0")
            .env("ET_FAKE_USER_MASTER_EXIT", "255")
            .env("ET_FAKE_MKSOCKET", env!("CARGO_BIN_EXE_mksocket"))
            .env("ET_FAKE_CLIENT_PIDS", &self.client_pids)
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

    /// Operational invocations with ET's private multiplexing arguments
    /// removed, for assertions unrelated to the control-master lifecycle.
    fn work_invocations(&self) -> Vec<Vec<String>> {
        self.invocations()
            .into_iter()
            .filter(|argv| argv.first().is_some_and(|arg| arg != "-MNf" && arg != "-O"))
            .filter(|argv| {
                !argv
                    .iter()
                    .any(|arg| arg == "-oSetEnv=ET_RS_CONFIG_SENTINEL=1")
            })
            .map(|argv| {
                argv.into_iter()
                    .filter(|arg| arg != "-oControlMaster=no" && !arg.starts_with("-oControlPath="))
                    .collect()
            })
            .collect()
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
fn ssh_config_remote_forward_is_omitted_from_initial_payload() {
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

    assert!(payload.reversetunnels.is_empty());
    assert_eq!(fake.work_invocations()[0], ["-G", "-T", "server-alias"]);
}

#[test]
fn ssh_config_remote_forward_is_omitted_with_explicit_local_forward() {
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

    assert!(payload.reversetunnels.is_empty());
}

#[test]
fn ssh_config_nonlocal_local_destinations_are_accepted_and_remote_rows_omitted() {
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
    assert!(payload.reversetunnels.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("WARNING"))
            .count(),
        0
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
    assert!(payload.reversetunnels.is_empty());
    for reason in [
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
    assert_eq!(fake.work_invocations(), [["-G", "-T", "server-alias"]]);
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
    assert_eq!(fake.work_invocations(), [["-G", "-T", "server-alias"]]);
}

#[test]
fn only_malformed_imported_local_forwards_are_rejected() {
    // Given
    let base_config = concat!(
        "host server-alias\n",
        "user config-user\n",
        "hostname 127.0.0.1\n",
        "port 22\n",
    );

    let fake = FakeSsh::new();
    let local = fake
        .command(
            &format!("{base_config}localforward unsupported\n"),
            VALID_MARKER,
            0,
            "",
        )
        .args(["-N", "-t", "5555:22", "server-alias:1"])
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(2), "{}", stderr(&local));
    assert!(stderr(&local).contains("malformed localforward"));

    let fake = FakeSsh::new();
    let remote = fake
        .command(
            &format!("{base_config}remoteforward 1492 [127.0.0.1]:1492 unexpected\n"),
            VALID_MARKER,
            0,
            "",
        )
        .args(["-N", "-r", "3000:4000", "server-alias:1"])
        .output()
        .unwrap();
    assert_eq!(remote.status.code(), Some(1), "{}", stderr(&remote));
    assert!(!stderr(&remote).contains("malformed remoteforward"));
}

#[test]
fn explicit_cli_remote_forwards_are_deduplicated_while_config_rows_are_omitted() {
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
    assert_eq!(ports, [(Some(3000), Some(4000)), (Some(1492), Some(1492)),]);
}

#[test]
fn bootstrap_ssh_invocations_share_a_private_session_control_path() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 8, "{invocations:?}");
    assert_eq!(invocations[0], ["-G", "-T", "server-alias"]);
    assert_eq!(&invocations[1][..2], ["-O", "check"]);
    assert!(invocations[1]
        .iter()
        .all(|arg| !arg.starts_with("-oControlPath=")));

    let control_argument = invocations[4]
        .iter()
        .find(|arg| arg.starts_with("-oControlPath="))
        .expect("master start must name a ControlPath");
    let control_path = control_argument.strip_prefix("-oControlPath=").unwrap();
    let path = std::path::Path::new(control_path);
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap();
    assert_eq!(file_name.len(), 32);
    assert!(file_name.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(path
        .parent()
        .and_then(|dir| dir.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("et-ssh-")));
    assert!(path.is_absolute(), "{path:?}");

    assert_eq!(invocations[4][0], "-MNf");
    assert!(invocations[4]
        .iter()
        .any(|arg| arg == "-oControlMaster=yes"));
    assert!(invocations[4]
        .iter()
        .any(|arg| arg == "-oControlPersist=15"));
    assert_eq!(invocations[4].last().unwrap(), "config-user@server-alias");

    let private_options = ["-oControlMaster=no", control_argument.as_str()];
    for invocation in [&invocations[2], &invocations[3], &invocations[5]] {
        assert_eq!(
            &invocation[..4],
            ["-O", "check", private_options[0], private_options[1]]
        );
    }
    for invocation in &invocations[6..=7] {
        assert_eq!(&invocation[..2], private_options);
    }
    assert!(invocations[6]
        .last()
        .unwrap()
        .contains(WINDOWS_PROBE_SENTINEL));
    assert!(invocations[7].last().unwrap().starts_with("printf '%s\\n'"));
    assert!(
        path.exists(),
        "ControlPersist socket did not survive the session"
    );
}

#[test]
fn control_master_status_is_not_forwarded_to_client_stderr() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("ET_FAKE_MASTER_STDERR", "Master running (pid=1234)\n")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("Master running"),
        "control-master status leaked to the user: {}",
        stderr(&output),
    );
}

#[test]
fn control_path_is_stable_for_a_destination_and_distinct_between_destinations() {
    let fake = FakeSsh::new();
    let mut paths = Vec::new();
    for (destination, config) in [
        ("server-alias", RESOLVED_CONFIG),
        ("server-alias", RESOLVED_CONFIG),
        (
            "other-alias",
            "host other-alias\nuser other-user\nhostname 127.0.0.1\nport 22\n",
        ),
    ] {
        let before = fake.invocations().len();
        let (port, server) = initial_payload_server();
        let output = fake
            .command(config, VALID_MARKER, 0, "")
            .args(["-N", &format!("{destination}:{port}")])
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let invocation = fake.invocations();
        let session_paths = invocation[before..]
            .iter()
            .flat_map(|argv| argv.iter())
            .filter_map(|arg| arg.strip_prefix("-oControlPath="))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(session_paths.len(), 1, "{invocation:?}");
        paths.push((*session_paths.first().unwrap()).to_owned());
    }
    assert_eq!(paths.len(), 3, "{paths:?}");
    assert_eq!(paths[0], paths[1], "same destination: {paths:?}");
    assert_ne!(paths[0], paths[2], "different destinations: {paths:?}");
    // Equality alone cannot prove the path is pid-free: every case above runs
    // in ONE `et` process per invocation, and repeated invocations would each
    // embed their own pid, so a pid-bearing path could still compare equal to
    // itself. Assert the absence of any per-process or per-call component
    // directly, so a master cannot silently become per-session again.
    let pids = fake
        .invocations()
        .iter()
        .flat_map(|argv| argv.iter())
        .filter_map(|arg| arg.strip_prefix("-oControlPath="))
        .filter_map(|path| std::path::Path::new(path).file_name()?.to_str())
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        pids.len(),
        2,
        "exactly two distinct destinations were used: {pids:?}"
    );
    // Assert against the pids of the `et` clients that actually ran. Searching
    // for the harness's own pid would be unsound: it is a different process,
    // and a 32-hex hash can contain any decimal digits by coincidence.
    let client_pids = fs::read_to_string(&fake.client_pids).unwrap();
    let client_pids = client_pids
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!client_pids.is_empty(), "fake ssh recorded no client pid");
    for path in &paths {
        for pid in &client_pids {
            assert!(
                !path.contains(pid),
                "ControlPath must not embed the client pid {pid}: {path}"
            );
        }
    }
    for path in paths {
        let file_name = std::path::Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        assert_eq!(file_name.len(), 32, "{path}");
        assert!(
            file_name.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{path}"
        );
        for serial in 0..4u32 {
            assert!(
                !file_name.ends_with(&format!(".{serial}")),
                "ControlPath must not embed a per-call serial: {path}"
            );
        }
    }
}

/// A hostile (or merely stale-and-wrong) object at the control socket path is
/// refused, and the session still completes over unmultiplexed SSH instead of
/// failing. Runs the real client end-to-end, so it proves the refusal is wired
/// into the bootstrap path and not just into the helper.
#[cfg(unix)]
#[test]
fn bootstrap_falls_back_when_control_socket_path_is_not_a_socket() {
    // First run: learn the exact path this destination hashes to.
    let fake = FakeSsh::new();
    let (probe_port, probe_server) = initial_payload_server();
    let probe = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N", &format!("server-alias:{probe_port}")])
        .output()
        .unwrap();
    probe_server.join().unwrap();
    assert!(probe.status.success(), "{}", stderr(&probe));
    let control_path = fake
        .invocations()
        .iter()
        .flat_map(|argv| argv.iter())
        .find_map(|arg| arg.strip_prefix("-oControlPath="))
        .expect("first run must establish an ET control path")
        .to_owned();
    // Replace the socket with a regular file: exactly what a planted or stale
    // non-socket object looks like at the predictable path. The guard removes
    // it even if an assertion below panics, because the control root may be
    // the shared /tmp fallback where a leftover non-socket would make sibling
    // tests refuse their own correctly hashed path.
    struct Planted(String);
    impl Drop for Planted {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _ = std::fs::remove_file(&control_path);
    std::fs::write(&control_path, b"not a socket").unwrap();
    let planted_guard = Planted(control_path.clone());

    // Second run: must refuse the path and still succeed unmultiplexed.
    let (port, server) = initial_payload_server();
    let before = fake.invocations().len();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "a refused control socket must not fail the session: {}",
        stderr(&output)
    );
    let invocations = fake.invocations();
    for invocation in &invocations[before..] {
        assert!(
            invocation
                .iter()
                .all(|arg| !arg.starts_with("-oControlPath=")),
            "refused socket must not be handed to ssh: {invocation:?}"
        );
    }
    // The planted file must be left alone, not silently unlinked.
    let planted = std::fs::read(&control_path);
    drop(planted_guard);
    assert_eq!(
        planted.ok().as_deref(),
        Some(&b"not a socket"[..]),
        "refusal must not remove another party's file"
    );
}

#[test]
fn bootstrap_falls_back_when_private_control_master_fails() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("ET_FAKE_MASTER_EXIT", "255")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 7, "{invocations:?}");
    assert_eq!(invocations[0][0], "-G");
    assert_eq!(&invocations[1][..2], ["-O", "check"]);
    assert_eq!(invocations[4][0], "-MNf");
    for invocation in &invocations[5..] {
        assert!(
            invocation
                .iter()
                .all(|arg| arg != "-oControlMaster=no" && !arg.starts_with("-oControlPath=")),
            "fallback invocation unexpectedly uses ET control socket: {invocation:?}"
        );
    }
    let control_path = invocations[4]
        .iter()
        .find_map(|arg| arg.strip_prefix("-oControlPath="))
        .unwrap();
    assert!(!std::path::Path::new(control_path).exists());
}

#[test]
fn working_user_control_master_is_preferred_without_overriding_its_path() {
    let (port, server) = initial_payload_server();
    let fake = FakeSsh::new();
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .env("ET_FAKE_USER_MASTER_EXIT", "0")
        .args(["-N", &format!("server-alias:{port}")])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.invocations();
    assert_eq!(invocations.len(), 4, "{invocations:?}");
    assert_eq!(invocations[0], ["-G", "-T", "server-alias"]);
    assert_eq!(&invocations[1][..2], ["-O", "check"]);
    assert!(invocations
        .iter()
        .flatten()
        .all(|arg| arg != "-MNf" && !arg.starts_with("-oControlPath=")));
}

const WINDOWS_PROBE_SENTINEL: &str = "__ET_COMSPEC__";

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

    let invocations = fake.work_invocations();
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
        &argv[..6],
        [
            "-oClearAllForwardings=yes",
            "-oRemoteCommand=none",
            "-oPermitLocalCommand=no",
            "-oSessionType=default",
            "-oStrictHostKeyChecking=no",
            "test-user@server-alias",
        ]
    );
    let prefix = "printf '%s\\n' '";
    let value = argv[6].strip_prefix(prefix).unwrap();
    let provisional = value.split_once("_xterm-256color'").unwrap().0;
    let (id, key) = parse_id_passkey(provisional).unwrap();
    assert!(id.starts_with("XXX"));
    assert_eq!(id.len(), 16);
    assert_eq!(key.len(), 32);
    assert_eq!(
        argv[6],
        format!(
            "printf '%s\\n' '{provisional}_xterm-256color' | '/opt/et terminal' '--verbose=2' '--serverfifo=/tmp/server fifo'"
        )
    );
}

#[test]
fn effective_ssh_config_drives_native_jump_agent_and_environment() {
    for cli_override in [false, true] {
        let (port, server) = initial_payload_server_with_error(Some("captured config payload"));
        let fake = FakeSsh::new();
        let config = format!("{RESOLVED_CONFIG}proxyjump config-user@jump-alias:2200\nforwardagent yes\nidentityagent /tmp/config agent\nsetenv APP=two words=a=b  \nsetenv EMPTY=\nsetenv LANG=config-locale\nsetenv TERM=bad-term\nsetenv COLORTERM=bad-color\nsetenv SSH_AUTH_SOCK=bad-agent\nsetenv ET_PIPE=bad-pipe\n");
        let mut command = fake.command(&config, VALID_MARKER, 0, "");
        command
            .env("TERM", "xterm-ghostty")
            .env("COLORTERM", "truecolor")
            .env("LANG", "inherited-locale")
            .env("SSH_AUTH_SOCK", "/tmp/env-agent")
            .args([
                "-N",
                "--jport",
                &port.to_string(),
                "--jserverfifo=/tmp/jump.fifo",
                "-r",
                "ET_PIPE:remote-pipe",
            ]);
        if cli_override {
            command.args([
                "--jumphost=cli-user@cli-jump:2300",
                "--ssh-socket=/tmp/cli-agent",
            ]);
        }
        let output = command.arg("destination:2022").output().unwrap();
        let payload = server.join().unwrap();
        assert!(
            stderr(&output).contains("captured config payload"),
            "{}",
            stderr(&output)
        );
        assert_eq!(payload.jumphost, Some(true));
        assert_eq!(payload.environmentvariables.len(), 4);
        for (name, value) in [
            ("APP", "two words=a=b  "),
            ("EMPTY", ""),
            ("LANG", "config-locale"),
            ("COLORTERM", "truecolor"),
        ] {
            assert_eq!(payload.environmentvariables[name], value);
        }
        let agent = payload
            .reversetunnels
            .iter()
            .find(|row| row.environmentvariable.as_deref() == Some("SSH_AUTH_SOCK"))
            .unwrap();
        assert!(agent.source.is_none());
        assert_eq!(
            agent.destination.as_ref().unwrap().name.as_deref(),
            Some(if cli_override {
                "/tmp/cli-agent"
            } else {
                "/tmp/config agent"
            })
        );
        let work = fake.work_invocations();
        assert_eq!(
            fake.invocations()
                .iter()
                .filter(|args| args
                    .iter()
                    .any(|arg| arg == "-oSetEnv=ET_RS_CONFIG_SENTINEL=1"))
                .count(),
            2
        );
        let (jump, user_host, ssh_port) = if cli_override {
            ("cli-user@cli-jump:2300", "cli-user@cli-jump", "2300")
        } else {
            (
                "config-user@jump-alias:2200",
                "config-user@jump-alias",
                "2200",
            )
        };
        if cli_override {
            assert_eq!(
                work[0],
                [
                    "-G",
                    "-T",
                    "-oProxyJump=cli-user@cli-jump:2300",
                    "destination"
                ]
            );
        }
        assert_eq!(&work[1][..2], ["-J", jump]);
        assert_eq!(&work[2][..2], ["-J", jump]);
        assert_eq!(work[3], ["-G", "-T", "-p", ssh_port, user_host]);
        assert_eq!(&work[4][..2], ["-p", ssh_port]);
        assert!(work[4].contains(&user_host.to_owned()));
        assert!(work[4]
            .last()
            .unwrap()
            .contains("'--jump' '--dsthost=127.0.0.1' '--dstport=2022'"));
    }
}

#[test]
fn effective_setenv_shares_terminal_and_jumphost_packet_budgets() {
    for jump in [false, true] {
        for (count, value_length, expected_count) in [(140, 1, 128), (20, 4096, 15)] {
            let (port, server) = initial_payload_server();
            let fake = FakeSsh::new();
            let mut config = RESOLVED_CONFIG.to_owned();
            if jump {
                config.push_str("proxyjump jump-alias\n");
            }
            for index in 0..count {
                config.push_str(&format!(
                    "setenv APP_{index:03}={}\n",
                    "x".repeat(value_length)
                ));
            }
            let output = fake
                .command(&config, VALID_MARKER, 0, "")
                .args([
                    "-N",
                    "--jport",
                    &port.to_string(),
                    &format!("destination:{port}"),
                ])
                .output()
                .unwrap();
            let payload = server.join().unwrap();
            assert!(output.status.success(), "{}", stderr(&output));
            assert_eq!(payload.environmentvariables.len(), expected_count);
            assert_eq!(
                payload.environmentvariables["APP_000"],
                "x".repeat(value_length)
            );
            assert!(!payload
                .environmentvariables
                .contains_key(&format!("APP_{expected_count:03}")));
            let term = TermInit {
                environmentnames: payload.environmentvariables.keys().cloned().collect(),
                environmentvalues: payload.environmentvariables.values().cloned().collect(),
                flowcontrol: payload.flowcontrol,

                no_pty: None,
                command: None,

                no_shell: None,
            };
            assert!(
                Packet::new(TerminalPacketType::TerminalInit as u8, term.encode_to_vec())
                    .wire_len()
                    <= MAX_LOCAL_PACKET_LEN
            );
            if jump {
                assert_eq!(payload.jumphost, Some(true));
                assert!(
                    Packet::new(
                        TerminalPacketType::JumphostInit as u8,
                        payload.encode_to_vec()
                    )
                    .wire_len()
                        <= MAX_LOCAL_PACKET_LEN
                );
            }
        }
    }
}

#[test]
fn windows_sessions_receive_explicit_setenv_without_inherited_locale() {
    for explicit in [false, true] {
        let (port, server) = initial_payload_server_with_error(Some("captured Windows payload"));
        let fake = FakeSsh::new();
        let config = format!("{RESOLVED_CONFIG}proxyjump jump-alias\nsetenv APP=literal & value\nsetenv app=wrong-case-duplicate\nsetenv COLORTERM=explicit-color\nsetenv LANG=explicit-locale\nsetenv term=do-not-override\nsetenv et_pipe=do-not-override\n");
        let mut command = fake.command(&config, VALID_MARKER, 0, "");
        command
            .env("TERM", "xterm-ghostty")
            .env("COLORTERM", "truecolor")
            .env("LANG", "inherited")
            .env("LC_ALL", "inherited")
            .env(
                "ET_FAKE_PROBE_STDOUT",
                "__ET_COMSPEC__C:\\Windows\\cmd.exe\r\n",
            )
            .args([
                "-N",
                "--jport",
                &port.to_string(),
                "-r",
                "ET_PIPE:remote-pipe",
            ]);
        if explicit {
            command.arg("--winserver");
        }
        let output = command.arg("destination:2022").output().unwrap();
        let payload = server.join().unwrap();
        assert!(
            stderr(&output).contains("captured Windows payload"),
            "{}",
            stderr(&output)
        );
        assert_eq!(payload.environmentvariables.len(), 3);
        for (name, value) in [
            ("APP", "literal & value"),
            ("COLORTERM", "explicit-color"),
            ("LANG", "explicit-locale"),
        ] {
            assert_eq!(payload.environmentvariables[name], value);
        }
        assert_eq!(payload.jumphost, Some(true));
        assert!(!fake
            .work_invocations()
            .iter()
            .any(|args| args.iter().any(|arg| arg.contains("literal & value"))));
    }
}

#[test]
fn disabled_agent_config_never_falls_back_to_environment_socket() {
    for options in [
        "forwardagent yes\nidentityagent none\n",
        "forwardagent no\nidentityagent /tmp/config-agent\n",
    ] {
        let (port, server) = initial_payload_server();
        let fake = FakeSsh::new();
        let output = fake
            .command(&format!("{RESOLVED_CONFIG}{options}"), VALID_MARKER, 0, "")
            .env("SSH_AUTH_SOCK", "/tmp/env-agent")
            .args(["-N", &format!("destination:{port}")])
            .output()
            .unwrap();
        let payload = server.join().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(payload.reversetunnels.is_empty());
    }
}

#[test]
fn unsupported_effective_config_fails_before_bootstrap() {
    for row in [
        "proxyjump first,second",
        "proxyjump user@jump:0",
        "proxyjump [::1]trailing",
        "proxyjump $(bad)",
        "setenv BAD-NAME=value",
        "forwardagent yes\nidentityagent $UNRESOLVED",
    ] {
        let fake = FakeSsh::new();
        let output = fake
            .command(&format!("{RESOLVED_CONFIG}{row}\n"), VALID_MARKER, 0, "")
            .args(["-N", "destination"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{row}");
        assert_eq!(fake.work_invocations(), [vec!["-G", "-T", "destination"]]);
    }
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

        no_pty: None,
        command: None,

        no_shell: None,
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

    let invocations = fake.work_invocations();
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

    let invocations = fake.work_invocations();
    assert_eq!(invocations.len(), 2, "{invocations:?}");
    assert_eq!(invocations[0], ["-G", "-T", "127.0.0.1"]);
    let bootstrap = &invocations[1];
    assert_eq!(
        &bootstrap[..4],
        [
            "-oClearAllForwardings=yes",
            "-oRemoteCommand=none",
            "-oPermitLocalCommand=no",
            "-oSessionType=default",
        ]
    );
    assert_eq!(bootstrap[4], "config-user@127.0.0.1");
    let input = bootstrap[5]
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
    let fake = FakeSsh::new();
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
        let output = fake
            .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
    }
    assert!(fake.invocations().iter().all(|args| args[0] == "-G"));
}

#[test]
fn excessive_unique_tunnel_environment_names_fail_before_ssh_bootstrap() {
    let fake = FakeSsh::new();
    let mut arguments = vec!["-N".to_owned()];
    for index in 0..129 {
        arguments.extend([
            "-r".to_owned(),
            format!("ET_PIPE_{index:03}:remote-{index}"),
        ]);
    }
    arguments.push("example.test".to_owned());
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("terminal environment has 129 reserved names; maximum is 128"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fake.invocations().len(), 1);
}

#[test]
fn colorterm_counts_toward_the_tunnel_environment_limit() {
    let fake = FakeSsh::new();
    let mut arguments = vec!["-N".to_owned()];
    for index in 0..128 {
        arguments.extend([
            "-r".to_owned(),
            format!("ET_PIPE_{index:03}:remote-{index}"),
        ]);
    }
    arguments.push("server-alias:1".to_owned());
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
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
    assert_eq!(fake.invocations().len(), 1);
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
    let fake = FakeSsh::new();
    let environment_name = format!("E{}", "T".repeat(MAX_LOCAL_PACKET_LEN));
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
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
    assert_eq!(fake.invocations().len(), 1);
}

#[test]
fn oversized_jumphost_initialization_fails_before_ssh_bootstrap() {
    let fake = FakeSsh::new();
    let mut arguments = vec![
        "-N".to_owned(),
        "--jumphost".to_owned(),
        "jump-alias".to_owned(),
    ];
    let destination = format!("remote-{}", "x".repeat(500));
    for index in 0..128 {
        arguments.extend(["-r".to_owned(), format!("ET_PIPE:{destination}{index}")]);
    }
    arguments.push("example.test".to_owned());
    let output = fake
        .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
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
    assert_eq!(fake.invocations().len(), 1);
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

    let invocations = fake.work_invocations();
    // -G dst, login-shell probe, dst bootstrap through -J, -G jumphost,
    // jump bootstrap.
    assert_eq!(invocations.len(), 5, "{invocations:?}");
    assert_eq!(
        invocations[0],
        [
            "-G",
            "-T",
            "-oProxyJump=jump.example",
            "test-user@server-alias"
        ]
    );
    assert!(invocations[1].last().unwrap().contains("__ET_COMSPEC__"));
    let destination = &invocations[2];
    assert_eq!(destination[0], "-J");
    assert_eq!(destination[1], "jump.example");
    assert_eq!(
        &destination[2..6],
        [
            "-oClearAllForwardings=yes",
            "-oRemoteCommand=none",
            "-oPermitLocalCommand=no",
            "-oSessionType=default",
        ]
    );
    assert_eq!(destination[6], "test-user@server-alias");
    let destination_command = &destination[7];
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
    assert_eq!(
        &jump[..4],
        [
            "-oClearAllForwardings=yes",
            "-oRemoteCommand=none",
            "-oPermitLocalCommand=no",
            "-oSessionType=default",
        ]
    );
    assert_eq!(jump[4], "jump.example");
    let jump_command = &jump[5];
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
fn destination_ssh_options_stay_off_jumphost_and_ssh_config_reaches_both() {
    let directory = TestDir::new("ssh-config-file");
    let config = directory.0.join("ssh_config");
    fs::write(&config, "Host *\n").unwrap();
    let config_path = config.to_str().unwrap();

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
        .args([
            "-N",
            "--jumphost",
            "jump.example",
            "--jport",
            &address.port().to_string(),
            "--ssh-option",
            "IdentityFile=/tmp/destination-id",
            "--ssh-option",
            "StrictHostKeyChecking=no",
            "--ssh-config",
            config_path,
            "test-user@server-alias:2022",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.work_invocations();
    assert_eq!(invocations.len(), 5, "{invocations:?}");
    assert_eq!(
        invocations[0],
        [
            "-G",
            "-T",
            "-F",
            config_path,
            "-oProxyJump=jump.example",
            "-oIdentityFile=/tmp/destination-id",
            "-oStrictHostKeyChecking=no",
            "test-user@server-alias"
        ]
    );
    let destination = &invocations[2];
    assert_eq!(&destination[..2], ["-F", config_path]);
    assert!(destination.iter().any(|arg| arg == "-J"));
    assert!(destination
        .iter()
        .any(|arg| arg == "-oIdentityFile=/tmp/destination-id"));
    assert!(destination
        .iter()
        .any(|arg| arg == "-oStrictHostKeyChecking=no"));
    assert_eq!(
        invocations[3],
        ["-G", "-T", "-F", config_path, "jump.example"]
    );
    let jump = &invocations[4];
    assert_eq!(&jump[..2], ["-F", config_path]);
    for option in [
        "-oIdentityFile=/tmp/destination-id",
        "-oStrictHostKeyChecking=no",
    ] {
        assert!(
            !jump.iter().any(|arg| arg == option),
            "direct jumphost argv must not replay {option}: {jump:?}"
        );
    }
    assert!(jump.iter().any(|arg| arg == "jump.example"), "{jump:?}");
}

#[test]
fn no_ssh_config_disables_config_on_destination_and_jumphost() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        bound(&stream);
        let _request = read_request(&mut stream).unwrap();
        write_response(&mut stream, &response_status(ConnectStatus::NewClient)).unwrap();
        let key = passkey_to_key(SERVER_KEY).unwrap();
        let mut connection = Connection::new_server(stream, &key);
        let packet = connection.read_packet().unwrap();
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
        .args([
            "-N",
            "--jumphost",
            "jump.example",
            "--jport",
            &address.port().to_string(),
            "--no-ssh-config",
            "test-user@server-alias:2022",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let invocations = fake.work_invocations();
    assert_eq!(
        invocations[0],
        [
            "-G",
            "-T",
            "-F",
            "none",
            "-oProxyJump=jump.example",
            "test-user@server-alias"
        ]
    );
    assert_eq!(&invocations[2][..2], ["-F", "none"]);
    assert_eq!(invocations[3], ["-G", "-T", "-F", "none", "jump.example"]);
    assert_eq!(&invocations[4][..2], ["-F", "none"]);
}

#[test]
fn ssh_config_path_validation_fails_closed_before_ssh() {
    let directory = TestDir::new("ssh-config-bad");
    let missing = directory.0.join("missing");
    let not_file = directory.0.join("dir");
    fs::create_dir(&not_file).unwrap();
    let link = directory.0.join("link");
    let regular = directory.0.join("ssh_config");
    fs::write(&regular, "Host *\n").unwrap();
    std::os::unix::fs::symlink(&regular, &link).unwrap();

    let fake = FakeSsh::new();
    let cases: &[(&[&str], &str)] = &[
        (
            &["-N", "--ssh-config", "relative", "example.test"],
            "must be an absolute path or 'none'",
        ),
        (
            &["-N", "--ssh-config", "/tmp/et config", "example.test"],
            "must contain only ASCII letters, digits",
        ),
        (
            &[
                "-N",
                "--ssh-config",
                missing.to_str().unwrap(),
                "example.test",
            ],
            "must name a readable, non-symlink regular file",
        ),
        (
            &[
                "-N",
                "--ssh-config",
                not_file.to_str().unwrap(),
                "example.test",
            ],
            "must name a readable, non-symlink regular file",
        ),
        (
            &["-N", "--ssh-config", link.to_str().unwrap(), "example.test"],
            "must name a readable, non-symlink regular file",
        ),
    ];
    for (args, message) in cases {
        let output = fake
            .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
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
    assert!(
        fake.invocations().is_empty(),
        "invalid --ssh-config must fail before ssh: {:?}",
        fake.invocations()
    );
}

#[test]
fn malformed_jumphost_and_jserverfifo_fail_before_ssh_bootstrap() {
    let fake = FakeSsh::new();
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
            "multi-hop jumphost is unsupported",
        ),
        (
            // `--jserverfifo` only makes sense together with `--jumphost`.
            &["-N", "--jserverfifo=/tmp/fifo", "example.test"],
            "--jserverfifo requires --jumphost",
        ),
    ];
    for (args, message) in cases {
        let output = fake
            .command(RESOLVED_CONFIG, VALID_MARKER, 0, "")
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
    assert!(fake.invocations().iter().all(|args| args[0] == "-G"));
}
