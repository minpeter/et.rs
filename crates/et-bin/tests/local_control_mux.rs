#![cfg(unix)]
//! Real client -> encrypted ET transport -> server -> PTY shell. Only SSH
//! authentication is replaced by a local launcher; mux/control are real IPC.
use prost::Message;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

const LIMIT: Duration = Duration::from_secs(15);

struct Stack {
    root: PathBuf,
    router: PathBuf,
    terminal: PathBuf,
    port: u16,
    server: Child,
}
impl Stack {
    fn start() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "et-local-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let router = root.join("router");
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let config = root.join("config");
        fs::write(
            &config,
            format!(
                "[Networking]\nport={port}\nbind_ip=127.0.0.1\n[Debug]\nserverfifo={}\n",
                router.display()
            ),
        )
        .unwrap();
        let mut server = Command::new(env!("CARGO_BIN_EXE_et"))
            .args(["server", "--cfgfile"])
            .arg(config)
            .env("HOME", &root)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = server.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        assert!(rx
            .recv_timeout(LIMIT)
            .unwrap()
            .starts_with("ETSERVER_READY"));
        let ssh = root.join("ssh");
        fs::write(&ssh, "#!/bin/sh\nif [ \"$1\" = -G ]; then printf 'hostname 127.0.0.1\\nuser tester\\nport 22\\n'; exit 0; fi\nif [ \"$1\" = -O ] || [ \"$1\" = -MNf ]; then exit 255; fi\nprintf 'bootstrap\\n' >> \"$HOME/ssh-count\"\nfor last do :; done\nexec /bin/sh -c \"$last\"\n").unwrap();
        fs::set_permissions(ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let terminal = root.join("etterminal");
        symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
        Self {
            root,
            router,
            terminal,
            port,
            server,
        }
    }
    fn client(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
        command
            .env("HOME", &self.root)
            .env(
                "PATH",
                format!("{}:{}", self.root.display(), std::env::var("PATH").unwrap()),
            )
            .env("TERM", "xterm")
            .env_remove("ET_DEBUG")
            .args([
                "--no-ssh-config",
                "--remote-shell",
                "posix",
                "--terminal-path",
            ])
            .arg(&self.terminal)
            .arg("--serverfifo")
            .arg(&self.router)
            .arg("--port")
            .arg(self.port.to_string());
        command
    }
    fn mux(&self, socket: &Path, action: &str) -> Command {
        let mut command = self.client();
        command.arg("-S").arg(socket).args(["-O", action]);
        command
    }
    fn start_control(&self, command: &str) -> PathBuf {
        let output = output(self.client().args([
            "--ctl",
            "--name",
            "work",
            "--command",
            command,
            "127.0.0.1",
        ]));
        assert!(output.status.success(), "{output:?}");
        let socket = self.root.join(".et/control/work.sock");
        assert!(socket.exists());
        socket
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        // Stop every local daemon before its backing server and directory.
        for path in [
            self.root.join(".et/control/work.sock"),
            self.root.join("ctl"),
        ] {
            if path.exists() {
                let _ = ctl_result(&path, 5, &[]);
            }
        }
        let mux = self.root.join("mux");
        if mux.exists() {
            let _ = self
                .mux(&mux, "exit")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.server.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        if self.server.wait_timeout(LIMIT).ok().flatten().is_none() {
            let _ = self.server.kill();
            let _ = self.server.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn output(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if child.wait_timeout(LIMIT).unwrap().is_none() {
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!("client timeout: {output:?}");
    }
    child.wait_with_output().unwrap()
}
fn ctl_result(socket: &Path, opcode: u8, payload: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
    let mut socket = UnixStream::connect(socket)?;
    socket.set_read_timeout(Some(LIMIT))?;
    socket.set_write_timeout(Some(LIMIT))?;
    socket.write_all(&[opcode])?;
    socket.write_all(&(payload.len() as u32).to_be_bytes())?;
    socket.write_all(payload)?;
    let mut header = [0; 5];
    socket.read_exact(&mut header)?;
    let count = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(count < 4 * 1024 * 1024);
    let mut body = vec![0; count];
    socket.read_exact(&mut body)?;
    Ok((header[0], body))
}
fn ctl(socket: &Path, opcode: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    ctl_result(socket, opcode, payload).unwrap()
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn read_until(socket: &Path, needle: &str) -> Vec<u8> {
    let mut output = Vec::new();
    wait(|| {
        let response = ctl(socket, 3, &(-1_i64).to_be_bytes());
        assert_eq!(response.0, 66);
        output = response.1;
        String::from_utf8_lossy(&output[9..]).contains(needle)
    });
    output
}

#[test]
fn control_protocol_cursors_secret_resize_tombstone_and_adoption() {
    let stack = Stack::start();
    let socket =
        stack.start_control("stty -echo; export ONCE=original; printf 'CT%s\\n' 'L-READY'");
    let first = read_until(&socket, "CTL-READY");
    let cursor: [u8; 8] = first[..8].try_into().unwrap();
    let same = ctl(&socket, 3, &(-1_i64).to_be_bytes());
    assert!(
        same.1.ends_with(&first[9..]),
        "read must be non-destructive"
    );
    let info = String::from_utf8(ctl(&socket, 4, &[]).1).unwrap();
    assert!(info.contains("alive=1\nconnected=1\n"));
    assert!(info.contains("rows=24\ncols=132\n"));
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let resize = et_core::proto::TerminalInfo {
        row: Some(37),
        column: Some(91),
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(ctl(&socket, 2, &resize).0, 64);
    assert_eq!(ctl(&socket, 1, b"stty size\n").0, 64);
    read_until(&socket, "37 91");
    assert_eq!(
        ctl(&socket, 7, b"export CREDENTIAL=super-private-value\n").0,
        64
    );
    assert_eq!(ctl(&socket, 1, b"printf 'SE%s\\n' 'CRET-DONE'\n").0, 64);
    read_until(&socket, "SECRET-DONE");
    let transcript = ctl(&socket, 6, &(-1_i64).to_be_bytes());
    assert_eq!(transcript.0, 68);
    assert!(transcript.1.windows(8).any(|w| w == b"<secret>"));
    assert!(!String::from_utf8_lossy(&transcript.1).contains("super-private-value"));
    let incremental = ctl(&socket, 3, &cursor);
    assert!(!String::from_utf8_lossy(&incremental.1[9..]).contains("CTL-READY"));
    assert_eq!(ctl(&socket, 3, b"bad").0, 65);
    assert_eq!(ctl(&socket, 255, &[]).0, 65);
    assert_eq!(ctl(&socket, 5, &[]).0, 64);
    wait(|| !socket.exists());
    let gone = stack.root.join(".et/control/work.gone");
    assert!(fs::read_to_string(&gone)
        .unwrap()
        .contains("shutdown was requested"));
    let count = fs::read(stack.root.join("ssh-count")).unwrap();
    let wrong_destination = output(
        stack
            .client()
            .args(["--ctl", "--name", "work", "--port"])
            .arg(if stack.port == 2022 { "2023" } else { "2022" })
            .arg("127.0.0.1"),
    );
    assert!(!wrong_destination.status.success(), "{wrong_destination:?}");
    assert!(String::from_utf8_lossy(&wrong_destination.stderr).contains("different destination"));
    assert_eq!(fs::read(stack.root.join("ssh-count")).unwrap(), count);
    let socket = stack.start_control("export ONCE=replayed");
    assert!(!gone.exists());
    assert_eq!(
        fs::read(stack.root.join("ssh-count")).unwrap(),
        count,
        "adoption must not bootstrap SSH again"
    );
    assert_eq!(ctl(&socket, 1, b"printf 'ONCE=%s\\n' \"$ONCE\"\n").0, 64);
    read_until(&socket, "ONCE=original");
    assert_eq!(ctl(&socket, 1, b"exit\n").0, 64);
    wait(|| !socket.exists());
    let saved = stack.root.join(".et/sessions/work");
    assert!(
        !saved.exists(),
        "definite remote end must remove saved credentials"
    );
    let socket = stack.start_control("stty -echo; printf 'FRE%s\\n' 'SH'");
    read_until(&socket, "FRESH");
    assert_eq!(
        fs::read(stack.root.join("ssh-count")).unwrap(),
        [count.as_slice(), b"bootstrap\n"].concat(),
        "same-name restart after remote exit must bootstrap a new session"
    );
    // A different session may replace this name while the old transport is
    // alive; finishing the old transport must preserve the replacement.
    let contents = fs::read_to_string(&saved).unwrap();
    let replacement = contents
        .lines()
        .map(|line| {
            if line.starts_with("id=") {
                "id=replacement-session"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&saved, replacement).unwrap();
    assert_eq!(ctl(&socket, 1, b"exit\n").0, 64);
    wait(|| !socket.exists());
    assert!(fs::read_to_string(&saved)
        .unwrap()
        .contains("\nid=replacement-session\n"));
}

#[test]
fn mux_reuses_transport_commands_propagate_exit_and_forward_cancel_keeps_streams() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    let started = output(stack.client().args(["-M", "-f", "-S"]).arg(&socket).args([
        "-o",
        "ControlPersist=yes",
        "--name",
        "master",
        "127.0.0.1",
    ]));
    assert!(started.status.success(), "{started:?}");
    let count = fs::read(stack.root.join("ssh-count")).unwrap();
    let checked = output(&mut stack.mux(&socket, "check"));
    assert!(checked.status.success(), "{checked:?}");
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Master running (pid="));
    // An independent OpenSSH implementation checks both framing and SCM_RIGHTS,
    // rather than letting the ET encoder and decoder share the same mistake.
    let checked = output(
        Command::new("ssh")
            .args(["-F", "none", "-S"])
            .arg(&socket)
            .args(["-O", "check", "127.0.0.1"]),
    );
    assert!(checked.status.success(), "{checked:?}");
    let passenger = output(
        Command::new("ssh")
            .args(["-F", "none", "-S"])
            .arg(&socket)
            .args([
                "-oBatchMode=yes",
                "-oConnectTimeout=1",
                "-tt",
                "127.0.0.1",
                "printf 'OPEN%s\\n' SSH-MUX; exit 37",
            ]),
    );
    assert_eq!(passenger.status.code(), Some(37), "{passenger:?}");
    assert!(String::from_utf8_lossy(&passenger.stdout).contains("OPENSSH-MUX"));
    for (mode, command, expected, code) in [
        (
            "ControlMaster=auto",
            "printf 'MU%s\\n' 'X-ONE'; exit 23",
            "MUX-ONE",
            23,
        ),
        (
            "ControlMaster=no",
            "printf 'MU%s\\n' 'X-TWO'; exit 7",
            "MUX-TWO",
            7,
        ),
    ] {
        let result = output(
            stack
                .client()
                .arg("-S")
                .arg(&socket)
                .args(["-o", mode])
                .args(["--command", command, "127.0.0.1"]),
        );
        assert_eq!(result.status.code(), Some(code), "{result:?}");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains(expected),
            "{result:?}"
        );
    }
    assert_eq!(fs::read(stack.root.join("ssh-count")).unwrap(), count);
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = echo.local_addr().unwrap().port();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = reserve.local_addr().unwrap().port();
    drop(reserve);
    let spec = format!("127.0.0.1:{source}:127.0.0.1:{destination}");
    let opened = output(stack.mux(&socket, "forward").args(["--tunnel", &spec]));
    assert!(opened.status.success(), "{opened:?}");
    let echo_worker = std::thread::spawn(move || {
        let (mut socket, _) = echo.accept().unwrap();
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        for _ in 0..2 {
            let mut bytes = [0; 3];
            socket.read_exact(&mut bytes).unwrap();
            socket.write_all(&bytes).unwrap();
        }
    });
    let mut forward = TcpStream::connect(("127.0.0.1", source)).unwrap();
    forward.set_read_timeout(Some(LIMIT)).unwrap();
    forward.write_all(b"one").unwrap();
    let mut bytes = [0; 3];
    forward.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"one");
    let cancelled = output(stack.mux(&socket, "cancel").args(["--tunnel", &spec]));
    assert!(cancelled.status.success(), "{cancelled:?}");
    assert!(TcpStream::connect(("127.0.0.1", source)).is_err());
    forward.write_all(b"two").unwrap();
    forward.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"two");
    echo_worker.join().unwrap();
    assert!(output(&mut stack.mux(&socket, "exit")).status.success());
    wait(|| !socket.exists());
}

#[test]
fn mux_controlpersist_expires_and_live_socket_cannot_be_replaced() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    let started = output(stack.client().args(["-M", "-f", "-S"]).arg(&socket).args([
        "-o",
        "ControlPersist=10",
        "127.0.0.1",
    ]));
    assert!(started.status.success(), "{started:?}");
    let count = fs::read(stack.root.join("ssh-count")).unwrap();
    let rejected = output(stack.client().args(["-M", "-f", "-S"]).arg(&socket).args([
        "-o",
        "ControlPersist=yes",
        "127.0.0.1",
    ]));
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read(stack.root.join("ssh-count")).unwrap(),
        count,
        "name collision must fail before remote bootstrap"
    );
    assert!(output(&mut stack.mux(&socket, "check")).status.success());
    wait(|| !socket.exists());
}

#[test]
fn malformed_partial_control_client_does_not_block_healthy_requests() {
    let stack = Stack::start();
    let socket = stack.start_control("stty -echo");
    let mut slow = UnixStream::connect(&socket).unwrap();
    slow.write_all(&[1, 0, 0]).unwrap();
    assert_eq!(ctl(&socket, 4, &[]).0, 67);
    let mut oversized = UnixStream::connect(&socket).unwrap();
    oversized.write_all(&[1, 0x7f, 0xff, 0xff, 0xff]).unwrap();
    oversized.set_read_timeout(Some(LIMIT)).unwrap();
    let mut byte = [0];
    assert_eq!(oversized.read(&mut byte).unwrap(), 0);
    assert_eq!(ctl(&socket, 4, &[]).0, 67);
}

#[test]
fn interactive_mux_stdin_eof_and_stop_leave_current_passenger_alive() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    assert!(
        output(stack.client().args(["-M", "-f", "-S"]).arg(&socket).args([
            "-o",
            "ControlPersist=yes",
            "127.0.0.1"
        ]))
        .status
        .success()
    );
    let captured = stack.root.join("passenger-output");
    let mut passenger = stack
        .client()
        .arg("-S")
        .arg(&socket)
        .arg("127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&captured).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = passenger.stdin.take().unwrap();
    input.write_all(b"printf 'AT%s\\n' 'TACHED'\n").unwrap();
    wait(|| fs::read_to_string(&captured).unwrap().contains("ATTACHED"));
    assert!(output(&mut stack.mux(&socket, "stop")).status.success());
    assert!(!socket.exists());
    input
        .write_all(b"sleep 0.1; printf 'ST%s\\n' 'ILL-LIVE'; exit\n")
        .unwrap();
    drop(input);
    assert!(passenger.wait_timeout(LIMIT).unwrap().unwrap().success());
    assert!(fs::read_to_string(captured).unwrap().contains("STILL-LIVE"));
}

#[test]
fn cancelled_command_status_cannot_finish_next_passenger() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    assert!(
        output(stack.client().args(["-M", "-f", "-S"]).arg(&socket).args([
            "-o",
            "ControlPersist=yes",
            "127.0.0.1"
        ]))
        .status
        .success()
    );
    let marker = stack.root.join("started");
    let command = format!("touch '{}'; sleep 0.3; exit 23", marker.display());
    let mut passenger = stack
        .client()
        .arg("-S")
        .arg(&socket)
        .args(["--command", &command, "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait(|| marker.exists());
    passenger.kill().unwrap();
    passenger.wait().unwrap();
    let deadline = Instant::now() + LIMIT;
    loop {
        let next = output(stack.client().arg("-S").arg(&socket).args([
            "--command",
            "exit 17",
            "127.0.0.1",
        ]));
        if next.status.code() == Some(17) {
            break;
        }
        assert_eq!(next.status.code(), Some(1), "stale exit leaked: {next:?}");
        assert!(
            String::from_utf8_lossy(&next.stderr).contains("busy"),
            "{next:?}"
        );
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut broken_output = stack
        .client()
        .arg("-S")
        .arg(&socket)
        .args([
            "--command",
            "sleep 0.2; printf output; sleep 0.2; exit 23",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(broken_output.stdout.take());
    assert_eq!(
        broken_output.wait_timeout(LIMIT).unwrap().unwrap().code(),
        Some(255)
    );
    let next =
        output(
            stack
                .client()
                .arg("-S")
                .arg(&socket)
                .args(["--command", "exit 19", "127.0.0.1"]),
        );
    assert_eq!(
        next.status.code(),
        Some(19),
        "output failure must drain the old command marker: {next:?}"
    );
}

#[test]
fn no_shell_master_forwards_unix_sockets_and_rejects_shell_passengers() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    let started = output(
        stack
            .client()
            .args(["-M", "-f", "-NT", "-S"])
            .arg(&socket)
            .args(["-o", "ControlPersist=yes", "127.0.0.1"]),
    );
    assert!(started.status.success(), "{started:?}");
    let count = fs::read(stack.root.join("ssh-count")).unwrap();
    let destination = stack.root.join("destination");
    let echo = std::os::unix::net::UnixListener::bind(&destination).unwrap();
    let source = stack.root.join("source");
    let spec = format!("{}:{}", source.display(), destination.display());
    // A no-command passenger can add forwards without launching another ET session.
    let opened = output(stack.client().args(["-N", "-S"]).arg(&socket).args([
        "--tunnel",
        &spec,
        "127.0.0.1",
    ]));
    assert!(opened.status.success(), "{opened:?}");
    let echo_worker = std::thread::spawn(move || {
        let (mut socket, _) = echo.accept().unwrap();
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        let mut bytes = [0; 5];
        socket.read_exact(&mut bytes).unwrap();
        socket.write_all(&bytes).unwrap();
    });
    let mut forward = UnixStream::connect(&source).unwrap();
    forward.set_read_timeout(Some(LIMIT)).unwrap();
    forward.write_all(b"unix!").unwrap();
    let mut bytes = [0; 5];
    forward.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"unix!");
    echo_worker.join().unwrap();
    assert!(
        output(stack.mux(&socket, "cancel").args(["--tunnel", &spec]))
            .status
            .success()
    );
    assert!(!source.exists());
    let rejected =
        output(
            stack
                .client()
                .arg("-S")
                .arg(&socket)
                .args(["--command", "exit 19", "127.0.0.1"]),
        );
    assert!(!rejected.status.success(), "{rejected:?}");
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unavailable"));
    assert_eq!(fs::read(stack.root.join("ssh-count")).unwrap(), count);
}

#[test]
fn generated_control_handle_uses_host_and_no_persist_does_not_save_credentials() {
    let stack = Stack::start();
    let socket = stack.root.join("ctl");
    let started = output(
        stack
            .client()
            .args(["--ctl", "--no-persist", "--ctl-socket"])
            .arg(&socket)
            .args([
                "--command",
                "stty -echo; printf 'NO%s\\n' '-PERSIST'",
                "127.0.0.1",
            ]),
    );
    assert!(started.status.success(), "{started:?}");
    let text = String::from_utf8(started.stdout).unwrap();
    let name = text
        .lines()
        .find_map(|line| line.strip_prefix("et control session: "))
        .unwrap();
    assert!(name.starts_with("127.0.0.1-"), "{text}");
    assert!(!stack.root.join(".et/sessions").join(name).exists());
    read_until(&socket, "NO-PERSIST");
    assert_eq!(ctl(&socket, 5, &[]).0, 64);
    wait(|| !socket.exists());
    assert!(stack
        .root
        .join(".et/control")
        .join(format!("{name}.gone"))
        .exists());
}

#[test]
fn primary_noexit_keeps_shell_state_and_reports_real_remote_exit() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    let captured = stack.root.join("primary-output");
    let mut primary = stack
        .client()
        .args(["-M", "-S"])
        .arg(&socket)
        .args([
            "--noexit",
            "--command",
            "stty -echo; export PRIMARY_STATE=kept; printf 'PRI%s\\n' 'MARY-READY'",
            "127.0.0.1",
        ])
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&captured).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = primary.stdin.take().unwrap();
    wait(|| {
        fs::read_to_string(&captured)
            .unwrap()
            .contains("PRIMARY-READY")
    });
    assert!(primary.try_wait().unwrap().is_none());
    input
        .write_all(b"printf 'STATE=%s\\n' \"$PRIMARY_STATE\"; exit 28\n")
        .unwrap();
    drop(input);
    assert_eq!(
        primary.wait_timeout(LIMIT).unwrap().unwrap().code(),
        Some(28)
    );
    assert!(fs::read_to_string(&captured)
        .unwrap()
        .contains("STATE=kept"));
    assert!(!socket.exists());
}

#[test]
fn stale_auto_master_background_passenger_and_nonce_marker() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    drop(UnixListener::bind(&socket).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let started = output(
        stack
            .client()
            .args(["-f", "-oControlMaster=auto", "-S"])
            .arg(&socket)
            .arg("127.0.0.1"),
    );
    assert!(started.status.success(), "{started:?}");
    let rejected = output(
        stack
            .client()
            .args(["-T", "-S"])
            .arg(&socket)
            .args(["127.0.0.1", "true"]),
    );
    assert!(!rejected.status.success());
    let command = output(
        stack
            .client()
            .arg("-S")
            .arg(&socket)
            .args(["127.0.0.1", "printf '__ET_PASSENGER_EXIT__:0\\n'; exit 23"]),
    );
    assert_eq!(command.status.code(), Some(23), "{command:?}");
    assert!(String::from_utf8_lossy(&command.stdout).contains("__ET_PASSENGER_EXIT__:0"));
    let release = stack.root.join("release");
    let finished = stack.root.join("finished");
    let script = format!(
        "while [ ! -f '{}' ]; do sleep 0.05; done; touch '{}'",
        release.display(),
        finished.display()
    );
    let background = output(
        stack
            .client()
            .args(["-f", "-S"])
            .arg(&socket)
            .arg("127.0.0.1")
            .arg(&script),
    );
    assert!(background.status.success(), "{background:?}");
    assert!(!finished.exists());
    fs::write(release, b"go").unwrap();
    wait(|| finished.exists());
}

#[test]
fn saved_attach_can_report_background_readiness() {
    let stack = Stack::start();
    let release = stack.root.join("release-attach");
    let socket = stack.start_control(&format!(
        "while [ ! -f '{}' ]; do sleep 0.05; done; exit",
        release.display()
    ));
    assert_eq!(ctl(&socket, 5, b"").0, 64);
    wait(|| !socket.exists());
    let attached = output(stack.client().args(["-f", "--attach", "work"]));
    assert!(attached.status.success(), "{attached:?}");
    fs::write(release, b"exit").unwrap();
}

#[test]
fn slow_passenger_output_applies_backpressure_without_failing_command() {
    let stack = Stack::start();
    let socket = stack.root.join("mux");
    assert!(output(
        stack
            .client()
            .args(["-M", "-f", "-S"])
            .arg(&socket)
            .arg("127.0.0.1")
    )
    .status
    .success());
    let mut passenger = stack
        .client()
        .arg("-S")
        .arg(&socket)
        .args([
            "127.0.0.1",
            "dd if=/dev/zero bs=1000000 count=6 2>/dev/null; exit 19",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Let the pipe and the master's bounded queue fill before reading output.
    std::thread::sleep(Duration::from_millis(300));
    assert!(passenger.try_wait().unwrap().is_none());
    assert!(output(&mut stack.mux(&socket, "check")).status.success());
    let mut stdout = passenger.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let status = passenger.wait_timeout(LIMIT).unwrap();
    if status.is_none() {
        let _ = passenger.kill();
        let _ = passenger.wait();
    }
    let bytes = reader.join().unwrap();
    assert_eq!(status.unwrap().code(), Some(19));
    assert_eq!(bytes.iter().filter(|&&byte| byte == 0).count(), 6_000_000);
}
