//! Regression test: signals delivered while the client blocks in poll() must
//! not kill or strand the session.
#![forbid(unsafe_code)]
#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const WATCHDOG: Duration = Duration::from_secs(20);
const SIGNAL_COUNT: usize = 128;
const MARKER: &str = "SIGWINCH-SURVIVED";

enum OutputEvent {
    Line(String),
    Done(io::Result<String>),
}

struct ClientObservation {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[test]
fn client_survives_sigwinch_storm_while_polling() {
    let directory =
        std::env::temp_dir().join(format!("et-rs-sigwinch-storm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let router = directory.join("router.sock");
    let config = directory.join("et.cfg");
    let pump_probe = directory.join("pump-probe.sock");
    let release = directory.join("remote-release");
    let remote_ready = directory.join("remote-ready");
    let probe_listener = UnixListener::bind(&pump_probe).unwrap();
    for fifo in [&release, &remote_ready] {
        assert!(Command::new("mkfifo").arg(fifo).status().unwrap().success());
    }
    let remote_ready_control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&remote_ready)
        .unwrap();

    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
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
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_ready(&mut server, port, &router);

    let ssh = directory.join("ssh");
    fs::write(
        &ssh,
        "#!/bin/sh\n\
         if [ \"$1\" = \"-G\" ]; then\n\
           printf 'hostname 127.0.0.1\\nuser tester\\n'\n\
           exit 0\n\
         fi\n\
         for last do :; done\n\
         exec /bin/sh -c \"$last\"\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    let terminal = directory.join("etterminal");
    symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
    let existing_path = std::env::var("PATH").unwrap();

    let client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", format!("{}:{existing_path}", directory.display()))
        .env("TERM", "xterm-256color")
        .env("ET_PUMP_PROBE", &pump_probe)
        .args(["--terminal-path"])
        .arg(&terminal)
        .args(["--serverfifo"])
        .arg(&router)
        .arg("-p")
        .arg(port.to_string())
        .arg("-c")
        .arg(format!(
            "printf x > '{}'; read _ < '{}'; printf 'SIGWINCH-%s\\n' SURVIVED",
            remote_ready.display(),
            release.display()
        ))
        .arg("127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let result = exercise_client(client, probe_listener, remote_ready_control, release);
    terminate_server(&mut server);
    fs::remove_dir_all(&directory).unwrap();

    let observation = result.unwrap_or_else(|error| panic!("{error}"));
    assert!(
        !observation.stderr.contains("Interrupted system call"),
        "client died from EINTR: {}",
        observation.stderr
    );
    assert!(observation.status.success(), "{}", observation.stderr);
    assert!(
        observation.stdout.contains(MARKER),
        "{:?} {:?}",
        observation.stdout,
        observation.stderr
    );
}

fn exercise_client(
    mut client: Child,
    probe_listener: UnixListener,
    mut remote_ready: fs::File,
    release_path: std::path::PathBuf,
) -> Result<ClientObservation, String> {
    let pid = Pid::from_raw(i32::try_from(client.id()).unwrap());
    let stdout = client.stdout.take().unwrap();
    let stderr = client.stderr.take().unwrap();
    let (output_tx, output_rx) = mpsc::sync_channel(64);
    std::thread::spawn(move || read_stdout(stdout, output_tx));
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut text = String::new();
        let result = stderr.read_to_string(&mut text).map(|_| text);
        let _ = stderr_tx.send(result);
    });
    let (exit_tx, exit_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = exit_tx.send(client.wait());
    });
    let (accept_tx, accept_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = accept_tx.send(probe_listener.accept().map(|(stream, _)| stream));
    });

    let mut failure = None;
    let mut probe = match accept_rx.recv_timeout(WATCHDOG) {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(error)) => {
            failure = Some(format!("client pump probe accept failed: {error}"));
            None
        }
        Err(error) => {
            failure = Some(format!("client never connected its pump probe: {error}"));
            None
        }
    };
    if let Some(stream) = probe.as_mut() {
        stream.set_read_timeout(Some(WATCHDOG)).unwrap();
        stream.set_write_timeout(Some(WATCHDOG)).unwrap();
        if let Err(error) = expect_probe(stream, b'R') {
            failure = Some(format!("client never reported pump readiness: {error}"));
        } else if let Err(error) = stream.write_all(b"G") {
            failure = Some(format!("could not release the armed pump gate: {error}"));
        }
    }

    let (remote_ready_tx, remote_ready_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        let result = remote_ready.read_exact(&mut byte);
        let _ = remote_ready_tx.send(result);
    });
    if let Err(error) = remote_ready_rx.recv_timeout(WATCHDOG) {
        failure.get_or_insert_with(|| format!("remote command never armed its release: {error}"));
    }

    if failure.is_none() {
        let stream = probe.as_mut().expect("probe established without failure");
        for delivered in 0..SIGNAL_COUNT {
            if let Err(error) = expect_probe(stream, b'A') {
                failure = Some(format!(
                    "client stopped arming poll after {delivered} signals: {error}"
                ));
                break;
            }
            if let Err(error) = kill(pid, Signal::SIGWINCH) {
                failure = Some(format!(
                    "client exited while delivering signal {delivered}: {error}"
                ));
                break;
            }
            if let Err(error) = expect_probe(stream, b'P') {
                failure = Some(format!(
                    "client made no pump progress after signal {delivered}: {error}"
                ));
                break;
            }
        }
    }

    // The remote command is released only after every acknowledged signal.
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = OpenOptions::new()
            .write(true)
            .open(release_path)
            .and_then(|mut release| release.write_all(b"go\n"));
        let _ = release_tx.send(result);
    });
    match release_rx.recv_timeout(WATCHDOG) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            failure.get_or_insert_with(|| format!("could not release remote command: {error}"));
        }
        Err(error) => {
            failure.get_or_insert_with(|| format!("remote release writer stalled: {error}"));
        }
    }

    let mut stdout_done = None;
    let mut marker_seen = false;
    while stdout_done.is_none() {
        match output_rx.recv_timeout(WATCHDOG) {
            Ok(OutputEvent::Line(line)) => marker_seen |= line.contains(MARKER),
            Ok(OutputEvent::Done(result)) => stdout_done = Some(result),
            Err(error) => {
                failure.get_or_insert_with(|| format!("client output stalled: {error}"));
                break;
            }
        }
    }
    if !marker_seen {
        failure
            .get_or_insert_with(|| "remote marker was not observed before client EOF".to_owned());
    }

    let status = match exit_rx.recv_timeout(WATCHDOG) {
        Ok(Ok(status)) => Some(status),
        Ok(Err(error)) => {
            failure.get_or_insert_with(|| format!("waiting for client failed: {error}"));
            None
        }
        Err(_) => {
            let _ = kill(pid, Signal::SIGKILL);
            let reaped = exit_rx.recv_timeout(WATCHDOG);
            failure.get_or_insert_with(|| {
                format!("client product hang after marker/exit trigger; cleanup={reaped:?}")
            });
            reaped.ok().and_then(Result::ok)
        }
    };
    let stdout = stdout_done
        .and_then(Result::ok)
        .unwrap_or_else(|| "<stdout unavailable>".to_owned());
    let stderr = stderr_rx
        .recv_timeout(WATCHDOG)
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(|| "<stderr unavailable>".to_owned());

    if let Some(error) = failure {
        return Err(format!("{error}; stdout={stdout:?}; stderr={stderr:?}"));
    }
    Ok(ClientObservation {
        status: status.expect("successful observation has an exit status"),
        stdout,
        stderr,
    })
}

fn read_stdout(stdout: impl Read, sender: mpsc::SyncSender<OutputEvent>) {
    let mut reader = BufReader::new(stdout);
    let mut complete = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(OutputEvent::Done(Ok(complete)));
                return;
            }
            Ok(_) => {
                complete.push_str(&line);
                if sender.send(OutputEvent::Line(line)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(OutputEvent::Done(Err(error)));
                return;
            }
        }
    }
}

fn expect_probe(stream: &mut UnixStream, expected: u8) -> io::Result<()> {
    let mut observed = [0_u8; 1];
    stream.read_exact(&mut observed)?;
    if observed[0] == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected pump event {:?}, received {:?}",
                char::from(expected),
                char::from(observed[0])
            ),
        ))
    }
}

fn terminate_server(server: &mut Child) {
    let pid = Pid::from_raw(i32::try_from(server.id()).unwrap());
    let _ = kill(pid, Signal::SIGTERM);
    match server.wait_timeout(WATCHDOG).unwrap() {
        Some(status) => assert!(status.success(), "server shutdown failed: {status}"),
        None => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = server.wait();
            panic!("server did not terminate after SIGTERM");
        }
    }
}

fn wait_ready(server: &mut Child, port: u16, router: &std::path::Path) {
    let stdout = server.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    assert_eq!(
        receiver.recv_timeout(WATCHDOG).unwrap().unwrap(),
        format!(
            "ETSERVER_READY tcp=127.0.0.1:{port} router={}\n",
            router.display()
        )
    );
}
