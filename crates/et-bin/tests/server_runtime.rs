#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn foreground_binary_loads_config_and_sigterm_cleans_every_surface() {
    let temp = tempfile_path("foreground");
    fs::create_dir(&temp).unwrap();
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o700)).unwrap();
    let router = temp.join("router.sock");
    let config = temp.join("et.cfg");
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_et"))
        .args(["server", "--cfgfile"])
        .arg(&config)
        .arg("--telemetry")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
    let stdout = child.stdout.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let ready_worker = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = ready_tx.send(result);
    });
    let ready = match ready_rx.recv_timeout(TIMEOUT) {
        Ok(Ok(line)) => line,
        other => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = child.wait();
            panic!("server did not become ready: {other:?}");
        }
    };
    ready_worker.join().unwrap();
    assert_eq!(
        ready,
        format!(
            "ETSERVER_READY tcp=127.0.0.1:{port} router={}\n",
            router.display()
        )
    );
    let probe = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    drop(probe);

    kill(pid, Signal::SIGTERM).unwrap();
    let (wait_tx, wait_rx) = mpsc::channel();
    let wait_worker = thread::spawn(move || {
        let _ = wait_tx.send(child.wait());
    });
    let status = match wait_rx.recv_timeout(TIMEOUT) {
        Ok(Ok(status)) => status,
        other => {
            let _ = kill(pid, Signal::SIGKILL);
            panic!("server did not exit after SIGTERM: {other:?}");
        }
    };
    wait_worker.join().unwrap();
    assert!(status.success());
    assert!(!router.exists());
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn daemon_mode_detaches_and_writes_a_pid_file() {
    let directory = tempfile_path("daemon");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let busybox = directory.join("etserver");
    symlink(env!("CARGO_BIN_EXE_et"), &busybox).unwrap();
    let pidfile = directory.join("etserver.pid");

    // Argument validation still happens in the parent, before detaching.
    let invalid = Command::new(env!("CARGO_BIN_EXE_et"))
        .args(["server", "--daemon", "--port", "0"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));

    // Child failures cross the bounded startup pipe instead of being hidden by
    // detached stderr or reported as an unclassified EOF.
    let failed_pidfile = directory.join("missing/etserver.pid");
    let failed = Command::new(env!("CARGO_BIN_EXE_et"))
        .args(["server", "--daemon", "--port", "2022", "--pidfile"])
        .arg(&failed_pidfile)
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(2), "{failed:?}");
    let failure = String::from_utf8(failed.stderr).unwrap();
    assert!(
        failure.contains("Error opening pidfile for writing"),
        "{failure}"
    );
    assert!(failure.contains(&failed_pidfile.to_string_lossy().into_owned()));
    assert!(!failure.contains("status channel closed"), "{failure}");

    // A real daemon run returns immediately and the child records its pid,
    // matching upstream `DaemonCreator::create`.
    for (index, (program, explicit_server_role, log_to_stdout)) in [
        (env!("CARGO_BIN_EXE_et"), true, false),
        (busybox.to_str().unwrap(), false, false),
        (env!("CARGO_BIN_EXE_et"), true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let router = directory.join(format!("router-{index}"));
        let pidfile = directory.join(format!("etserver-{index}.pid"));
        let shutdown_socket =
            std::env::temp_dir().join(format!("ed{}{}", std::process::id(), index));
        let shutdown_listener = UnixListener::bind(&shutdown_socket).unwrap();
        let (runtime_tx, runtime_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let shutdown_worker = thread::spawn(move || {
            let runtime = accept_daemon_status(&shutdown_listener, b"ETD0", "runtime startup");
            let runtime_started = runtime.is_ok();
            let _ = runtime_tx.send(runtime);
            if runtime_started {
                let _ = shutdown_tx.send(accept_daemon_status(
                    &shutdown_listener,
                    b"ETD2",
                    "shutdown completion",
                ));
            }
        });
        let mut arguments = Vec::new();
        if explicit_server_role {
            arguments.push("server".to_owned());
        }
        arguments.extend([
            "--daemon".to_owned(),
            "--port".to_owned(),
            "0".to_owned(),
            "--pidfile".to_owned(),
            pidfile.to_str().unwrap().to_owned(),
            "--serverfifo".to_owned(),
            router.to_str().unwrap().to_owned(),
        ]);
        if log_to_stdout {
            arguments.push("--logtostdout".to_owned());
        }
        // Replace the rejected port with an ephemeral one the OS assigns.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let position = arguments.iter().position(|value| value == "0").unwrap();
        arguments[position] = port.to_string();

        let output = Command::new(program)
            .args(&arguments)
            .env("ET_RS_TEST_SERVER_SHUTDOWN_SOCKET", &shutdown_socket)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "daemon scenario index={index} program={program} logtostdout={log_to_stdout}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{output:?}");

        // The parent returns after the detached child starts its runtime; the
        // pid file is therefore complete without filesystem polling.
        let pid = fs::read_to_string(&pidfile)
            .expect("daemon did not write a pid file")
            .trim()
            .parse::<i32>()
            .expect("daemon wrote an invalid pid file");
        assert!(pid > 0);
        // Owner-only permissions, like upstream's 0600 open().
        let mode = fs::metadata(&pidfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // The test-only runtime frame proves signal handling and the runtime
        // are ready before SIGTERM, without changing production startup.
        let runtime = runtime_rx.recv_timeout(TIMEOUT);
        if !matches!(runtime, Ok(Ok(()))) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = UnixStream::connect(&shutdown_socket);
            shutdown_worker.join().unwrap();
            let _ = fs::remove_file(&shutdown_socket);
            match runtime {
                Ok(Ok(())) => unreachable!(),
                Ok(Err(error)) => panic!("daemon runtime-start signal failed: {error}"),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("daemon did not signal runtime startup before the watchdog")
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("daemon runtime-start observer disconnected")
                }
            }
        }

        // The daemon runs detached from this process. Its completion frame is
        // emitted only after runtime shutdown retires the router.
        kill(Pid::from_raw(pid), Signal::SIGTERM).unwrap();
        let shutdown = shutdown_rx.recv_timeout(TIMEOUT);
        if !matches!(shutdown, Ok(Ok(()))) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            // Wake the observer so failure cleanup can join without polling.
            let _ = UnixStream::connect(&shutdown_socket);
        }
        shutdown_worker.join().unwrap();
        let _ = fs::remove_file(&shutdown_socket);
        match shutdown {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("daemon shutdown completion signal failed: {error}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("daemon did not signal shutdown completion before the watchdog")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("daemon shutdown completion observer disconnected")
            }
        }
        assert!(
            !router.exists(),
            "daemon retained its router after shutdown"
        );
        fs::remove_file(pidfile).unwrap();
    }
    let _ = fs::remove_file(&pidfile);
    fs::remove_dir_all(directory).unwrap();
}

fn accept_daemon_status(
    listener: &UnixListener,
    expected: &[u8; 4],
    phase: &str,
) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut frame = [0u8; 4];
    stream.read_exact(&mut frame)?;
    if &frame != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed daemon {phase} frame"),
        ));
    }
    Ok(())
}

fn tempfile_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "et-rs-server-binary-{label}-{}",
        std::process::id()
    ))
}
