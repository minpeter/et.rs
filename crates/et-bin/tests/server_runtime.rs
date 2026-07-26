#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
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

    // A real daemon run returns immediately and the child records its pid,
    // matching upstream `DaemonCreator::create`.
    for (index, program) in [env!("CARGO_BIN_EXE_et"), busybox.to_str().unwrap()]
        .into_iter()
        .enumerate()
    {
        let router = directory.join(format!("router-{index}"));
        let pidfile = directory.join(format!("etserver-{index}.pid"));
        let mut arguments = Vec::new();
        if index == 0 {
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
        // Replace the rejected port with an ephemeral one the OS assigns.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let position = arguments.iter().position(|value| value == "0").unwrap();
        arguments[position] = port.to_string();

        let output = Command::new(program).args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");

        // The detached child writes the pid file shortly after starting.
        let mut recorded = None;
        for _ in 0..50 {
            if let Ok(text) = fs::read_to_string(&pidfile) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    recorded = Some(pid);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let pid = recorded.expect("daemon did not write a pid file");
        assert!(pid > 0);
        // Owner-only permissions, like upstream's 0600 open().
        let mode = fs::metadata(&pidfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // The daemon runs detached from this process.
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    let _ = fs::remove_file(&pidfile);
    fs::remove_dir_all(directory).unwrap();
}

fn tempfile_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "et-rs-server-binary-{label}-{}",
        std::process::id()
    ))
}
