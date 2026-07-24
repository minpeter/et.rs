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
fn daemon_mode_is_rejected_for_subcommand_and_busybox_dispatch() {
    let directory = tempfile_path("daemon");
    fs::create_dir(&directory).unwrap();
    let busybox = directory.join("etserver");
    symlink(env!("CARGO_BIN_EXE_et"), &busybox).unwrap();
    for (program, arguments) in [
        (env!("CARGO_BIN_EXE_et"), vec!["server", "--daemon"]),
        (busybox.to_str().unwrap(), vec!["--daemon"]),
    ] {
        let output = Command::new(program).args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("daemon mode is not implemented"));
    }
    fs::remove_dir_all(directory).unwrap();
}

fn tempfile_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "et-rs-server-binary-{label}-{}",
        std::process::id()
    ))
}
