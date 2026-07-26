//! Regression test: signals delivered while the client blocks in poll() must
//! not kill the session.
//!
//! The client installs a process-wide SIGWINCH handler for terminal resizes.
//! poll() is never auto-restarted by SA_RESTART, so any SIGWINCH landing on
//! the thread blocked in poll() makes it fail with EINTR. The client used to
//! treat that as fatal and died with:
//!
//!   et: polling terminal streams: Interrupted system call (os error 4)
#![forbid(unsafe_code)]
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn client_survives_sigwinch_storm_while_polling() {
    let directory =
        std::env::temp_dir().join(format!("et-rs-sigwinch-storm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let router = directory.join("router.sock");
    let config = directory.join("et.cfg");
    let ready = directory.join("session-ready");
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

    // Keep the session alive long enough for the storm, then print a marker.
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", format!("{}:{existing_path}", directory.display()))
        .env("TERM", "xterm-256color")
        .env("ET_SSH_READY", &ready)
        .args(["--terminal-path"])
        .arg(&terminal)
        .args(["--serverfifo"])
        .arg(&router)
        .arg("-p")
        .arg(port.to_string())
        .args(["-c", "sleep 2; printf 'SIGWINCH-SURVIVED\\n'", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait until the client's pump loop is live (it writes the gate file).
    let gate_deadline = Instant::now() + TIMEOUT;
    while !ready.exists() {
        assert!(
            Instant::now() < gate_deadline,
            "client never reached the terminal loop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Storm the client with SIGWINCH while it blocks in poll() waiting for
    // server output. Any one of these interrupts poll() with EINTR.
    let client_pid = Pid::from_raw(i32::try_from(client.id()).unwrap());
    let storm_deadline = Instant::now() + Duration::from_millis(1_500);
    while Instant::now() < storm_deadline {
        if kill(client_pid, Signal::SIGWINCH).is_err() {
            break; // client already exited; the assertions below explain why
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let status = match client.wait_timeout(TIMEOUT).unwrap() {
        Some(status) => status,
        None => {
            let _ = client.kill();
            let _ = client.wait();
            panic!("client did not exit after the signal storm");
        }
    };
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    client
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout_text)
        .unwrap();
    client
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr_text)
        .unwrap();
    assert!(
        !stderr_text.contains("Interrupted system call"),
        "client died from EINTR: {stderr_text}"
    );
    assert!(status.success(), "{stderr_text}");
    assert!(
        stdout_text.contains("SIGWINCH-SURVIVED"),
        "{stdout_text:?} {stderr_text:?}"
    );

    let server_pid = Pid::from_raw(i32::try_from(server.id()).unwrap());
    kill(server_pid, Signal::SIGTERM).unwrap();
    assert!(server.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    fs::remove_dir_all(directory).unwrap();
}

fn wait_ready(server: &mut std::process::Child, port: u16, router: &std::path::Path) {
    let stdout = server.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    assert_eq!(
        receiver.recv_timeout(TIMEOUT).unwrap().unwrap(),
        format!(
            "ETSERVER_READY tcp=127.0.0.1:{port} router={}\n",
            router.display()
        )
    );
}
