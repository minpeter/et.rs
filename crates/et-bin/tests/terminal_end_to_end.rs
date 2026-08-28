#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn real_client_ghostty_fallback_bootstrap_server_bridge_and_pty_emit_color() {
    let directory = std::env::temp_dir().join(format!("et-rs-terminal-e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let router = directory.join("router.sock");
    let config = directory.join("et.cfg");
    let home = directory.join("home");
    fs::create_dir(&home).unwrap();
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
        .env_remove("COLORTERM")
        .env("HOME", &home)
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
         unset COLORTERM\n\
         exec /bin/sh -c \"$last\"\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    let terminal = directory.join("etterminal");
    symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
    let existing_path = std::env::var("PATH").unwrap();
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", format!("{}:{existing_path}", directory.display()))
        .env("HOME", &home)
        .env("TERM", "xterm-ghostty")
        .env("COLORTERM", "truecolor")
        .args(["--terminal-path"])
        .arg(&terminal)
        .args(["--serverfifo"])
        .arg(&router)
        .arg("-p")
        .arg(port.to_string())
        .args([
            "-c",
            "case \"$TERM\" in xterm-color|*-256color) printf '\\033[01;32mGHOSTTY-GREEN\\033[00m:\\033[01;34mGHOSTTY-BLUE\\033[00m\\n';; esac; printf 'FULL-PTY:%s:%s\\n' \"$TERM\" \"${COLORTERM-}\"",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = client.wait_timeout(TIMEOUT).unwrap();
    let status = match status {
        Some(status) => status,
        None => {
            let _ = client.kill();
            let _ = client.wait();
            panic!("interactive client did not exit");
        }
    };
    let mut stdout = client.stdout.take().unwrap();
    let mut stderr = client.stderr.take().unwrap();
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    stdout.read_to_string(&mut stdout_text).unwrap();
    stderr.read_to_string(&mut stderr_text).unwrap();
    assert!(status.success(), "{stderr_text}");
    assert!(!stderr_text.contains("Connection to "), "{stderr_text:?}");
    assert!(
        stdout_text.contains("FULL-PTY:xterm-256color:truecolor"),
        "{stdout_text:?}"
    );
    assert!(
        stdout_text.contains("\u{1b}[01;32mGHOSTTY-GREEN\u{1b}[00m"),
        "{stdout_text:?}"
    );
    assert!(
        stdout_text.contains("\u{1b}[01;34mGHOSTTY-BLUE\u{1b}[00m"),
        "{stdout_text:?}"
    );

    let mut no_exit = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", format!("{}:{existing_path}", directory.display()))
        .env("TERM", "xterm-256color")
        .args(["--terminal-path"])
        .arg(&terminal)
        .args(["--serverfifo"])
        .arg(&router)
        .arg("-p")
        .arg(port.to_string())
        .args([
            "--no-exit",
            "-c",
            "printf 'NOEXIT:%s\\n' \"$TERM\"; exit",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = no_exit.wait_timeout(TIMEOUT).unwrap().unwrap();
    let mut no_exit_stdout = String::new();
    let mut no_exit_stderr = String::new();
    no_exit
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut no_exit_stdout)
        .unwrap();
    no_exit
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut no_exit_stderr)
        .unwrap();
    assert!(status.success(), "{no_exit_stderr}");
    assert!(
        !no_exit_stderr.contains("Connection to "),
        "{no_exit_stderr:?}"
    );
    assert!(
        no_exit_stdout.contains("NOEXIT:xterm-256color"),
        "{no_exit_stdout:?}"
    );

    let server_pid = Pid::from_raw(i32::try_from(server.id()).unwrap());
    kill(server_pid, Signal::SIGTERM).unwrap();
    assert!(server.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    assert!(!router.exists());
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
