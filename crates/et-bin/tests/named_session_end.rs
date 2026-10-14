//! Named sessions leave the local list and the server registry when the shell exits.
#![cfg(unix)]
#![forbid(unsafe_code)]

#[allow(dead_code)]
mod reconnect_stack;

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use reconnect_stack::{shell_quote, Stack};
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn ended_named_session_leaves_the_list_and_attach_says_it_ended() {
    let mut stack = Stack::start();
    let name = "work";
    let stop = stack.directory.join("stop");
    let command = format!(
        "printf 'LIVE\\n'; while [ ! -f {} ]; do sleep 0.05; done; printf 'ENDED\\n'",
        shell_quote(stop.to_str().unwrap())
    );
    let mut client = et(&stack)
        .args(["--name", name, "--command", &command, "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout_pipe = client.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let mut pipe = stdout_pipe;
        pipe.read_to_string(&mut output).unwrap();
        output
    });
    let session = stack.directory.join(".et/sessions").join(name);
    wait_until("named session is listed while the shell is running", || {
        session.is_file() && list(&stack, "127.0.0.1").contains(name)
    });
    let saved = fs::read(&session).unwrap();
    fs::write(&stop, b"1").unwrap();
    let status = client
        .wait_timeout(TIMEOUT)
        .unwrap()
        .unwrap_or_else(|| panic!("named client did not exit"));
    let stdout = reader.join().unwrap();
    let mut stderr = String::new();
    client
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "stdout={stdout:?} stderr={stderr:?}");
    assert!(stdout.contains("ENDED"), "{stdout:?}");
    assert!(
        !list(&stack, "127.0.0.1").contains(name),
        "ended session still listed: {}",
        list(&stack, "127.0.0.1")
    );

    let mut attach_error = String::new();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        restore_session(&stack, name, &saved);
        let mut attach = et(&stack)
            .args(["--attach", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        match attach.wait_timeout(Duration::from_secs(2)).unwrap() {
            Some(status) => {
                attach
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut attach_error)
                    .unwrap();
                if !status.success() && attach_error.contains("session not found or ended") {
                    break;
                }
                if Instant::now() >= deadline {
                    panic!("attach did not report a missing session: {attach_error:?}");
                }
            }
            None => {
                let _ = attach.kill();
                let _ = attach.wait();
                if Instant::now() >= deadline {
                    panic!("server kept the ended session registered");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !attach_error.contains("client is not registered"),
        "{attach_error:?}"
    );
    assert!(
        !attach_error.contains("rejected the session key"),
        "{attach_error:?}"
    );
    assert!(
        !list(&stack, "127.0.0.1").contains(name),
        "stale session returned to the list"
    );
    stack.shutdown();
}

fn et(stack: &Stack) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
    command
        .env(
            "PATH",
            format!(
                "{}:{}",
                stack.directory.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SHELL", "/bin/sh")
        .env("TERM", "xterm-256color")
        .args(["--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .args(["--port", &stack.port.to_string()]);
    command
}

fn list(stack: &Stack, host: &str) -> String {
    let output = et(stack).args(["--list", host]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn restore_session(stack: &Stack, name: &str, bytes: &[u8]) {
    let directory = stack.directory.join(".et/sessions");
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(
        stack.directory.join(".et"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn wait_until(description: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("timed out waiting until {description}");
}
