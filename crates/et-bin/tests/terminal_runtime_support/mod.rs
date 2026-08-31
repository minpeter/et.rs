use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use et_core::proto::TerminalBuffer;
use et_net::local_packet::read_local_packet;
use prost::Message;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);

pub const LOGIN_COLOR_MARKER: &[u8] = b"\x1b[31mET-LOGIN-COLOR\x1b[0m";
pub const NON_LOGIN_MARKER: &[u8] = b"ET-NON-LOGIN";

pub struct Fixture {
    directory: std::path::PathBuf,
    pub socket: std::path::PathBuf,
    pub listener: UnixListener,
    ready_socket: std::path::PathBuf,
    ready_listener: UnixListener,
}

impl Fixture {
    pub fn new(label: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("et-rs-terminal-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("router.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let ready_socket = directory.join("ready.sock");
        let ready_listener = UnixListener::bind(&ready_socket).unwrap();
        Self {
            directory,
            socket,
            listener,
            ready_socket,
            ready_listener,
        }
    }

    pub fn spawn(&self) -> std::process::Child {
        self.spawn_with_shell("/bin/sh")
    }

    pub fn spawn_with_shell(&self, shell: &str) -> std::process::Child {
        self.spawn_session(shell, &[])
    }

    /// Spawn the session child with extra environment entries applied before
    /// exec, so a test can seed server-side state the session reads at startup.
    pub fn spawn_session(
        &self,
        shell: &str,
        environment: &[(&str, &std::ffi::OsStr)],
    ) -> std::process::Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
        command
            .args([
                "terminal",
                "--session-child",
                "--ready-socket",
                self.ready_socket.to_str().unwrap(),
                "--serverfifo",
            ])
            .arg(&self.socket)
            .env("SHELL", shell)
            .env_remove("COLORTERM");
        for (name, value) in environment {
            command.env(name, value);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// Write a server-side file inside the fixture directory and return its path.
    pub fn file(&self, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    /// Wrapper that emits an ANSI palette color marker only when argv[1] is `-l`.
    pub fn login_probe_shell(&self) -> std::path::PathBuf {
        let path = self.directory.join("login-probe-shell");
        fs::write(
            &path,
            "#!/bin/sh\n\
             if [ \"${1-}\" = \"-l\" ]; then\n\
             printf '\\033[31mET-LOGIN-COLOR\\033[0m\\n'\n\
             shift\n\
             exec /bin/sh \"$@\"\n\
             fi\n\
             printf 'ET-NON-LOGIN\\n'\n\
             exec /bin/sh \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    pub fn spawn_parent(&self) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_et"))
            .args(["terminal", "--serverfifo"])
            .arg(&self.socket)
            .env("SHELL", "/bin/sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    pub fn wait_ready(&self) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let listener = self.ready_listener.try_clone().unwrap();
        std::thread::spawn(move || {
            let result = listener.accept().and_then(|(mut stream, _)| {
                let mut ready = [0u8; 1];
                std::io::Read::read_exact(&mut stream, &mut ready)?;
                Ok(ready)
            });
            let _ = sender.send(result);
        });
        assert_eq!(receiver.recv_timeout(TIMEOUT).unwrap().unwrap(), [1]);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub fn write_credentials(child: &mut std::process::Child) {
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{ID}/{KEY}_xterm-256color").unwrap();
}

pub fn read_line_timeout(stdout: impl std::io::Read + Send + 'static) -> String {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    receiver.recv_timeout(TIMEOUT).unwrap().unwrap()
}

pub fn contains(output: &[u8], marker: &[u8]) -> bool {
    output.windows(marker.len()).any(|window| window == marker)
}

pub fn collect_until(router: &mut impl Read, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut output = Vec::new();
    while !done(&output) {
        let packet = read_local_packet(router).unwrap();
        output.extend(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .unwrap(),
        );
    }
    output
}
