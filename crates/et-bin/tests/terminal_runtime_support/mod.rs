use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);

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
        Command::new(env!("CARGO_BIN_EXE_et"))
            .args([
                "terminal",
                "--session-child",
                "--ready-socket",
                self.ready_socket.to_str().unwrap(),
                "--serverfifo",
            ])
            .arg(&self.socket)
            .env("SHELL", shell)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
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
