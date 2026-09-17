use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use et_htm::codes;

const LIMIT: Duration = Duration::from_secs(30);

// Native CI test artifacts can be copied with et.exe to an isolated QA host.
fn executable() -> std::ffi::OsString {
    std::env::var_os("ET_HTM_TEST_BINARY")
        .unwrap_or_else(|| std::ffi::OsString::from(env!("CARGO_BIN_EXE_et")))
}

pub struct Daemon {
    process: Child,
    directory: PathBuf,
    pub path: PathBuf,
}

impl Daemon {
    pub fn start() -> Self {
        // Darwin's long per-user TMPDIR plus the diagnostic suffix can exceed
        // sockaddr_un. Keep the owned 0700 test namespace under short /tmp.
        #[cfg(target_os = "macos")]
        let base = PathBuf::from("/tmp");
        #[cfg(all(unix, not(target_os = "macos")))]
        let base = std::env::temp_dir();
        #[cfg(windows)]
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let directory = base.join(format!(
            "et-htm-qa-{}-{}",
            std::process::id(),
            et_core::keys::gen_id_passkey().0
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.join("htm.ipc");
        let mut command = Command::new(executable());
        command
            .args(["htmd", "--ready-stdout", "--socket"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(unix)]
        command.env("SHELL", "/bin/sh");
        #[cfg(windows)]
        command.env("SHELL", "cmd.exe").env("COMSPEC", "cmd.exe");
        let mut process = command.spawn().unwrap();
        let output = process.stdout.take().unwrap();
        let daemon = Self {
            process,
            directory,
            path,
        };
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(output).read_line(&mut line).unwrap();
            send.send(line).unwrap();
        });
        assert_eq!(receive.recv_timeout(LIMIT).unwrap(), "HTMD_READY\n");
        daemon
    }

    pub fn finish(&mut self) {
        use wait_timeout::ChildExt;
        assert!(self
            .process
            .wait_timeout(LIMIT)
            .unwrap()
            .expect("htmd exit")
            .success());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

pub struct Relay {
    process: Child,
    pub input: ChildStdin,
    messages: Receiver<Vec<u8>>,
    output: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl Relay {
    pub fn start(path: &Path) -> Self {
        Self::start_with(path, &[])
    }

    pub fn restart(path: &Path) -> Self {
        Self::start_with(path, &["-x"])
    }

    fn start_with(path: &Path, args: &[&str]) -> Self {
        let mut command = Command::new(executable());
        #[cfg(unix)]
        command.env("SHELL", "/bin/sh");
        #[cfg(windows)]
        command.env("SHELL", "cmd.exe").env("COMSPEC", "cmd.exe");
        let mut process = command
            .args(["htm", "--socket"])
            .arg(path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = process.stdin.take().unwrap();
        let mut output = process.stdout.take().unwrap();
        let (send, messages) = mpsc::channel();
        std::thread::spawn(move || {
            let mut enter = [0; 7];
            output.read_exact(&mut enter).unwrap();
            assert_eq!(&enter, codes::ENTER_HTM_MODE);
            let mut output = BufReader::new(output);
            loop {
                let mut line = Vec::new();
                if output.read_until(b'\n', &mut line).unwrap() == 0 {
                    break;
                }
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            process,
            input,
            messages,
            output: RefCell::default(),
        }
    }

    pub fn line(&self) -> Vec<u8> {
        self.messages.recv_timeout(LIMIT).expect("control line")
    }

    pub fn command(&mut self, command: &str) -> Vec<u8> {
        writeln!(self.input, "{command}").unwrap();
        self.reply()
    }

    pub fn reply(&self) -> Vec<u8> {
        loop {
            let line = self.line();
            if line.starts_with(b"%begin ") {
                break;
            }
            self.remember_output(&line);
        }
        let mut out = Vec::new();
        loop {
            let line = self.line();
            if line.starts_with(b"%end ") {
                return out;
            }
            assert!(
                !line.starts_with(b"%error "),
                "command failed: {}",
                String::from_utf8_lossy(&out)
            );
            assert!(!line.starts_with(b"%output "), "notification inside reply");
            out.extend(line);
        }
    }

    pub fn state(&mut self) -> serde_json::Value {
        // Drain the attach handshake before sending a query. The process ID
        // distinguishes fresh daemon %0 from the previous daemon's %0.
        let body = self.command("list-panes -a -F '#{pane_id} #{pane_pid}'");
        let body = if body.is_empty() { self.reply() } else { body };
        let panes: serde_json::Map<String, serde_json::Value> = String::from_utf8(body)
            .unwrap()
            .lines()
            .map(|line| {
                let (id, pid) = line.split_once(' ').unwrap();
                (id.to_owned(), serde_json::Value::String(pid.into()))
            })
            .collect();
        serde_json::json!({"panes": panes})
    }

    pub fn output_contains(&self, pane: &str, expected: &[u8]) {
        let deadline = std::time::Instant::now() + LIMIT;
        loop {
            {
                let mut panes = self.output.borrow_mut();
                let output = panes.entry(pane.into()).or_default();
                if let Some(at) = output
                    .windows(expected.len())
                    .position(|part| part == expected)
                {
                    output.drain(..at + expected.len());
                    return;
                }
            }
            let body = self
                .messages
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or_else(|error| {
                    panic!(
                        "waiting for {pane} {:?}: {error}; output: {:?}",
                        String::from_utf8_lossy(expected),
                        self.output.borrow()
                    )
                });
            self.remember_output(&body);
        }
    }

    fn remember_output(&self, line: &[u8]) {
        if let Some(body) = line.strip_prefix(b"%output ") {
            let space = body.iter().position(|b| *b == b' ').unwrap();
            let pane = String::from_utf8(body[..space].to_vec()).unwrap();
            self.output
                .borrow_mut()
                .entry(pane)
                .or_default()
                .extend(unescape(body[space + 1..].strip_suffix(b"\n").unwrap()));
        }
    }

    pub fn finish(&mut self) {
        use wait_timeout::ChildExt;
        assert!(self
            .process
            .wait_timeout(LIMIT)
            .unwrap()
            .expect("htm exit")
            .success());
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn output_before_reply_and_interleaved_panes_are_retained() {
    let mut process = Command::new(executable())
        .arg("--version")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let input = process.stdin.take().unwrap();
    let (sender, messages) = mpsc::channel();
    let relay = Relay {
        process,
        input,
        messages,
        output: RefCell::default(),
    };
    for line in [
        "%output %1 hel\n",
        "%begin 1 1 1\n",
        "%end 1 1 1\n",
        "%output %2 other\n",
        "%output %1 lo\\040world\n",
    ] {
        sender.send(line.as_bytes().to_vec()).unwrap();
    }
    assert!(relay.reply().is_empty());
    relay.output_contains("%1", b"hello world");
    relay.output_contains("%2", b"other");
    assert!(relay.output.borrow().values().all(Vec::is_empty));
}

/// Owns the namespace and shutdown capability of an automatically started daemon.
/// Unlike foreground Daemon, the detached process is reaped by its OS parent.
pub struct Endpoint {
    pub path: PathBuf,
    directory: PathBuf,
}

impl Endpoint {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        let base = PathBuf::from("/tmp");
        #[cfg(all(unix, not(target_os = "macos")))]
        let base = std::env::temp_dir();
        #[cfg(windows)]
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let directory = base.join(format!(
            "et-htm-auto-{}-{}",
            std::process::id(),
            et_core::keys::gen_id_passkey().0
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            path: directory.join("htm.ipc"),
            directory,
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let cleanup = (|| -> std::io::Result<()> {
            match et_htm::transport::connect(&self.path) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(LIMIT))?;
                    stream.set_write_timeout(Some(LIMIT))?;
                    stream.write_all(b"kill-server\n")?;
                    std::io::copy(&mut stream, &mut std::io::sink())?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            std::fs::remove_dir_all(&self.directory)
        })();
        if let Err(error) = cleanup {
            eprintln!("HTM autostart cleanup failed: {error}");
            assert!(std::thread::panicking(), "HTM autostart cleanup failed");
        }
    }
}

pub fn unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            out.push((bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + bytes[i + 3] - b'0');
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}
