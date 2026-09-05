use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use et_htm::{codes, framing};

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
        #[cfg(unix)]
        let base = std::env::temp_dir();
        #[cfg(windows)]
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let directory = base.join(format!(
            "et-htm-qa-{}-{}",
            std::process::id(),
            et_core::keys::gen_id_passkey().0
        ));
        std::fs::create_dir(&directory).unwrap();
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
    messages: Receiver<(u8, Vec<u8>)>,
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
            let mut enter = [0; 6];
            output.read_exact(&mut enter).unwrap();
            assert_eq!(&enter, codes::ENTER_HTM_MODE);
            loop {
                let mut header = [0];
                if output.read_exact(&mut header).is_err() || header[0] == 27 {
                    return;
                }
                if header[0] == codes::SESSION_END {
                    continue;
                }
                let length = usize::try_from(framing::read_length(&mut output).unwrap()).unwrap();
                let body = framing::read_exact_vec(&mut output, length).unwrap();
                if send.send((header[0], body)).is_err() {
                    return;
                }
            }
        });
        Self {
            process,
            input,
            messages,
        }
    }

    pub fn state(&self) -> serde_json::Value {
        loop {
            let (header, body) = self.messages.recv_timeout(LIMIT).expect("HTM state event");
            if header == codes::INIT_STATE {
                return serde_json::from_slice(&body).unwrap();
            }
        }
    }

    pub fn output_contains(&self, pane: &str, expected: &[u8]) {
        let deadline = std::time::Instant::now() + LIMIT;
        let mut output = Vec::new();
        loop {
            let (header, body) = self
                .messages
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("pane output event");
            if header == codes::APPEND_TO_PANE && body.starts_with(pane.as_bytes()) {
                output.extend(framing::decode(&body[codes::UUID_LENGTH..]).unwrap());
                if output.windows(expected.len()).any(|part| part == expected) {
                    return;
                }
            }
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

/// Owns the namespace and shutdown capability of an automatically started daemon.
/// Unlike foreground Daemon, the detached process is reaped by its OS parent.
pub struct Endpoint {
    pub path: PathBuf,
    directory: PathBuf,
}

impl Endpoint {
    pub fn new() -> Self {
        #[cfg(unix)]
        let base = std::env::temp_dir();
        #[cfg(windows)]
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let directory = base.join(format!(
            "et-htm-auto-{}-{}",
            std::process::id(),
            et_core::keys::gen_id_passkey().0
        ));
        std::fs::create_dir(&directory).unwrap();
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
                    framing::write_debug_keys(&mut stream, b"x")?;
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
