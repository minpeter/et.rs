//! Detaching the per-session terminal process.
//!
//! Upstream's `etterminal` prints the `IDPASSKEY:` marker and then becomes a
//! session leader (`DaemonCreator::createSessionLeader`) so the bootstrap `ssh`
//! can return while the session keeps running. Forking is not expressible in
//! safe Rust, so the same end state is reached by re-executing this binary as a
//! detached child and waiting for it to report readiness.
//!
//! The readiness channel is a Unix socket on POSIX and a loopback TCP socket on
//! Windows, where the `--ready-socket` value carries `127.0.0.1:<port>`.

#[cfg(unix)]
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::terminal_credentials::CredentialInput;

const READY_TIMEOUT: Duration = Duration::from_secs(10);

pub fn spawn(router: &Path, input: &CredentialInput, verbose: u8) -> Result<(), String> {
    spawn_with_args(router, input, verbose, &[])
}

/// Spawn the detached session process, forwarding `extra` arguments (used by
/// `--jump` to pass the relay destination).
pub fn spawn_with_args(
    router: &Path,
    input: &CredentialInput,
    verbose: u8,
    extra: &[String],
) -> Result<(), String> {
    let readiness = Readiness::bind()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate et executable: {error}"))?;
    let mut child = Command::new(executable);
    child
        .args([
            "terminal",
            "--session-child",
            "--ready-socket",
            &readiness.address(),
            "--serverfifo",
            router
                .to_str()
                .ok_or_else(|| "invalid terminal router path".to_owned())?,
            &format!("--verbose={verbose}"),
        ])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::detach::configure(&mut child);
    let mut child = crate::detach::spawn(&mut child)
        .map_err(|error| format!("could not start terminal session process: {error}"))?;
    let credential_line = format!("{}/{}_{}\n", input.id, input.passkey, input.term);
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "terminal child stdin was not created".to_owned())
        .and_then(|mut stdin| {
            stdin
                .write_all(credential_line.as_bytes())
                .map_err(|error| format!("could not send terminal credentials: {error}"))
        });
    if let Err(error) = write_result {
        stop(&mut child);
        readiness.cleanup();
        return Err(error);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let acceptor = readiness.acceptor();
    let worker = std::thread::Builder::new()
        .name("et-terminal-ready".to_owned())
        .spawn(move || {
            let _ = sender.send(acceptor.accept_ready());
        })
        .map_err(|error| format!("could not start terminal readiness worker: {error}"))?;
    let result = receiver
        .recv_timeout(READY_TIMEOUT)
        .map_err(|_| "timed out waiting for terminal session process".to_owned())
        .and_then(|result| {
            result
                .map_err(|error| format!("terminal session process did not become ready: {error}"))
        });
    if result.is_err() {
        stop(&mut child);
        readiness.unblock();
    }
    let _ = worker.join();
    readiness.cleanup();
    result
}

/// Tell the parent this session is live. `target` is the value that was passed
/// through `--ready-socket`.
pub fn signal(target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let mut stream = std::os::unix::net::UnixStream::connect(target)
        .map_err(|error| format!("could not connect terminal readiness socket: {error}"))?;
    #[cfg(windows)]
    let mut stream = {
        let address = target
            .to_str()
            .and_then(|value| value.parse::<std::net::SocketAddr>().ok())
            .ok_or_else(|| "invalid terminal readiness address".to_owned())?;
        std::net::TcpStream::connect(address)
            .map_err(|error| format!("could not connect terminal readiness socket: {error}"))?
    };
    stream
        .write_all(&[1])
        .map_err(|error| format!("could not signal terminal readiness: {error}"))
}

/// Readiness listener, owned by the spawning parent.
struct Readiness {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(unix)]
    directory: PathBuf,
    #[cfg(unix)]
    socket: PathBuf,
    #[cfg(windows)]
    listener: std::net::TcpListener,
    #[cfg(windows)]
    address: std::net::SocketAddr,
}

struct Acceptor {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(windows)]
    listener: std::net::TcpListener,
}

impl Readiness {
    fn bind() -> Result<Self, String> {
        #[cfg(unix)]
        {
            let directory = readiness_directory()?;
            let socket = directory.join("ready.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket)
                .map_err(|error| format!("could not bind terminal readiness socket: {error}"))?;
            Ok(Self {
                listener,
                directory,
                socket,
            })
        }
        #[cfg(windows)]
        {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .map_err(|error| format!("could not bind terminal readiness socket: {error}"))?;
            let address = listener
                .local_addr()
                .map_err(|error| format!("could not inspect readiness socket: {error}"))?;
            Ok(Self { listener, address })
        }
    }

    fn address(&self) -> String {
        #[cfg(unix)]
        {
            self.socket.to_string_lossy().into_owned()
        }
        #[cfg(windows)]
        {
            self.address.to_string()
        }
    }

    fn acceptor(&self) -> Acceptor {
        Acceptor {
            listener: self
                .listener
                .try_clone()
                .expect("readiness listener clone must succeed"),
        }
    }

    /// Release a blocked acceptor when the child failed to start.
    fn unblock(&self) {
        #[cfg(unix)]
        let _ = std::os::unix::net::UnixStream::connect(&self.socket);
        #[cfg(windows)]
        let _ = std::net::TcpStream::connect(self.address);
    }

    fn cleanup(&self) {
        #[cfg(unix)]
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Acceptor {
    fn accept_ready(&self) -> std::io::Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        let mut ready = [0u8; 1];
        stream.read_exact(&mut ready)?;
        if ready == [1] {
            Ok(())
        } else {
            Err(std::io::Error::other("invalid readiness byte"))
        }
    }
}

#[cfg(unix)]
fn readiness_directory() -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "et-rs-terminal-ready-{}-{}",
        std::process::id(),
        et_core::keys::gen_id_passkey().0
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|error| format!("could not create terminal readiness directory: {error}"))?;
    Ok(directory)
}

fn stop(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
