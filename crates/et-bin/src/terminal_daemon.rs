use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
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
    let directory = readiness_directory()?;
    let socket = directory.join("ready.sock");
    let listener = UnixListener::bind(&socket)
        .map_err(|error| format!("could not bind terminal readiness socket: {error}"))?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate et executable: {error}"))?;
    let mut child = Command::new(executable);
    child
        .args([
            "terminal",
            "--session-child",
            "--ready-socket",
            socket
                .to_str()
                .ok_or_else(|| "invalid readiness path".to_owned())?,
            "--serverfifo",
            router
                .to_str()
                .ok_or_else(|| "invalid terminal router path".to_owned())?,
            &format!("--verbose={verbose}"),
        ])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = child
        .spawn()
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
        cleanup(&directory);
        return Err(error);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("et-terminal-ready".to_owned())
        .spawn(move || {
            let result = listener.accept().and_then(|(mut stream, _)| {
                let mut ready = [0u8; 1];
                stream.read_exact(&mut ready)?;
                if ready == [1] {
                    Ok(())
                } else {
                    Err(std::io::Error::other("invalid readiness byte"))
                }
            });
            let _ = sender.send(result);
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
        let _ = UnixStream::connect(&socket);
    }
    let _ = worker.join();
    cleanup(&directory);
    result
}

pub fn signal(path: &Path) -> Result<(), String> {
    let mut stream = UnixStream::connect(path)
        .map_err(|error| format!("could not connect terminal readiness socket: {error}"))?;
    stream
        .write_all(&[1])
        .map_err(|error| format!("could not signal terminal readiness: {error}"))
}

fn readiness_directory() -> Result<std::path::PathBuf, String> {
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

fn cleanup(directory: &Path) {
    let _ = fs::remove_dir_all(directory);
}
