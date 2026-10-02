//! Safe re-exec daemonization with a private authenticated readiness channel.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::local_ipc;
use et_cli::client::ClientArgs;

const CHILD: &str = "ET_RS_LOCAL_DAEMON_STATUS";

fn nonce() -> String {
    et_core::crypto::random_bytes::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn prepare(parsed: &mut ClientArgs, raw: &[OsString]) -> io::Result<Option<i32>> {
    if parsed.print_config
        || parsed.ssh_version
        || parsed.list_sessions
        || parsed.kill_named.is_some()
    {
        return Ok(None);
    }
    if parsed.ctl && parsed.session_name.is_none() {
        parsed.session_name = Some(parsed.attach.clone().unwrap_or_else(|| {
            let destination =
                et_cli::host::parse_host_string(parsed.host.as_deref().unwrap_or("anonymous"));
            let host: String = destination
                .host
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                        c
                    } else {
                        '-'
                    }
                })
                .take(40)
                .collect();
            let host = host.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let host = if host.is_empty() { "anonymous" } else { host };
            format!("{host}-{}", nonce())
        }));
    }
    if !(parsed.ctl || parsed.background) || parsed.control_command.is_some() {
        return Ok(None);
    }
    if std::env::var_os(CHILD).is_some() {
        crate::detach::close_inherited_descriptors()?;
        return Ok(None);
    }
    let directory = std::env::temp_dir().join(format!("et-ready-{}", nonce()));
    local_ipc::private_dir(&directory)?;
    let path = directory.join("status");
    let listener = local_ipc::Listener::bind(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("binding daemon readiness socket: {e}")))?;
    let result = (|| {
        let executable = std::env::current_exe()?.canonicalize()?;
        let mut command = crate::detach::direct_command(executable.as_os_str());
        command.arg("client");
        if parsed.ctl && parsed.attach.is_none() {
            command
                .arg("--name")
                .arg(parsed.session_name.as_deref().unwrap());
        }
        command
            .args(raw)
            .env(CHILD, &path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = crate::detach::spawn(&mut command)
            .map_err(|e| io::Error::new(e.kind(), format!("spawning background client: {e}")))?;
        let deadline = Instant::now() + Duration::from_secs(45);
        let startup = loop {
            if let Some(mut socket) = listener.accept().map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("accepting daemon readiness connection: {e}"),
                )
            })? {
                let received = read_status(&mut socket, local_ipc::TIMEOUT).map_err(|e| {
                    io::Error::new(e.kind(), format!("reading daemon readiness response: {e}"))
                });
                break received.and_then(|status| match status.split_first() {
                    Some((0, _)) => Ok(()),
                    Some((_, message)) => Err(io::Error::other(format!(
                        "background client startup failed: {}",
                        String::from_utf8_lossy(message)
                    ))),
                    None => Err(io::Error::other("empty daemon startup response")),
                });
            }
            if child.try_wait()?.is_some() {
                break Err(io::Error::other(
                    "background client exited before readiness",
                ));
            }
            if Instant::now() >= deadline {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "background client startup timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if startup.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        startup
    })();
    drop(listener);
    let _ = std::fs::remove_file(directory.join(".et-lock"));
    let _ = std::fs::remove_dir(directory);
    result?;
    if parsed.ctl {
        let name = parsed.session_name.as_deref().unwrap();
        let path = match parsed.ctl_socket.as_deref() {
            Some(path) => path.into(),
            None => crate::local_control::control_dir()?.join(format!("{name}.sock")),
        };
        println!(
            "et control session: {name}\ncontrol socket: {}",
            path.display()
        );
    }
    Ok(Some(0))
}

/// Keep the re-exec child in the foreground process group through SSH
/// authentication. Detach only after authentication, before copying stdio into
/// the terminal pump or passing its descriptors to a mux master.
pub fn detach() -> io::Result<()> {
    if std::env::var_os(CHILD).is_some() {
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        rustix::process::setsid()?;
        rustix::stdio::dup2_stdin(&null)?;
        rustix::stdio::dup2_stdout(&null)?;
        rustix::stdio::dup2_stderr(&null)?;
    }
    Ok(())
}

/// The accepted socket stays nonblocking: Darwin rejects SO_RCVTIMEO after
/// the sender has closed, even when its complete response is still buffered.
pub(super) fn read_status(
    socket: &mut std::os::unix::net::UnixStream,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut status = Vec::new();
    let mut buffer = [0; 8192];
    while status.len() < buffer.len() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let remaining = buffer.len() - status.len();
        match socket.read(&mut buffer[..remaining]) {
            Ok(0) => break,
            Ok(count) => status.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(status)
}

pub fn ready() -> io::Result<()> {
    if let Some(path) = std::env::var_os(CHILD) {
        local_ipc::connect(Path::new(&path))?.write_all(&[0])?;
        std::env::remove_var(CHILD);
    }
    Ok(())
}
pub fn failed(message: &str) {
    if let Some(path) = std::env::var_os(CHILD) {
        if let Ok(mut socket) = local_ipc::connect(Path::new(&path)) {
            let _ = socket.write_all(&[1]);
            let bytes = message.as_bytes();
            let _ = socket.write_all(&bytes[..bytes.len().min(8191)]);
        }
    }
}
