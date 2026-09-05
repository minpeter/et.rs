//! HTM daemon startup and shutdown through owned process/IPC capabilities.
//! Never enumerate or kill unrelated processes named et.exe or htmd.exe.

use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use crate::detach::{Child, Stdio};

struct Startup(Option<Child>);

impl Drop for Startup {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            if let Err(error) = child.kill() {
                eprintln!("htm: stopping failed daemon startup: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("htm: reaping failed daemon startup: {error}");
            }
        }
    }
}

pub fn spawn(path: &Path) -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let mut command = crate::detach::direct_command(executable.as_os_str());
    command
        .args(["htmd", "--daemon-child", "--ready-stdout", "--socket"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::detach::configure(&mut command);
    let mut child = crate::detach::spawn(&mut command)?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing htmd readiness pipe"))?;
    let mut startup = Startup(Some(child));
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("htmd-startup".to_owned())
        .spawn(move || {
            let mut ready = [0; 11];
            let result = output.read_exact(&mut ready).and_then(|()| {
                if &ready == b"HTMD_READY\n" {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid htmd readiness marker",
                    ))
                }
            });
            // The receiver may have timed out and killed this owned child.
            let _ = send.send(result);
        })?;
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
        .and_then(|result| result);
    if result.is_ok() {
        startup.0.take();
    }
    // Failure closes the child's writer before joining the status reader.
    drop(startup);
    worker
        .join()
        .map_err(|_| io::Error::other("htmd readiness worker panicked"))?;
    result
}

pub fn stop(path: &Path) -> io::Result<()> {
    let mut stream = match et_htm::transport::connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    et_htm::framing::write_debug_keys(&mut stream, b"x")?;
    // EOF acknowledges shutdown only after the daemon retires its endpoint.
    io::copy(&mut stream, &mut io::sink())?;
    Ok(())
}
