#![cfg(unix)]
#![allow(dead_code)]

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_PROMPT_LATENCY: Duration = Duration::from_secs(5);
pub const THROTTLE_BYTES_PER_SECOND: usize = 100 * 1024;
pub const BASELINE_BYTES_PER_SECOND: usize = 16 * 1024;
pub const SATURATION_BYTES: usize = 64 * 1024;

pub fn receive_until(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, mpsc::RecvTimeoutError> {
    let deadline = Instant::now() + timeout;
    while !output.windows(marker.len()).any(|window| window == marker) {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(mpsc::RecvTimeoutError::Timeout);
        };
        output.extend(receiver.recv_timeout(remaining)?);
    }
    Ok(output)
}

pub fn receive_bytes(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    additional: usize,
    timeout: Duration,
) -> Result<Vec<u8>, mpsc::RecvTimeoutError> {
    let target = output.len() + additional;
    let deadline = Instant::now() + timeout;
    while output.len() < target {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(mpsc::RecvTimeoutError::Timeout);
        };
        output.extend(receiver.recv_timeout(remaining)?);
    }
    Ok(output)
}

pub struct ThrottleProxy {
    pub port: u16,
    stop: mpsc::Receiver<TcpStream>,
    worker: thread::JoinHandle<io::Result<()>>,
}

impl ThrottleProxy {
    pub fn start(server_port: u16, bytes_per_second: usize) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, stop) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept()?;
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_recv_buffer_size(64 * 1024)?;
            socket.connect(&SockAddr::from(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                server_port,
            )))?;
            let mut server = TcpStream::from(socket);
            stop_tx
                .send(server.try_clone()?)
                .map_err(|_| io::Error::other("proxy stop receiver closed"))?;
            let mut client_read = client.try_clone()?;
            let mut server_write = server.try_clone()?;
            let upstream = thread::spawn(move || io::copy(&mut client_read, &mut server_write));

            let downstream = (|| {
                let started = Instant::now();
                let mut transferred = 0usize;
                let mut chunk = [0u8; 8192];
                loop {
                    let count = server.read(&mut chunk)?;
                    if count == 0 {
                        return Ok(());
                    }
                    client.write_all(&chunk[..count])?;
                    transferred += count;
                    let expected =
                        Duration::from_secs_f64(transferred as f64 / bytes_per_second as f64);
                    if let Some(remaining) = expected.checked_sub(started.elapsed()) {
                        thread::sleep(remaining);
                    }
                }
            })();
            let _ = client.shutdown(Shutdown::Both);
            let _ = server.shutdown(Shutdown::Both);
            let upstream = upstream
                .join()
                .map_err(|_| io::Error::other("proxy upload thread panicked"))?;
            normalize_proxy_close(downstream)?;
            normalize_proxy_close(upstream.map(|_| ()))
        });
        Self { port, stop, worker }
    }

    pub fn finish(self) -> io::Result<()> {
        let stream = self
            .stop
            .recv_timeout(TIMEOUT)
            .map_err(|_| io::Error::other("proxy did not accept client"))?;
        let _ = stream.shutdown(Shutdown::Both);
        self.worker
            .join()
            .map_err(|_| io::Error::other("proxy worker panicked"))?
    }
}

fn normalize_proxy_close(result: io::Result<()>) -> io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub struct Stack {
    pub directory: std::path::PathBuf,
    pub router: std::path::PathBuf,
    pub terminal: std::path::PathBuf,
    pub port: u16,
    server: std::process::Child,
}

impl Stack {
    pub fn start() -> Self {
        let directory =
            std::env::temp_dir().join(format!("et-rs-flow-control-qa-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let router = directory.join("router.sock");
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let config = directory.join("et.cfg");
        fs::write(
            &config,
            format!(
                "[Networking]\nport={port}\nbind_ip=127.0.0.1\n[Debug]\nserverfifo={}\n",
                router.display()
            ),
        )
        .unwrap();
        let mut server = Command::new(env!("CARGO_BIN_EXE_et"))
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
            "#!/bin/sh\nif [ \"$1\" = \"-G\" ]; then\n\
             printf 'hostname 127.0.0.1\\nuser tester\\n'; exit 0; fi\n\
             for last do :; done\nexec /bin/sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let terminal = directory.join("etterminal");
        symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
        Self {
            directory,
            router,
            terminal,
            port,
            server,
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let pid = Pid::from_raw(i32::try_from(self.server.id()).unwrap());
        let _ = kill(pid, Signal::SIGTERM);
        let _ = self.server.wait_timeout(TIMEOUT);
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait_ready(server: &mut std::process::Child, port: u16, router: &std::path::Path) {
    let stdout = server.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
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
