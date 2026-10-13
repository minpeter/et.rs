//! Agent proxy that records the session-bind bootstrap ssh sends (#881).
//!
//! The proxy relays every request to the real agent and keeps the last
//! non-forwarded `session-bind@openssh.com` request in forwarded form.
//! ProxyJump helpers bind before the destination, so the last binding belongs
//! to the final host. Bootstrap wiring is upstream #879 and is not done here.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::{
    forwarded_session_bind, log, session_bind_host_key_fingerprint, SessionBindLog,
    SSH_AGENT_MAX_MESSAGE_LENGTH,
};

const SLOW_AGENT_WARNING: Duration = Duration::from_secs(5);

pub struct SshAgentSessionBindRecorder {
    socket_path: PathBuf,
    #[cfg(unix)]
    directory: PathBuf,
    last: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    #[cfg(unix)]
    stop_write: std::os::unix::net::UnixStream,
}

impl SshAgentSessionBindRecorder {
    /// `upstream` empty means ssh had no agent: every request is answered with
    /// `SSH_AGENT_FAILURE`, and a well-formed bind is still recorded.
    pub fn start(upstream: impl AsRef<Path>) -> io::Result<Self> {
        #[cfg(unix)]
        {
            unix::start(upstream.as_ref())
        }
        #[cfg(windows)]
        {
            windows::start(upstream.as_ref())
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn last_forwarded_bind(&self) -> Option<Vec<u8>> {
        self.last.lock().ok().and_then(|guard| guard.clone())
    }
}

impl Drop for SshAgentSessionBindRecorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(unix)]
        {
            let _ = self.stop_write.write_all(&[1]);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(self.directory.join("agent.sock"));
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

fn note_bind(last: &Mutex<Option<Vec<u8>>>, request: &[u8]) {
    let Some(bind) = forwarded_session_bind(request) else {
        return;
    };
    if let Some(fingerprint) = session_bind_host_key_fingerprint(&bind) {
        log(
            SessionBindLog::Verbose,
            &format!("Agent proxy saw session binding for host key {fingerprint}"),
        );
    }
    if let Ok(mut guard) = last.lock() {
        *guard = Some(bind);
    }
}

fn pop_frame(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ()> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffer[..4].try_into().unwrap());
    if length == 0 || length > SSH_AGENT_MAX_MESSAGE_LENGTH {
        return Err(());
    }
    let total = 4 + usize::try_from(length).map_err(|_| ())?;
    if buffer.len() < total {
        return Ok(None);
    }
    let body = buffer[4..total].to_vec();
    buffer.drain(..total);
    Ok(Some(body))
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend(u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    framed.extend_from_slice(body);
    framed
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
mod unix {
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::io::Errno;

    use super::{
        frame, note_bind, pop_frame, random_token, SshAgentSessionBindRecorder, SLOW_AGENT_WARNING,
    };
    use crate::ssh_agent_session_bind::{
        log, SessionBindLog, SSH_AGENT_FAILURE, SSH_AGENT_MAX_MESSAGE_LENGTH,
    };

    pub(super) fn start(upstream: &Path) -> io::Result<SshAgentSessionBindRecorder> {
        let directory = private_directory()?;
        let socket_path = directory.join("agent.sock");
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
        listener.set_nonblocking(true)?;
        let (stop_read, stop_write) = UnixStream::pair()?;
        stop_read.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(None));
        let upstream_path = upstream.to_path_buf();
        let no_agent = upstream_is_empty(&upstream_path);
        let worker_stop = Arc::clone(&stop);
        let worker_last = Arc::clone(&last);
        let worker_path = socket_path.clone();
        let worker_upstream = upstream_path.clone();
        let worker = thread::Builder::new()
            .name("et-ssh-bind".to_owned())
            .spawn(move || {
                run(
                    listener,
                    stop_read,
                    worker_stop,
                    worker_last,
                    worker_upstream,
                    worker_path,
                );
            })?;
        if no_agent {
            log(
                SessionBindLog::Warning,
                &format!(
                    "ssh has no agent to authenticate with; agent proxy {} answers every request with failure",
                    socket_path.display()
                ),
            );
        } else {
            log(
                SessionBindLog::Info,
                &format!(
                    "Agent proxy {} relays to ssh agent {}",
                    socket_path.display(),
                    upstream_path.display()
                ),
            );
        }
        Ok(SshAgentSessionBindRecorder {
            socket_path,
            directory,
            last,
            stop,
            worker: Some(worker),
            stop_write,
        })
    }

    fn upstream_is_empty(path: &Path) -> bool {
        path.as_os_str().is_empty()
    }

    fn private_directory() -> io::Result<PathBuf> {
        let directory = std::env::temp_dir().join(format!("et-ssh-bind-{}", random_token()?));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    struct Client {
        stream: UnixStream,
        upstream: Option<UnixStream>,
        buffer: Vec<u8>,
    }

    fn run(
        listener: UnixListener,
        stop_read: UnixStream,
        stop: Arc<AtomicBool>,
        last: Arc<Mutex<Option<Vec<u8>>>>,
        upstream_path: PathBuf,
        socket_path: PathBuf,
    ) {
        let mut clients: Vec<Client> = Vec::new();
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let mut polls = Vec::with_capacity(clients.len() + 2);
            polls.push(PollFd::new(&stop_read, PollFlags::IN));
            polls.push(PollFd::new(&listener, PollFlags::IN));
            for client in &clients {
                polls.push(PollFd::new(&client.stream, PollFlags::IN));
            }
            match poll(
                &mut polls,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 100_000_000,
                }),
            ) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(error) => {
                    log(
                        SessionBindLog::Warning,
                        &format!("agent proxy poll failed: {error}"),
                    );
                    break;
                }
            }
            let stop_ready = polls[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR);
            let accept_ready = polls[1].revents().contains(PollFlags::IN);
            let client_ready: Vec<bool> = polls[2..]
                .iter()
                .map(|descriptor| {
                    descriptor
                        .revents()
                        .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
                })
                .collect();
            drop(polls);
            if stop_ready || stop.load(Ordering::Acquire) {
                break;
            }
            let mut dead = Vec::new();
            for (index, ready) in client_ready.into_iter().enumerate() {
                if ready && !service(&mut clients[index], &stop, &last, &socket_path) {
                    dead.push(index);
                }
            }
            for index in dead.into_iter().rev() {
                clients.swap_remove(index);
            }
            if accept_ready {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(true);
                        let upstream = connect_upstream(&upstream_path, &stop);
                        clients.push(Client {
                            stream,
                            upstream,
                            buffer: Vec::new(),
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        drop(clients);
        let _ = socket_path;
    }

    fn service(
        client: &mut Client,
        stop: &AtomicBool,
        last: &Mutex<Option<Vec<u8>>>,
        socket_path: &Path,
    ) -> bool {
        let mut chunk = [0u8; 4096];
        let count = match client.stream.read(&mut chunk) {
            Ok(0) => return false,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return true,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        };
        client.buffer.extend_from_slice(&chunk[..count]);
        loop {
            let request = match pop_frame(&mut client.buffer) {
                Ok(Some(request)) => request,
                Ok(None) => return true,
                Err(()) => return false,
            };
            note_bind(last, &request);
            let reply = match relay(client, &request, stop, socket_path) {
                Some(reply) => reply,
                None => return false,
            };
            if write_all_cancellable(&mut client.stream, &frame(&reply), stop).is_err() {
                return false;
            }
        }
    }

    fn relay(
        client: &mut Client,
        request: &[u8],
        stop: &AtomicBool,
        socket_path: &Path,
    ) -> Option<Vec<u8>> {
        let Some(upstream) = client.upstream.as_mut() else {
            return Some(vec![SSH_AGENT_FAILURE]);
        };
        if write_all_cancellable(upstream, &frame(request), stop).is_err() {
            return None;
        }
        match read_frame(upstream, stop, socket_path) {
            Ok(body) => Some(body),
            Err(_) => None,
        }
    }

    fn connect_upstream(path: &Path, stop: &AtomicBool) -> Option<UnixStream> {
        if path.as_os_str().is_empty() || stop.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(path) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                Some(stream)
            }
            Err(error) => {
                log(
                    SessionBindLog::Warning,
                    &format!(
                        "Could not connect to ssh agent {}: {error}",
                        path.display()
                    ),
                );
                None
            }
        }
    }

    fn read_frame(stream: &mut UnixStream, stop: &AtomicBool, socket_path: &Path) -> io::Result<Vec<u8>> {
        let mut length_bytes = [0u8; 4];
        read_exact_cancellable(stream, &mut length_bytes, stop, socket_path)?;
        let length = u32::from_be_bytes(length_bytes);
        if length == 0 || length > SSH_AGENT_MAX_MESSAGE_LENGTH {
            log(
                SessionBindLog::Warning,
                &format!(
                    "ssh agent {} sent an invalid reply (length {length})",
                    socket_path.display()
                ),
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ssh agent reply length",
            ));
        }
        let mut body = vec![0u8; length as usize];
        read_exact_cancellable(stream, &mut body, stop, socket_path)?;
        Ok(body)
    }

    fn read_exact_cancellable(
        stream: &mut UnixStream,
        buf: &mut [u8],
        stop: &AtomicBool,
        socket_path: &Path,
    ) -> io::Result<()> {
        let started = Instant::now();
        let mut warned = false;
        let mut filled = 0;
        while filled < buf.len() {
            if stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "agent proxy stopped",
                ));
            }
            if !warned && started.elapsed() >= SLOW_AGENT_WARNING {
                warned = true;
                log(
                    SessionBindLog::Warning,
                    &format!(
                        "ssh agent {} has not answered for {}s; still waiting (it may be asking to confirm a key)",
                        socket_path.display(),
                        SLOW_AGENT_WARNING.as_secs()
                    ),
                );
            }
            match stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ssh agent closed the reply",
                    ));
                }
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !wait_readable(stream, stop)? {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "agent proxy stopped",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_all_cancellable(stream: &mut UnixStream, bytes: &[u8], stop: &AtomicBool) -> io::Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            if stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "agent proxy stopped",
                ));
            }
            match stream.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ssh agent write blocked",
                    ));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut polls = [PollFd::new(stream, PollFlags::OUT)];
                    match poll(&mut polls, Some(&rustix::event::Timespec { tv_sec: 0, tv_nsec: 50_000_000 })) {
                        Ok(_) => {}
                        Err(Errno::INTR) => {}
                        Err(error) => return Err(io::Error::from(error)),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn wait_readable(stream: &UnixStream, stop: &AtomicBool) -> io::Result<bool> {
        if stop.load(Ordering::Acquire) {
            return Ok(false);
        }
        let mut polls = [PollFd::new(stream, PollFlags::IN)];
        match poll(
            &mut polls,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            }),
        ) {
            Ok(_) => Ok(true),
            Err(Errno::INTR) => Ok(true),
            Err(error) => Err(io::Error::from(error)),
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io::{self, Read, Write};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use interprocess::os::windows::named_pipe::{pipe_mode, DuplexPipeStream, PipeListenerOptions};
    use interprocess::ConnectWaitMode;

    use super::{
        frame, note_bind, pop_frame, random_token, SshAgentSessionBindRecorder, SLOW_AGENT_WARNING,
    };
    use crate::ssh_agent_session_bind::{log, SessionBindLog, SSH_AGENT_FAILURE, SSH_AGENT_MAX_MESSAGE_LENGTH};

    pub(super) fn start(upstream: &Path) -> io::Result<SshAgentSessionBindRecorder> {
        let socket_path = format!(r"\\.\pipe\et-ssh-bind-{}", random_token()?);
        let mut options = PipeListenerOptions::new().path(socket_path.as_str());
        options.accept_remote = false;
        options.nonblocking = true;
        options.inheritable = false;
        options.input_buffer_size_hint = SSH_AGENT_MAX_MESSAGE_LENGTH.saturating_add(4);
        options.output_buffer_size_hint = SSH_AGENT_MAX_MESSAGE_LENGTH.saturating_add(4);
        if let Some(descriptor) = current_user_security_descriptor() {
            options.security_descriptor = Some(descriptor);
        }
        let listener = options.create_duplex::<pipe_mode::Bytes>()?;
        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(None));
        let upstream = upstream.to_path_buf();
        let worker_stop = Arc::clone(&stop);
        let worker_last = Arc::clone(&last);
        let worker = thread::Builder::new()
            .name("et-ssh-bind".to_owned())
            .spawn(move || run(listener, worker_stop, worker_last, upstream))?;
        log(
            SessionBindLog::Info,
            &format!("Agent proxy {socket_path} relays to ssh agent {}", upstream.display()),
        );
        Ok(SshAgentSessionBindRecorder {
            socket_path: socket_path.into(),
            last,
            stop,
            worker: Some(worker),
        })
    }

    fn current_user_security_descriptor(
    ) -> Option<interprocess::os::windows::security_descriptor::SecurityDescriptor> {
        let output = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let sid = text.split(',').nth(1)?.trim().trim_matches('"');
        if !sid.starts_with("S-") {
            return None;
        }
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let wide = widestring::U16CString::from_str(sddl).ok()?;
        interprocess::os::windows::security_descriptor::SecurityDescriptor::deserialize(
            wide.as_ucstr(),
        )
        .ok()
    }

    fn run(
        listener: interprocess::os::windows::named_pipe::PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>,
        stop: Arc<AtomicBool>,
        last: Arc<Mutex<Option<Vec<u8>>>>,
        upstream: std::path::PathBuf,
    ) {
        let mut clients = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok(stream) => {
                    let _ = stream.set_nonblocking(true);
                    let stop = Arc::clone(&stop);
                    let last = Arc::clone(&last);
                    let upstream = upstream.clone();
                    clients.retain(|handle: &JoinHandle<()>| !handle.is_finished());
                    clients.push(thread::spawn(move || {
                        let _ = serve(stream, &stop, &last, &upstream);
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        for handle in clients {
            let _ = handle.join();
        }
    }

    fn serve(
        mut client: DuplexPipeStream<pipe_mode::Bytes>,
        stop: &AtomicBool,
        last: &Mutex<Option<Vec<u8>>>,
        upstream_path: &Path,
    ) -> io::Result<()> {
        let mut upstream = connect_upstream(upstream_path, stop);
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        while !stop.load(Ordering::Acquire) {
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            loop {
                let request = match pop_frame(&mut buffer) {
                    Ok(Some(request)) => request,
                    Ok(None) => break,
                    Err(()) => return Ok(()),
                };
                note_bind(last, &request);
                let reply = relay(&mut upstream, &request, stop, upstream_path)?;
                client.write_all(&frame(&reply))?;
            }
        }
        Ok(())
    }

    fn relay(
        upstream: &mut Option<DuplexPipeStream<pipe_mode::Bytes>>,
        request: &[u8],
        stop: &AtomicBool,
        path: &Path,
    ) -> io::Result<Vec<u8>> {
        let Some(stream) = upstream.as_mut() else {
            return Ok(vec![SSH_AGENT_FAILURE]);
        };
        if write_all_cancellable(stream, &frame(request), stop).is_err() {
            return Err(io::Error::other("ssh agent write failed"));
        }
        read_frame(stream, stop, path)
    }

    fn connect_upstream(path: &Path, stop: &AtomicBool) -> Option<DuplexPipeStream<pipe_mode::Bytes>> {
        if path.as_os_str().is_empty() {
            return None;
        }
        let path = path.to_string_lossy();
        while !stop.load(Ordering::Acquire) {
            match DuplexPipeStream::connect_by_path_with_wait_mode(
                path.as_ref(),
                ConnectWaitMode::Timeout(Duration::from_millis(50)),
            ) {
                Ok(stream) => {
                    let _ = stream.set_nonblocking(true);
                    return Some(stream);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) if error.raw_os_error() == Some(231) => {}
                Err(error) => {
                    log(
                        SessionBindLog::Warning,
                        &format!("Could not connect to ssh agent {path}: {error}"),
                    );
                    return None;
                }
            }
        }
        None
    }

    fn read_frame(
        stream: &mut DuplexPipeStream<pipe_mode::Bytes>,
        stop: &AtomicBool,
        path: &Path,
    ) -> io::Result<Vec<u8>> {
        let mut length_bytes = [0u8; 4];
        read_exact_cancellable(stream, &mut length_bytes, stop, path)?;
        let length = u32::from_be_bytes(length_bytes);
        if length == 0 || length > SSH_AGENT_MAX_MESSAGE_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ssh agent reply length",
            ));
        }
        let mut body = vec![0u8; length as usize];
        read_exact_cancellable(stream, &mut body, stop, path)?;
        Ok(body)
    }

    fn read_exact_cancellable(
        stream: &mut DuplexPipeStream<pipe_mode::Bytes>,
        buf: &mut [u8],
        stop: &AtomicBool,
        path: &Path,
    ) -> io::Result<()> {
        let started = Instant::now();
        let mut warned = false;
        let mut filled = 0;
        while filled < buf.len() {
            if stop.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "agent proxy stopped"));
            }
            if !warned && started.elapsed() >= SLOW_AGENT_WARNING {
                warned = true;
                log(
                    SessionBindLog::Warning,
                    &format!(
                        "ssh agent {} has not answered for {}s; still waiting (it may be asking to confirm a key)",
                        path.display(),
                        SLOW_AGENT_WARNING.as_secs()
                    ),
                );
            }
            match stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ssh agent closed the reply",
                    ));
                }
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_all_cancellable(
        stream: &mut DuplexPipeStream<pipe_mode::Bytes>,
        bytes: &[u8],
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            if stop.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "agent proxy stopped"));
            }
            match stream.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "ssh agent write blocked"));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::SshAgentSessionBindRecorder;
    use crate::ssh_agent_session_bind::{
        encode_session_bind, frame_agent_message, SSH_AGENTC_EXTENSION, SSH_AGENT_FAILURE,
        SSH_AGENT_SUCCESS,
    };

    struct FakeAgent {
        path: PathBuf,
        directory: PathBuf,
        received: Arc<Mutex<Vec<Vec<u8>>>>,
        worker: Option<JoinHandle<()>>,
    }

    impl FakeAgent {
        fn new(reply: impl Fn(Vec<u8>) -> Vec<u8> + Send + 'static) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "et-fake-agent-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("agent.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&received);
            let worker = thread::spawn(move || {
                let _ = listener.set_nonblocking(true);
                let deadline = std::time::Instant::now() + Duration::from_secs(8);
                while std::time::Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
                            let mut buffer = Vec::new();
                            let mut chunk = [0u8; 1024];
                            loop {
                                match stream.read(&mut chunk) {
                                    Ok(0) | Err(_) => break,
                                    Ok(count) => {
                                        buffer.extend_from_slice(&chunk[..count]);
                                        while let Some(body) = take_frame(&mut buffer) {
                                            recorded.lock().unwrap().push(body.clone());
                                            let response = reply(body);
                                            if response.is_empty() {
                                                return;
                                            }
                                            let _ = stream.write_all(&frame_agent_message(&response).unwrap());
                                        }
                                    }
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                path,
                directory,
                received,
                worker: Some(worker),
            }
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn take_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
        if buffer.len() < 4 {
            return None;
        }
        let length = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
        if length == 0 || buffer.len() < 4 + length {
            return None;
        }
        let body = buffer[4..4 + length].to_vec();
        buffer.drain(..4 + length);
        Some(body)
    }

    fn round_trip(stream: &mut UnixStream, request: &[u8]) -> Vec<u8> {
        stream
            .write_all(&frame_agent_message(request).unwrap())
            .unwrap();
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let size = u32::from_be_bytes(length) as usize;
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).unwrap();
        body
    }

    fn connect(path: &std::path::Path) -> UnixStream {
        let stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
        stream
    }

    #[test]
    fn recorder_relays_requests_and_keeps_the_last_forwarded_bind() {
        let agent = FakeAgent::new(|request| {
            if request.first() == Some(&11) {
                let mut answer = vec![SSH_AGENT_SUCCESS];
                answer.extend_from_slice(&[0, 0, 0, 0]);
                return answer;
            }
            vec![SSH_AGENT_SUCCESS]
        });
        let recorder = SshAgentSessionBindRecorder::start(&agent.path).unwrap();
        assert!(recorder.last_forwarded_bind().is_none());
        let mut jump = connect(recorder.socket_path());
        assert_eq!(
            round_trip(
                &mut jump,
                &encode_session_bind(b"jump-key", b"sid", b"sig", false).unwrap()
            ),
            vec![SSH_AGENT_SUCCESS]
        );
        drop(jump);
        let mut destination = connect(recorder.socket_path());
        assert_eq!(
            round_trip(
                &mut destination,
                &encode_session_bind(b"dest-key", b"sid", b"sig", false).unwrap()
            ),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(
            round_trip(&mut destination, &[11]),
            vec![SSH_AGENT_SUCCESS, 0, 0, 0, 0]
        );
        drop(destination);
        assert_eq!(
            recorder.last_forwarded_bind().as_deref(),
            Some(encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap().as_slice())
        );
        let received = agent.received.lock().unwrap();
        assert_eq!(received.len(), 3);
        assert_eq!(
            received[0],
            encode_session_bind(b"jump-key", b"sid", b"sig", false).unwrap()
        );
        assert_eq!(
            received[1],
            encode_session_bind(b"dest-key", b"sid", b"sig", false).unwrap()
        );
    }

    #[test]
    fn recorder_without_an_agent_fails_requests_and_still_records_the_bind() {
        for upstream in [PathBuf::new(), PathBuf::from("/nonexistent/et/agent.sock")] {
            let recorder = SshAgentSessionBindRecorder::start(&upstream).unwrap();
            let path = recorder.socket_path().to_path_buf();
            let mut client = connect(&path);
            assert_eq!(
                round_trip(&mut client, &[11]),
                vec![SSH_AGENT_FAILURE]
            );
            assert_eq!(
                round_trip(
                    &mut client,
                    &encode_session_bind(b"dest-key", b"sid", b"sig", false).unwrap()
                ),
                vec![SSH_AGENT_FAILURE]
            );
            assert_eq!(
                recorder.last_forwarded_bind().as_deref(),
                Some(encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap().as_slice())
            );
            drop(client);
            drop(recorder);
            assert!(!path.parent().unwrap().exists());
        }
    }

    #[test]
    fn recorder_accepts_split_and_pipelined_requests() {
        let agent = FakeAgent::new(|request| {
            let mut answer = vec![SSH_AGENT_SUCCESS];
            answer.extend(request);
            answer
        });
        let recorder = SshAgentSessionBindRecorder::start(&agent.path).unwrap();
        let mut client = connect(recorder.socket_path());
        let bind = frame_agent_message(
            &encode_session_bind(b"dest-key", b"sid", b"sig", false).unwrap(),
        )
        .unwrap();
        let identities = frame_agent_message(&[SSH_AGENTC_EXTENSION]).unwrap();
        client.write_all(&bind[..6]).unwrap();
        thread::sleep(Duration::from_millis(50));
        let mut rest = bind[6..].to_vec();
        rest.extend_from_slice(&identities);
        client.write_all(&rest).unwrap();
        let first = {
            let mut length = [0u8; 4];
            client.read_exact(&mut length).unwrap();
            let size = u32::from_be_bytes(length) as usize;
            let mut body = vec![0u8; size];
            client.read_exact(&mut body).unwrap();
            body
        };
        assert_eq!(
            first,
            [
                vec![SSH_AGENT_SUCCESS],
                encode_session_bind(b"dest-key", b"sid", b"sig", false).unwrap()
            ]
            .concat()
        );
        assert_eq!(
            recorder.last_forwarded_bind().as_deref(),
            Some(encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap().as_slice())
        );
    }

    #[test]
    fn recorder_drops_a_malformed_length() {
        let recorder = SshAgentSessionBindRecorder::start("").unwrap();
        let mut client = connect(recorder.socket_path());
        client.write_all(&0u32.to_be_bytes()).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn recorder_shuts_down_while_a_request_is_pending() {
        let directory = std::env::temp_dir().join(format!(
            "et-hang-agent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let recorder = SshAgentSessionBindRecorder::start(&path).unwrap();
        let mut client = connect(recorder.socket_path());
        client
            .write_all(&frame_agent_message(&[11]).unwrap())
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        let started = std::time::Instant::now();
        drop(recorder);
        assert!(started.elapsed() < Duration::from_secs(5));
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
        drop(listener);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
