//! Raw pipe command channel (`et -T`), matching EternalTerminal #854.
//!
//! The remote command runs on `/bin/sh -c` (or `cmd.exe /c` on Windows) with
//! separate stdin, stdout, and stderr. There is no pty, no login shell, and
//! no `; exit` typed into a shell. Stderr is framed as `TerminalBuffer.is_stderr`.

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::local::LocalStream;
use et_net::local_packet::{write_local_packet_until_cancelled, LocalPacketDecoder};
use prost::Message;

use crate::terminal_protocol::{
    local_packet_effect, read_ready_packet, LocalPacketEffect, TerminalInitialization,
};

const MAX_OUTPUT_CHUNK: usize = 16 * 1024;
const MAX_PENDING_INPUT: usize = 256 * 1024;

enum PipeEvent {
    StdoutEof,
    StderrEof,
    Failed(String),
    Child(Result<i32, String>),
}

pub(crate) fn run<F>(
    mut router: LocalStream,
    initialization: TerminalInitialization,
    started: F,
) -> Result<i32, String>
where
    F: FnOnce(&mut LocalStream) -> Result<(), String>,
{
    let command = initialization
        .command
        .filter(|command| !command.is_empty())
        .ok_or_else(|| "no_pty TermInit requires a non-empty command".to_owned())?;
    if command.contains('\0') {
        return Err("pipe command contains NUL".to_owned());
    }

    let mut child = spawn_command(&command, &initialization.environment)?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "pipe command has no stdin".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "pipe command has no stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "pipe command has no stderr".to_owned())?;
    #[cfg(unix)]
    set_nonblocking(&stdin)?;

    let cancelled = Arc::new(AtomicBool::new(false));
    let kill_child = Arc::new(AtomicBool::new(false));
    let router_writer =
        Arc::new(Mutex::new(router.try_clone().map_err(|error| {
            format!("could not clone pipe router: {error}")
        })?));
    let (events_tx, events_rx) = mpsc::channel();
    let (wake_reader, wake_writer) = et_net::local::wake_pair()
        .map_err(|error| format!("could not create pipe wakeup: {error}"))?;

    let stdout_worker = spawn_output(
        stdout,
        router_writer.clone(),
        cancelled.clone(),
        false,
        events_tx.clone(),
        wake_writer
            .try_clone()
            .map_err(|error| format!("could not clone pipe wakeup: {error}"))?,
    )?;
    let stderr_worker = spawn_output(
        stderr,
        router_writer.clone(),
        cancelled.clone(),
        true,
        events_tx.clone(),
        wake_writer
            .try_clone()
            .map_err(|error| format!("could not clone pipe wakeup: {error}"))?,
    )?;
    let child_slot = Arc::new(Mutex::new(Some(child)));
    let waiter_slot = child_slot.clone();
    let waiter_kill = kill_child.clone();
    let child_wake = wake_writer;
    let child_worker = thread::Builder::new()
        .name("et-pipe-child".to_owned())
        .spawn(move || {
            let result = wait_child(waiter_slot, &waiter_kill);
            let _ = events_tx.send(PipeEvent::Child(result));
            signal(&mut { child_wake });
        })
        .map_err(|error| format!("could not start pipe child worker: {error}"))?;

    let workers = vec![stdout_worker, stderr_worker, child_worker];
    let cleanup = Cleanup {
        cancelled: cancelled.clone(),
        kill_child: kill_child.clone(),
        workers,
    };

    let startup = (|| {
        router
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure pipe router: {error}"))?;
        wake_reader
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure pipe wakeup: {error}"))?;
        let mut writer = router_writer
            .lock()
            .map_err(|_| "pipe router writer is unavailable".to_owned())?;
        started(&mut writer)
    })();
    if let Err(error) = startup {
        drop(cleanup);
        return Err(error);
    }

    let status = pump(&mut router, wake_reader, &events_rx, &mut Some(stdin));
    drop(cleanup);
    status
}

fn spawn_command(script: &str, environment: &[(String, String)]) -> Result<Child, String> {
    let mut command = shell_command(script);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        if home.is_dir() {
            command.current_dir(home);
        }
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    command.env("ET_VERSION", env!("CARGO_PKG_VERSION"));
    command
        .spawn()
        .map_err(|error| format!("could not spawn pipe command: {error}"))
}

fn shell_command(script: &str) -> Command {
    #[cfg(unix)]
    {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    }
    #[cfg(windows)]
    {
        let shell = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_owned());
        let flag = if shell.to_ascii_lowercase().contains("cmd") {
            "/c"
        } else {
            "-c"
        };
        let mut command = Command::new(shell);
        command.arg(flag).arg(script);
        command
    }
}

fn spawn_output<R>(
    reader: R,
    router: Arc<Mutex<LocalStream>>,
    cancelled: Arc<AtomicBool>,
    is_stderr: bool,
    events: mpsc::Sender<PipeEvent>,
    mut wake: LocalStream,
) -> Result<JoinHandle<()>, String>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(if is_stderr {
            "et-pipe-stderr".to_owned()
        } else {
            "et-pipe-stdout".to_owned()
        })
        .spawn(move || {
            let event = match forward_output(reader, &router, &cancelled, is_stderr) {
                Ok(()) => {
                    if is_stderr {
                        PipeEvent::StderrEof
                    } else {
                        PipeEvent::StdoutEof
                    }
                }
                Err(error) => PipeEvent::Failed(error),
            };
            let _ = events.send(event);
            signal(&mut wake);
        })
        .map_err(|error| format!("could not start pipe output worker: {error}"))
}

fn forward_output(
    mut reader: impl Read,
    router: &Mutex<LocalStream>,
    cancelled: &AtomicBool,
    is_stderr: bool,
) -> Result<(), String> {
    let mut buffer = [0u8; MAX_OUTPUT_CHUNK];
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("could not read pipe output: {error}"))?;
        if count == 0 {
            return Ok(());
        }
        write_output(router, cancelled, &buffer[..count], is_stderr)?;
    }
}

fn write_output(
    router: &Mutex<LocalStream>,
    cancelled: &AtomicBool,
    output: &[u8],
    is_stderr: bool,
) -> Result<(), String> {
    if output.is_empty() {
        return Ok(());
    }
    let message = TerminalBuffer {
        buffer: Some(output.to_vec()),
        // Absent means stdout. Encoding Some(false) would add a field upstream
        // leaves off the wire.
        is_stderr: is_stderr.then_some(true),
    };
    let packet = Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        message.encode_to_vec(),
    );
    let mut router = router
        .lock()
        .map_err(|_| "pipe router writer is unavailable".to_owned())?;
    write_local_packet_until_cancelled(&mut *router, &packet, cancelled)
        .map_err(|error| format!("could not forward pipe output: {error}"))
}

fn wait_child(slot: Arc<Mutex<Option<Child>>>, kill: &AtomicBool) -> Result<i32, String> {
    loop {
        if kill.load(Ordering::Acquire) {
            if let Ok(mut guard) = slot.lock() {
                if let Some(child) = guard.as_mut() {
                    let _ = child.kill();
                }
            }
        }
        let mut guard = slot
            .lock()
            .map_err(|_| "pipe child owner is unavailable".to_owned())?;
        let Some(child) = guard.as_mut() else {
            return Err("pipe child is not owned".to_owned());
        };
        match child.try_wait() {
            Ok(Some(status)) => return Ok(exit_code(status)),
            Ok(None) => {}
            Err(error) => return Err(format!("could not wait for pipe command: {error}")),
        }
        drop(guard);
        thread::sleep(Duration::from_millis(20));
    }
}

fn pump(
    router: &mut LocalStream,
    mut wake_reader: LocalStream,
    events: &mpsc::Receiver<PipeEvent>,
    stdin: &mut Option<ChildStdin>,
) -> Result<i32, String> {
    wake_reader
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure pipe wakeup: {error}"))?;
    let mut decoder = LocalPacketDecoder::new();
    let mut pending = Vec::new();
    let mut stdout_done = false;
    let mut child_status = None;
    loop {
        apply_events(events, &mut stdout_done, &mut child_status)?;
        if stdout_done {
            if let Some(status) = child_status {
                return Ok(status);
            }
        }
        if stdout_done {
            // Flush any input already accepted, then close stdin. A redirected
            // last command (`cat >file`) EOFs stdout while still reading.
            if pending.is_empty() {
                stdin.take();
            }
        }
        if stdout_done && stdin.is_none() {
            if let Some(status) = child_status {
                return Ok(status);
            }
        }

        let accept_input = stdin.is_some() && !stdout_done && pending.len() < MAX_PENDING_INPUT;
        let want_write = stdin.is_some() && !pending.is_empty();
        #[cfg(unix)]
        if !poll_pipe(
            router,
            &wake_reader,
            stdin.as_ref(),
            accept_input,
            want_write,
        )? {
            continue;
        }
        #[cfg(not(unix))]
        thread::sleep(Duration::from_millis(10));

        drain_wakeup(&mut wake_reader)?;
        apply_events(events, &mut stdout_done, &mut child_status)?;
        if stdout_done && pending.is_empty() {
            stdin.take();
        }
        if stdout_done {
            if let Some(status) = child_status {
                return Ok(status);
            }
        }
        if accept_input {
            if let Some(packet) = read_ready_packet(router, &mut decoder)? {
                if take_input(packet, &mut pending)? {
                    // TERMINAL_CLOSE ends the pipe session successfully.
                    // Cleanup kills the child; its signal status is not the
                    // session status.
                    return Ok(0);
                }
                decoder = LocalPacketDecoder::new();
            }
        }
        if let Some(input) = stdin.as_mut() {
            if !pending.is_empty() {
                write_pending(input, &mut pending)?;
            }
        }
    }
}

fn apply_events(
    events: &mpsc::Receiver<PipeEvent>,
    stdout_done: &mut bool,
    child_status: &mut Option<i32>,
) -> Result<bool, String> {
    let mut saw = false;
    while let Ok(event) = events.try_recv() {
        saw = true;
        match event {
            PipeEvent::StdoutEof => *stdout_done = true,
            PipeEvent::StderrEof => {}
            PipeEvent::Failed(error) => return Err(error),
            PipeEvent::Child(status) => *child_status = Some(status?),
        }
    }
    Ok(saw)
}

fn take_input(packet: Packet, pending: &mut Vec<u8>) -> Result<bool, String> {
    if local_packet_effect(&packet)? == LocalPacketEffect::Close {
        return Ok(true);
    }
    if packet.header() == TerminalPacketType::TerminalInfo as u8 {
        return Ok(false);
    }
    if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
        let message = TerminalBuffer::decode(packet.payload())
            .map_err(|_| "TERMINAL_BUFFER protobuf is malformed".to_owned())?;
        if let Some(bytes) = message.buffer {
            pending.extend(bytes);
        }
        return Ok(false);
    }
    Err("unsupported local terminal packet type".to_owned())
}

fn write_pending(stdin: &mut ChildStdin, pending: &mut Vec<u8>) -> Result<(), String> {
    while !pending.is_empty() {
        match stdin.write(pending) {
            Ok(0) => return Err("pipe stdin closed".to_owned()),
            Ok(count) => {
                pending.drain(..count);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                pending.clear();
                break;
            }
            Err(error) => return Err(format!("could not write pipe stdin: {error}")),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn poll_pipe(
    router: &LocalStream,
    wake: &LocalStream,
    stdin: Option<&ChildStdin>,
    accept_input: bool,
    stdin_writable: bool,
) -> Result<bool, String> {
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::time::Timespec;

    let mut flags = PollFlags::HUP | PollFlags::ERR;
    if accept_input {
        flags |= PollFlags::IN;
    }
    let mut descriptors = vec![
        PollFd::new(router, flags),
        PollFd::new(wake, PollFlags::IN | PollFlags::HUP),
    ];
    if stdin_writable {
        if let Some(stdin) = stdin {
            descriptors.push(PollFd::new(stdin, PollFlags::OUT));
        }
    }
    let timeout = Timespec::try_from(Duration::from_millis(100))
        .map_err(|error| format!("could not build pipe poll timeout: {error}"))?;
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::INTR => Ok(false),
        Err(error) => Err(format!("could not poll pipe session: {error}")),
    }
}

#[cfg(unix)]
fn set_nonblocking(stdin: &ChildStdin) -> Result<(), String> {
    use std::os::fd::AsFd;

    let flags = rustix::fs::fcntl_getfl(stdin.as_fd())
        .map_err(|error| format!("could not read pipe stdin flags: {error}"))?;
    rustix::fs::fcntl_setfl(stdin.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| format!("could not set pipe stdin nonblocking: {error}"))?;
    Ok(())
}

fn drain_wakeup(wake: &mut LocalStream) -> Result<(), String> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("could not drain pipe wakeup: {error}")),
        }
    }
}

fn signal(wake: &mut LocalStream) {
    let _ = wake.write_all(&[1]);
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

struct Cleanup {
    cancelled: Arc<AtomicBool>,
    kill_child: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.kill_child.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_pty;
    use et_net::local_packet::{read_local_packet, write_local_packet};

    fn collect(peer: &mut LocalStream) -> Vec<TerminalBuffer> {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut output = Vec::new();
        while let Ok(packet) = read_local_packet(peer) {
            if packet.header() != TerminalPacketType::TerminalBuffer as u8 {
                continue;
            }
            output.push(TerminalBuffer::decode(packet.payload()).unwrap());
        }
        output
    }

    fn stream(buffers: &[TerminalBuffer], stderr: bool) -> Vec<u8> {
        buffers
            .iter()
            .filter(|buffer| buffer.is_stderr.unwrap_or(false) == stderr)
            .flat_map(|buffer| buffer.buffer.clone().unwrap_or_default())
            .collect()
    }

    fn write_init(peer: &mut LocalStream, command: &str) {
        let init = et_core::proto::TermInit {
            no_pty: Some(true),
            command: Some(command.to_owned()),
            ..Default::default()
        };
        write_local_packet(
            peer,
            &Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec()),
        )
        .unwrap();
    }

    #[test]
    fn raw_pipe_separates_stdout_stderr_and_passes_binary() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        write_init(&mut peer, "printf 'OUT\\000\\001\\377'; printf 'ERR' >&2");
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = terminal_pty::run_with_startup(router, "xterm", |_| Ok(()));
            let _ = done_tx.send(result);
        });
        let buffers = collect(&mut peer);
        assert_eq!(stream(&buffers, false), b"OUT\0\x01\xff");
        assert_eq!(stream(&buffers, true), b"ERR");
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn raw_pipe_forwards_stdin_without_shell_injection() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        write_init(
            &mut peer,
            "IFS= read -r line; printf '%s' \"$line\"; printf E >&2",
        );
        let input = TerminalBuffer {
            buffer: Some(b"a\x03b\n".to_vec()),
            is_stderr: None,
        };
        write_local_packet(
            &mut peer,
            &Packet::new(
                TerminalPacketType::TerminalBuffer as u8,
                input.encode_to_vec(),
            ),
        )
        .unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = terminal_pty::run_with_startup(router, "xterm", |_| Ok(()));
            let _ = done_tx.send(result);
        });
        let buffers = collect(&mut peer);
        assert_eq!(stream(&buffers, false), b"a\x03b");
        assert_eq!(stream(&buffers, true), b"E");
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn stdout_eof_closes_stdin_when_the_child_redirects_stdout() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        // `exec` closes the session stdout pipe while cat still reads stdin
        // (dash does this for a trailing simple command; bash needs exec).
        write_init(&mut peer, "printf OUT; exec cat >/dev/null");
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = terminal_pty::run_with_startup(router, "xterm", |_| Ok(()));
            let _ = done_tx.send(result);
        });
        let buffers = collect(&mut peer);
        assert_eq!(stream(&buffers, false), b"OUT");
        assert!(stream(&buffers, true).is_empty());
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn empty_pipe_command_is_rejected() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        let init = et_core::proto::TermInit {
            no_pty: Some(true),
            command: Some(String::new()),
            ..Default::default()
        };
        write_local_packet(
            &mut peer,
            &Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec()),
        )
        .unwrap();
        let error = terminal_pty::run_with_startup(router, "xterm", |_| Ok(())).unwrap_err();
        assert!(error.contains("non-empty"), "{error}");
    }
}
