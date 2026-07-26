use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::local::LocalStream;
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use prost::Message;
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use sysinfo::{Pid as SystemPid, ProcessesToUpdate, Signal as SystemSignal, System};

const MAX_OUTPUT_CHUNK: usize = 16 * 1024;

use crate::terminal_protocol::{handle_packet, read_initial_environment, read_ready_packet};

enum WorkerEvent {
    Output(Result<(), String>),
    Child(Result<u32, String>),
}

pub fn run(mut router: LocalStream, term: &str) -> Result<i32, String> {
    let environment = read_initial_environment(&mut router)?;
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("could not open PTY: {error}"))?;
    let mut command = CommandBuilder::new(default_shell());
    command.env("TERM", term);
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("could not spawn terminal shell: {error}"))?;
    let child_pid = child.process_id();
    drop(pair.slave);
    let mut killer = child.clone_killer();
    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("could not clone PTY reader: {error}"))?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("could not open PTY writer: {error}"))?;
    let mut router_writer = router
        .try_clone()
        .map_err(|error| format!("could not clone terminal router: {error}"))?;
    let (wake_reader, wake_writer) = et_net::local::wake_pair()
        .map_err(|error| format!("could not create PTY wakeup: {error}"))?;
    let output_wake = wake_writer
        .try_clone()
        .map_err(|error| format!("could not clone PTY wakeup: {error}"))?;
    let (events_tx, events_rx) = mpsc::channel();
    let output_tx = events_tx.clone();
    let output_worker = thread::Builder::new()
        .name("et-pty-output".to_owned())
        .spawn(move || {
            let result = forward_output(&mut pty_reader, &mut router_writer);
            let _ = output_tx.send(WorkerEvent::Output(result));
            signal(output_wake);
        })
        .map_err(|error| format!("could not start PTY output worker: {error}"))?;
    let child_worker = thread::Builder::new()
        .name("et-pty-child".to_owned())
        .spawn(move || {
            let result = child
                .wait()
                .map(|status| status.exit_code())
                .map_err(|error| format!("could not wait for terminal shell: {error}"));
            let _ = events_tx.send(WorkerEvent::Child(result));
            signal(wake_writer);
        })
        .map_err(|error| format!("could not start PTY child worker: {error}"))?;

    router
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure terminal router: {error}"))?;
    wake_reader
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure PTY wakeup: {error}"))?;
    let result = pump(
        &mut router,
        wake_reader,
        pair.master.as_ref(),
        &mut pty_writer,
        &events_rx,
    );
    kill_process_group(child_pid);
    if result.is_err() {
        let _ = killer.kill();
    }
    drop(pty_writer);
    let output_join = output_worker
        .join()
        .map_err(|_| "PTY output worker panicked".to_owned());
    let child_join = child_worker
        .join()
        .map_err(|_| "PTY child worker panicked".to_owned());
    let status = result?;
    output_join?;
    child_join?;
    i32::try_from(status).map_err(|_| "terminal shell exit status is out of range".to_owned())
}

/// Shell the session hosts.
///
/// Unix follows upstream and uses `$SHELL`. Windows uses ConPTY (through
/// `portable-pty`) with `%COMSPEC%`, so an `et` session lands in a native
/// `cmd.exe`/PowerShell instead of requiring a WSL distribution. `ET_SHELL`
/// overrides the choice on both platforms.
fn default_shell() -> String {
    if let Some(shell) = std::env::var("ET_SHELL")
        .ok()
        .filter(|value| !value.trim().is_empty() && !value.contains('\0'))
    {
        return shell;
    }
    #[cfg(unix)]
    {
        std::env::var("SHELL")
            .ok()
            .filter(|value| value.starts_with('/') && !value.contains('\0'))
            .unwrap_or_else(|| "/bin/sh".to_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("COMSPEC")
            .ok()
            .filter(|value| !value.trim().is_empty() && !value.contains('\0'))
            .unwrap_or_else(|| "cmd.exe".to_owned())
    }
}

fn forward_output(reader: &mut dyn Read, router: &mut LocalStream) -> Result<(), String> {
    let mut buffer = [0u8; MAX_OUTPUT_CHUNK];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("could not read PTY output: {error}"))?;
        if count == 0 {
            return Ok(());
        }
        let message = TerminalBuffer {
            buffer: Some(buffer[..count].to_vec()),
        };
        let packet = Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            message.encode_to_vec(),
        );
        write_local_packet(router, &packet)
            .map_err(|error| format!("could not forward PTY output: {error}"))?;
    }
}

fn pump(
    router: &mut LocalStream,
    wake_reader: LocalStream,
    master: &dyn portable_pty::MasterPty,
    pty_writer: &mut dyn Write,
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<u32, String> {
    #[cfg(unix)]
    return pump_poll(router, wake_reader, master, pty_writer, events);
    #[cfg(windows)]
    return pump_windows(router, wake_reader, master, pty_writer, events);
}

#[cfg(unix)]
fn pump_poll(
    router: &mut LocalStream,
    mut wake_reader: LocalStream,
    master: &dyn portable_pty::MasterPty,
    pty_writer: &mut dyn Write,
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<u32, String> {
    let mut decoder = LocalPacketDecoder::new();
    loop {
        let (router_events, wake_events) = {
            let mut descriptors = [
                PollFd::new(&*router, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
                PollFd::new(&wake_reader, PollFlags::IN | PollFlags::HUP),
            ];
            // poll() is never restarted by SA_RESTART; retry on EINTR so a
            // stray signal cannot kill the terminal session.
            loop {
                match poll(&mut descriptors, None) {
                    Ok(_) => break,
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(error) => {
                        return Err(format!("could not poll terminal session: {error}"));
                    }
                }
            }
            (descriptors[0].revents(), descriptors[1].revents())
        };
        if wake_events.intersects(PollFlags::IN | PollFlags::HUP) {
            while let Ok(event) = events.try_recv() {
                match event {
                    WorkerEvent::Output(Err(error)) | WorkerEvent::Child(Err(error)) => {
                        return Err(error);
                    }
                    WorkerEvent::Child(Ok(status)) => return Ok(status),
                    WorkerEvent::Output(Ok(())) => {}
                }
            }
            drain_wakeup(&mut wake_reader)?;
        }
        if router_events.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Err("terminal router disconnected".to_owned());
        }
        if router_events.contains(PollFlags::IN) {
            if let Some(packet) = read_ready_packet(router, &mut decoder)? {
                handle_packet(packet, master, pty_writer)?;
                decoder = LocalPacketDecoder::new();
            }
        }
    }
}

/// Windows session pump: the router channel and the worker wake handle cannot
/// be polled together, so both are checked without blocking on the same 10ms
/// cadence upstream's `select()` timeout uses.
#[cfg(windows)]
fn pump_windows(
    router: &mut LocalStream,
    mut wake_reader: LocalStream,
    master: &dyn portable_pty::MasterPty,
    pty_writer: &mut dyn Write,
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<u32, String> {
    const IDLE: std::time::Duration = std::time::Duration::from_millis(10);
    let mut decoder = LocalPacketDecoder::new();
    loop {
        let mut progress = false;
        while let Ok(event) = events.try_recv() {
            progress = true;
            match event {
                WorkerEvent::Output(Err(error)) | WorkerEvent::Child(Err(error)) => {
                    return Err(error);
                }
                WorkerEvent::Child(Ok(status)) => return Ok(status),
                WorkerEvent::Output(Ok(())) => {}
            }
        }
        drain_wakeup(&mut wake_reader)?;
        match read_ready_packet(router, &mut decoder) {
            Ok(Some(packet)) => {
                progress = true;
                handle_packet(packet, master, pty_writer)?;
                decoder = LocalPacketDecoder::new();
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        if !progress {
            std::thread::sleep(IDLE);
        }
    }
}

fn drain_wakeup(wake_reader: &mut LocalStream) -> Result<(), String> {
    let mut buffer = [0u8; 64];
    loop {
        match wake_reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("could not drain PTY wakeup: {error}")),
        }
    }
}

fn signal(mut wake: LocalStream) {
    let _ = wake.write_all(&[1]);
}

/// Terminate the shell and everything it started.
///
/// Unix signals the child's process group and then its session, like upstream.
/// Windows has no process groups with the same semantics, so the subtree is
/// walked and terminated instead (equivalent to the job-object cleanup a native
/// Windows server needs).
#[cfg(windows)]
fn kill_process_group(process_id: Option<u32>) {
    use sysinfo::{Pid as SystemPid, ProcessRefreshKind, ProcessesToUpdate, System};
    let Some(root) = process_id else {
        return;
    };
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut children_of: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    for (pid, process) in system.processes() {
        if let Some(parent) = process.parent() {
            children_of
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }
    let mut order = Vec::new();
    let mut queue = std::collections::VecDeque::from([root]);
    while let Some(current) = queue.pop_front() {
        for child in children_of.remove(&current).unwrap_or_default() {
            order.push(child);
            queue.push_back(child);
        }
    }
    order.reverse();
    order.push(root);
    for pid in order {
        if let Some(process) = system.process(SystemPid::from_u32(pid)) {
            process.kill();
        }
    }
}

#[cfg(unix)]
fn kill_process_group(process_id: Option<u32>) {
    let Some(process_id) = process_id.and_then(|value| i32::try_from(value).ok()) else {
        return;
    };
    let _ = kill(Pid::from_raw(-process_id), Signal::SIGKILL);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let session = SystemPid::from_u32(process_id.cast_unsigned());
    for process in system
        .processes()
        .values()
        .filter(|process| process.session_id() == Some(session))
    {
        let _ = process.kill_with(SystemSignal::Kill);
    }
}
