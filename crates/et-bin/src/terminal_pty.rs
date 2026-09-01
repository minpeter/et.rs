use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{FlowControlMode, TerminalBuffer, TerminalPacketType};
use et_net::local::LocalStream;
use et_net::local_packet::{write_local_packet_until_cancelled, LocalPacketDecoder};
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
const FINAL_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

use crate::terminal_protocol::{handle_packet, read_initialization, read_ready_packet};

enum WorkerEvent {
    Output(Result<(), String>),
    Child(Result<u32, String>),
}

pub fn run_with_startup<F>(router: LocalStream, term: &str, started: F) -> Result<i32, String>
where
    F: FnOnce(&mut LocalStream) -> Result<(), String>,
{
    let command = CommandBuilder::new(default_shell());
    #[cfg(unix)]
    let command = {
        let mut command = command;
        command.arg("-l");
        command
    };
    run_with_command(router, term, command, Duration::ZERO, started)
}

fn run_with_command<F>(
    mut router: LocalStream,
    term: &str,
    mut command: CommandBuilder,
    output_delay: Duration,
    started: F,
) -> Result<i32, String>
where
    F: FnOnce(&mut LocalStream) -> Result<(), String>,
{
    let initialization = read_initialization(&mut router)?;
    if initialization.flow_control != FlowControlMode::None {
        // Keep terminal output in the server's bounded application queue,
        // rather than a large opaque local-socket queue (upstream PR #730).
        et_net::local::minimize_terminal_output_buffering(&router)
            .map_err(|error| format!("could not bound terminal output buffering: {error}"))?;
    }
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("could not open PTY: {error}"))?;
    command.env("TERM", term);
    for (name, value) in initialization.environment {
        command.env(name, value);
    }
    // Complete every fallible descriptor allocation before creating the shell.
    // Once the process exists, all returns below pass through one cleanup path.
    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("could not clone PTY reader: {error}"))?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("could not open PTY writer: {error}"))?;
    let router_writer =
        Arc::new(Mutex::new(router.try_clone().map_err(|error| {
            format!("could not clone terminal router: {error}")
        })?));
    let output_gate = Arc::new((Mutex::new(false), Condvar::new()));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (wake_reader, wake_writer) = et_net::local::wake_pair()
        .map_err(|error| format!("could not create PTY wakeup: {error}"))?;
    let output_wake = wake_writer
        .try_clone()
        .map_err(|error| format!("could not clone PTY wakeup: {error}"))?;

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("could not spawn terminal shell: {error}"))?;
    let child_pid = child.process_id();
    drop(pair.slave);
    let mut killer = child.clone_killer();
    let (events_tx, events_rx) = mpsc::channel();
    let output_tx = events_tx.clone();
    let worker_writer = router_writer.clone();
    let worker_gate = output_gate.clone();
    let worker_cancelled = cancelled.clone();
    let output_worker = match thread::Builder::new()
        .name("et-pty-output".to_owned())
        .spawn(move || {
            let result = wait_for_output_gate(&worker_gate, &worker_cancelled).and_then(|()| {
                if !output_delay.is_zero() {
                    thread::sleep(output_delay);
                }
                forward_output(&mut pty_reader, &worker_writer, &worker_cancelled)
            });
            let _ = output_tx.send(WorkerEvent::Output(result));
            signal(output_wake);
        }) {
        Ok(worker) => worker,
        Err(error) => {
            kill_process_group(child_pid);
            let _ = killer.kill();
            let _ = child.wait();
            return Err(format!("could not start PTY output worker: {error}"));
        }
    };
    let child_owner = Arc::new(Mutex::new(Some(child)));
    let waiter_owner = child_owner.clone();
    let child_worker = match thread::Builder::new()
        .name("et-pty-child".to_owned())
        .spawn(move || {
            let result = waiter_owner
                .lock()
                .map_err(|_| "terminal shell owner is unavailable".to_owned())
                .and_then(|mut owner| {
                    owner
                        .take()
                        .ok_or_else(|| "terminal shell is not owned".to_owned())
                })
                .and_then(|mut child| {
                    child
                        .wait()
                        .map(|status| status.exit_code())
                        .map_err(|error| format!("could not wait for terminal shell: {error}"))
                });
            let _ = events_tx.send(WorkerEvent::Child(result));
            signal(wake_writer);
        }) {
        Ok(worker) => worker,
        Err(error) => {
            kill_process_group(child_pid);
            let _ = killer.kill();
            if let Ok(mut owner) = child_owner.lock() {
                if let Some(mut child) = owner.take() {
                    let _ = child.wait();
                }
            }
            cancelled.store(true, Ordering::Release);
            let (ready, changed) = &*output_gate;
            if let Ok(mut ready) = ready.lock() {
                *ready = true;
                changed.notify_all();
            }
            drop(pty_writer);
            let _ = output_worker.join();
            return Err(format!("could not start PTY child worker: {error}"));
        }
    };

    let setup = router
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure terminal router: {error}"))
        .and_then(|()| {
            wake_reader
                .set_nonblocking(true)
                .map_err(|error| format!("could not configure PTY wakeup: {error}"))
        })
        .and_then(|()| {
            let mut writer = router_writer
                .lock()
                .map_err(|_| "terminal router writer is unavailable".to_owned())?;
            started(&mut writer)?;
            // Keep startup status ahead of every user-visible byte while
            // preserving current-main's MOTD-before-shell ordering.
            #[cfg(unix)]
            crate::terminal_motd::emit(&mut writer)?;
            Ok(())
        });
    let output_started = setup.is_ok();
    if output_started {
        let (ready, changed) = &*output_gate;
        if let Ok(mut ready) = ready.lock() {
            *ready = true;
            changed.notify_all();
        }
    }
    let result = setup.and_then(|()| {
        pump(
            &mut router,
            wake_reader,
            pair.master.as_ref(),
            &mut pty_writer,
            &events_rx,
        )
    });
    let graceful_drain = result.as_ref().is_ok_and(|completion| completion.drained);
    kill_process_group(child_pid);
    // Preserve normal output through PTY EOF. If the bounded fallback elapsed,
    // cancel and close the writer even though the shell itself exited normally.
    cancelled.store(!graceful_drain, Ordering::Release);
    let (ready, changed) = &*output_gate;
    if let Ok(mut ready) = ready.lock() {
        *ready = true;
        changed.notify_all();
    }
    if output_started && !graceful_drain {
        let _ = router.shutdown(Shutdown::Both);
        if let Ok(writer) = router_writer.lock() {
            let _ = writer.shutdown(Shutdown::Both);
        }
    }
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
    let completion = result?;
    output_join?;
    child_join?;
    i32::try_from(completion.status)
        .map_err(|_| "terminal shell exit status is out of range".to_owned())
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

fn wait_for_output_gate(
    gate: &(Mutex<bool>, Condvar),
    cancelled: &AtomicBool,
) -> Result<(), String> {
    let (ready, changed) = gate;
    let mut ready = ready
        .lock()
        .map_err(|_| "terminal output gate is unavailable".to_owned())?;
    while !*ready && !cancelled.load(Ordering::Acquire) {
        ready = changed
            .wait(ready)
            .map_err(|_| "terminal output gate is unavailable".to_owned())?;
    }
    if cancelled.load(Ordering::Acquire) {
        Err("terminal output cancelled before startup".to_owned())
    } else {
        Ok(())
    }
}

fn forward_output(
    reader: &mut dyn Read,
    router: &Mutex<LocalStream>,
    cancelled: &AtomicBool,
) -> Result<(), String> {
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
        let mut router = router
            .lock()
            .map_err(|_| "terminal router writer is unavailable".to_owned())?;
        write_local_packet_until_cancelled(&mut *router, &packet, cancelled)
            .map_err(|error| format!("could not forward PTY output: {error}"))?;
    }
}

struct PumpCompletion {
    status: u32,
    drained: bool,
}

#[derive(Default)]
struct CompletionState {
    child_status: Option<u32>,
    output_done: bool,
    drain_deadline: Option<Instant>,
}

impl CompletionState {
    fn observe(&mut self, event: WorkerEvent) -> Result<Option<PumpCompletion>, String> {
        match event {
            WorkerEvent::Output(Err(error)) | WorkerEvent::Child(Err(error)) => Err(error),
            WorkerEvent::Child(Ok(status)) => {
                self.child_status = Some(status);
                self.drain_deadline = Some(Instant::now() + FINAL_OUTPUT_DRAIN_TIMEOUT);
                Ok(self.output_done.then_some(PumpCompletion {
                    status,
                    drained: true,
                }))
            }
            WorkerEvent::Output(Ok(())) => {
                self.output_done = true;
                Ok(self.child_status.map(|status| PumpCompletion {
                    status,
                    drained: true,
                }))
            }
        }
    }

    fn expired_status(&self) -> Option<PumpCompletion> {
        self.child_status
            .filter(|_| {
                self.drain_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
            })
            .map(|status| PumpCompletion {
                status,
                drained: false,
            })
    }
}

fn pump(
    router: &mut LocalStream,
    wake_reader: LocalStream,
    master: &dyn portable_pty::MasterPty,
    pty_writer: &mut dyn Write,
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<PumpCompletion, String> {
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
) -> Result<PumpCompletion, String> {
    let mut decoder = LocalPacketDecoder::new();
    let mut completion = CompletionState::default();
    loop {
        let (router_events, wake_events) = {
            let mut descriptors = [
                PollFd::new(&*router, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
                PollFd::new(&wake_reader, PollFlags::IN | PollFlags::HUP),
            ];
            // poll() is never restarted by SA_RESTART; retry on EINTR so a
            // stray signal cannot kill the terminal session.
            loop {
                let timeout = completion.drain_deadline.map(|deadline| {
                    rustix::time::Timespec::try_from(
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .expect("two-second PTY drain timeout fits timespec")
                });
                match poll(&mut descriptors, timeout.as_ref()) {
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
                if let Some(status) = completion.observe(event)? {
                    return Ok(status);
                }
            }
            drain_wakeup(&mut wake_reader)?;
        }
        if let Some(status) = completion.expired_status() {
            return Ok(status);
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
) -> Result<PumpCompletion, String> {
    const IDLE: std::time::Duration = std::time::Duration::from_millis(10);
    let mut decoder = LocalPacketDecoder::new();
    let mut completion = CompletionState::default();
    loop {
        let mut progress = false;
        while let Ok(event) = events.try_recv() {
            progress = true;
            if let Some(status) = completion.observe(event)? {
                return Ok(status);
            }
        }
        if let Some(status) = completion.expired_status() {
            return Ok(status);
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

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::proto::TermInit;
    use et_net::local_packet::{
        read_local_packet, status_packet, write_local_packet, STARTUP_STATUS,
    };
    use prost::Message;
    use std::io::Cursor;

    #[cfg(unix)]
    #[test]
    fn normal_immediate_exit_drains_delayed_output_before_eof() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_local_packet(
            &mut peer,
            &Packet::new(
                TerminalPacketType::TerminalInit as u8,
                TermInit::default().encode_to_vec(),
            ),
        )
        .unwrap();
        let mut command = CommandBuilder::new("/bin/sh");
        command.args(["-c", "printf FINAL-OUTPUT-MARKER"]);
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = run_with_command(
                router,
                "xterm",
                command,
                Duration::from_millis(250),
                |writer| {
                    write_local_packet(writer, &status_packet(STARTUP_STATUS, Ok(())))
                        .map_err(|error| error.to_string())
                },
            );
            let _ = done_tx.send(result);
        });

        thread::sleep(Duration::from_millis(100));
        let status = read_local_packet(&mut peer).unwrap();
        assert_eq!(status.header(), STARTUP_STATUS);
        let mut output = Vec::new();
        while let Ok(packet) = read_local_packet(&mut peer) {
            assert_eq!(packet.header(), TerminalPacketType::TerminalBuffer as u8);
            output.extend(
                TerminalBuffer::decode(packet.payload())
                    .unwrap()
                    .buffer
                    .unwrap(),
            );
        }
        assert!(
            output
                .windows(b"FINAL-OUTPUT-MARKER".len())
                .any(|window| window == b"FINAL-OUTPUT-MARKER"),
            "final PTY output was lost: {:?}",
            String::from_utf8_lossy(&output)
        );
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn injected_setup_failure_reaps_shell_while_peer_stays_open_and_unread() {
        let (router, mut peer) = et_net::local::wake_pair().unwrap();
        let mut startup = router.try_clone().unwrap();
        write_local_packet(
            &mut peer,
            &Packet::new(
                TerminalPacketType::TerminalInit as u8,
                TermInit::default().encode_to_vec(),
            ),
        )
        .unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result =
                run_with_startup(router, "xterm", |_| Err("injected setup failure".into()));
            let _ = done_tx.send(result);
        });
        let error = done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("PTY cleanup waited for the non-reading peer")
            .unwrap_err();
        assert_eq!(error, "injected setup failure");
        write_local_packet(
            &mut startup,
            &status_packet(STARTUP_STATUS, Err("injected setup failure")),
        )
        .unwrap();
        assert_eq!(
            read_local_packet(&mut peer).unwrap().header(),
            STARTUP_STATUS
        );
        drop(peer);
    }

    #[test]
    fn immediate_output_waits_until_startup_status_is_fully_serialized() {
        let (writer, mut peer) = et_net::local::wake_pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let writer = Arc::new(Mutex::new(writer));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_writer = writer.clone();
        let worker_gate = gate.clone();
        let worker_cancelled = cancelled.clone();
        let worker = thread::spawn(move || {
            wait_for_output_gate(&worker_gate, &worker_cancelled)?;
            forward_output(
                &mut Cursor::new(b"immediate output"),
                &worker_writer,
                &worker_cancelled,
            )
        });

        // Model delayed main-thread scheduling: output is already readable from
        // the PTY, but the only socket writer remains owned by startup status.
        {
            let mut writer = writer.lock().unwrap();
            write_local_packet(&mut *writer, &status_packet(STARTUP_STATUS, Ok(()))).unwrap();
        }
        let (ready, changed) = &*gate;
        *ready.lock().unwrap() = true;
        changed.notify_all();

        assert_eq!(
            read_local_packet(&mut peer).unwrap().header(),
            STARTUP_STATUS
        );
        assert_eq!(
            read_local_packet(&mut peer).unwrap().header(),
            TerminalPacketType::TerminalBuffer as u8
        );
        worker.join().unwrap().unwrap();
    }
}
