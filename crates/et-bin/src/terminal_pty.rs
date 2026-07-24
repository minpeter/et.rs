use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::local_packet::{write_local_packet, LocalPacketDecoder};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use prost::Message;
use rustix::event::{poll, PollFd, PollFlags};

const MAX_OUTPUT_CHUNK: usize = 16 * 1024;

use crate::terminal_protocol::{handle_packet, read_initial_environment, read_ready_packet};

enum WorkerEvent {
    Output(Result<(), String>),
    Child(Result<u32, String>),
}

pub fn run(mut router: UnixStream, term: &str) -> Result<i32, String> {
    let environment = read_initial_environment(&mut router)?;
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("could not open PTY: {error}"))?;
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|value| value.starts_with('/') && !value.contains('\0'))
        .unwrap_or_else(|| "/bin/sh".to_owned());
    let mut command = CommandBuilder::new(shell);
    command.env("TERM", term);
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("could not spawn terminal shell: {error}"))?;
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
    let (wake_reader, wake_writer) =
        UnixStream::pair().map_err(|error| format!("could not create PTY wakeup: {error}"))?;
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

fn forward_output(reader: &mut dyn Read, router: &mut UnixStream) -> Result<(), String> {
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
    router: &mut UnixStream,
    mut wake_reader: UnixStream,
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
            poll(&mut descriptors, None)
                .map_err(|error| format!("could not poll terminal session: {error}"))?;
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

fn drain_wakeup(wake_reader: &mut UnixStream) -> Result<(), String> {
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

fn signal(mut wake: UnixStream) {
    let _ = wake.write_all(&[1]);
}
