use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use rustix::event::{poll, PollFd, PollFlags};

use crate::forward_endpoint::{Endpoint, ForwardListener, ForwardStream};

use super::forward_worker::{Command, Role};

const READ_CHUNK: usize = 16 * 1024;

pub(crate) struct BoundSource {
    pub(crate) listener: ForwardListener,
    pub(crate) destination: Endpoint,
}

pub(crate) struct ActiveIo {
    pub(crate) writer: mpsc::SyncSender<WriteCommand>,
    pub(crate) control: ForwardStream,
}

pub(crate) enum WriteCommand {
    Data(Vec<u8>),
    Stop,
}

pub(crate) fn spawn_listener(
    source: BoundSource,
    commands: mpsc::SyncSender<Command>,
    stop: UnixStream,
    next_client_fd: Arc<AtomicI32>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let BoundSource {
            listener,
            destination,
        } = source;
        loop {
            let mut descriptors = [
                PollFd::new(&listener, PollFlags::IN),
                PollFd::new(&stop, PollFlags::IN),
            ];
            if poll(&mut descriptors, None).is_err() {
                return;
            }
            if descriptors[1]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            {
                return;
            }
            if descriptors[0].revents().contains(PollFlags::IN) {
                loop {
                    match listener.accept() {
                        Ok(stream) => {
                            let client_fd = next_client_fd.fetch_add(1, Ordering::Relaxed);
                            if client_fd <= 0
                                || commands
                                    .send(Command::Accepted {
                                        client_fd,
                                        destination: destination.clone(),
                                        stream,
                                    })
                                    .is_err()
                            {
                                return;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => return,
                    }
                }
            }
        }
    })
}

pub(crate) fn spawn_connector(
    client_fd: i32,
    socket_id: i32,
    destination: Endpoint,
    commands: mpsc::SyncSender<Command>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let result = destination.connect();
        let _ = commands.send(Command::Connected {
            client_fd,
            socket_id,
            result,
        });
    })
}

pub(crate) fn spawn_io(
    role: Role,
    socket_id: i32,
    stream: ForwardStream,
    commands: mpsc::SyncSender<Command>,
) -> io::Result<(ActiveIo, [JoinHandle<()>; 2])> {
    let mut reader = stream.try_clone()?;
    let control = stream.try_clone()?;
    let (writer_tx, writer_rx) = mpsc::sync_channel(64);
    let reader_commands = commands.clone();
    let reader_handle = thread::spawn(move || {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = reader_commands.send(Command::Closed { role, socket_id });
                    return;
                }
                Ok(count) => {
                    if reader_commands
                        .send(Command::Read {
                            role,
                            socket_id,
                            buffer: buffer[..count].to_vec(),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = reader_commands.send(Command::IoFailed {
                        role,
                        socket_id,
                        error,
                    });
                    return;
                }
            }
        }
    });
    let writer_commands = commands;
    let writer_handle = thread::spawn(move || {
        let mut writer = stream;
        while let Ok(command) = writer_rx.recv() {
            match command {
                WriteCommand::Data(buffer) => {
                    if let Err(error) = writer.write_all(&buffer) {
                        let _ = writer_commands.send(Command::IoFailed {
                            role,
                            socket_id,
                            error,
                        });
                        return;
                    }
                }
                WriteCommand::Stop => return,
            }
        }
    });
    Ok((
        ActiveIo {
            writer: writer_tx,
            control,
        },
        [reader_handle, writer_handle],
    ))
}

pub(crate) fn stop_io(io: ActiveIo) {
    io.control.shutdown();
    let _ = io.writer.send(WriteCommand::Stop);
}
