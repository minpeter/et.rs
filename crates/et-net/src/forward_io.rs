use std::io::{self, Read, Write};
#[cfg(windows)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};

use crate::forward_endpoint::{Endpoint, ForwardListener, ForwardStream};
use et_core::proto::SocketEndpoint;

use super::forward_worker::{Command, CommandSender, Role};

const READ_CHUNK: usize = 16 * 1024;

pub(crate) struct BoundSource {
    pub(crate) listener: ForwardListener,
    pub(crate) destination: SocketEndpoint,
}

pub(crate) struct ActiveIo {
    pub(crate) writer: mpsc::SyncSender<WriteCommand>,
    pub(crate) control: ForwardStream,
}

pub(crate) enum WriteCommand {
    Data(Vec<u8>),
    Stop,
}

/// Signal used to stop listener threads.
///
/// On Unix this is the read end of a socket pair so the accept loop can block
/// in `poll(2)` exactly like upstream's `select()`. Windows cannot poll a
/// socket pair created this way, so the loop uses a non-blocking accept with
/// the same 10ms cadence upstream's `select()` timeout provides, driven by a
/// shared flag.
#[cfg(unix)]
pub(crate) type ListenerStop = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub(crate) type ListenerStop = Arc<AtomicBool>;

/// Accept cadence for the Windows listener loop, matching the 10ms `select()`
/// timeout upstream uses for its accept/update loop.
#[cfg(windows)]
const ACCEPT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

pub(crate) fn spawn_listener(
    source: BoundSource,
    commands: CommandSender,
    stop: ListenerStop,
    next_client_fd: Arc<AtomicI32>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let BoundSource {
            listener,
            destination,
        } = source;
        loop {
            #[cfg(unix)]
            {
                let mut descriptors = [
                    PollFd::new(&listener, PollFlags::IN),
                    PollFd::new(&stop, PollFlags::IN),
                ];
                // poll() is never restarted by SA_RESTART; retry on EINTR so
                // a stray signal cannot silently stop the forward acceptor.
                match poll(&mut descriptors, None) {
                    Ok(_) => {}
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(_) => return,
                }
                if descriptors[1]
                    .revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
                {
                    return;
                }
                if !descriptors[0].revents().contains(PollFlags::IN) {
                    continue;
                }
            }
            #[cfg(windows)]
            {
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
            let mut accepted_any = false;
            loop {
                match listener.accept() {
                    Ok(stream) => {
                        accepted_any = true;
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
            #[cfg(windows)]
            if !accepted_any {
                thread::sleep(ACCEPT_INTERVAL);
            }
            #[cfg(unix)]
            let _ = accepted_any;
        }
    })
}

pub(crate) fn spawn_connector(
    client_fd: i32,
    socket_id: i32,
    destination: Endpoint,
    commands: CommandSender,
    session_user: Option<(u32, u32)>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let result = destination.connect_with_user(session_user);
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
    commands: CommandSender,
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
                WriteCommand::Stop => {
                    // Perform the final shutdown here so every Data command
                    // queued before Stop is flushed to the socket first.
                    writer.shutdown();
                    return;
                }
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
    // Queue Stop before touching the socket: the writer thread drains any
    // pending Data commands in FIFO order and then closes the socket. Only
    // shut down the read half here to wake the reader thread; a full
    // shutdown would discard writes that are still queued.
    let _ = io.writer.send(WriteCommand::Stop);
    io.control.shutdown_read();
}
