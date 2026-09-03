use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel as channel;

#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};

use crate::forward_endpoint::{Endpoint, ForwardListener, ForwardStream};
use et_core::proto::SocketEndpoint;

use super::forward_worker::{Command, CommandSender, Role};

const READ_CHUNK: usize = 16 * 1024;
#[cfg(windows)]
const IO_CANCEL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) struct BoundSource {
    pub(crate) listener: ForwardListener,
    pub(crate) destination: SocketEndpoint,
}

pub(crate) struct ActiveIo {
    pub(crate) writer: channel::Sender<WriteCommand>,
    pub(crate) control: ForwardStream,
    pub(crate) cancel: channel::Receiver<()>,
    pub(crate) pending_bytes: Arc<AtomicUsize>,
    pub(crate) abandoned: Arc<AtomicBool>,
    pub(crate) read_closed: bool,
    pub(crate) write_closed: bool,
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
    cancel: channel::Receiver<()>,
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
                        if client_fd <= 0 {
                            return;
                        }
                        if cancellation_requested(&cancel)
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
    cancel: channel::Receiver<()>,
    session_user: Option<(u32, u32)>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let result = destination.connect_with_user(session_user);
        if !cancellation_requested(&cancel) {
            let _ = commands.send(Command::Connected {
                client_fd,
                socket_id,
                result,
            });
        }
    })
}

pub(crate) fn spawn_io(
    role: Role,
    socket_id: i32,
    stream: ForwardStream,
    commands: CommandSender,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
) -> io::Result<(ActiveIo, [JoinHandle<()>; 2])> {
    #[cfg(windows)]
    {
        // Winsock does not reliably interrupt an in-flight synchronous I/O
        // call when another handle for the same socket is shut down. Finite
        // deadlines make both sibling threads observe hard cancellation.
        stream.set_read_timeout(Some(IO_CANCEL_INTERVAL))?;
        stream.set_write_timeout(Some(IO_CANCEL_INTERVAL))?;
    }
    let mut reader = stream.try_clone()?;
    let control = stream.try_clone()?;
    let (writer_tx, writer_rx) = channel::bounded(64);
    let reader_commands = commands.clone();
    let reader_cancel = cancel.clone();
    let reader_handle = thread::spawn(move || {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            #[cfg(windows)]
            if cancellation_requested(&reader_cancel) {
                return;
            }
            match reader.read(&mut buffer) {
                Ok(0) => {
                    if !cancellation_requested(&reader_cancel) {
                        let _ = reader_commands.send(Command::Closed { role, socket_id });
                    }
                    return;
                }
                Ok(count) => {
                    if cancellation_requested(&reader_cancel)
                        || reader_commands
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
                #[cfg(windows)]
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    if !cancellation_requested(&reader_cancel) {
                        let _ = reader_commands.send(Command::IoFailed {
                            role,
                            socket_id,
                            error,
                        });
                    }
                    return;
                }
            }
        }
    });
    let writer_commands = commands;
    let writer_cancel = cancel.clone();
    let pending_bytes = Arc::new(AtomicUsize::new(0));
    let writer_pending_bytes = pending_bytes.clone();
    let writer_abandoned = abandoned.clone();
    let writer_handle = thread::spawn(move || {
        let mut writer = stream;
        loop {
            let command = channel::select! {
                recv(writer_rx) -> command => match command {
                    Ok(command) => command,
                    Err(_) => break,
                },
                recv(writer_cancel) -> _ => break,
            };
            match command {
                WriteCommand::Data(buffer) => {
                    #[cfg(windows)]
                    let result = write_all_cancellable(&mut writer, &buffer, &writer_cancel);
                    #[cfg(not(windows))]
                    let result = writer.write_all(&buffer).map(|()| true);
                    let delivered = match result {
                        Ok(delivered) => delivered,
                        Err(error) => {
                            if !cancellation_requested(&writer_cancel) {
                                let _ = writer_commands.send(Command::IoFailed {
                                    role,
                                    socket_id,
                                    error,
                                });
                            }
                            break;
                        }
                    };
                    if !delivered {
                        break;
                    }
                    writer_pending_bytes.fetch_sub(buffer.len(), Ordering::AcqRel);
                }
                WriteCommand::Stop => {
                    // Perform the final shutdown here so every Data command
                    // queued before Stop is flushed to the socket first.
                    shutdown_write(&writer);
                    break;
                }
            }
        }
        if writer_pending_bytes.load(Ordering::Acquire) != 0 {
            writer_abandoned.store(true, Ordering::Release);
        }
    });
    Ok((
        ActiveIo {
            writer: writer_tx,
            control,
            cancel,
            pending_bytes,
            abandoned,
            read_closed: false,
            write_closed: false,
        },
        [reader_handle, writer_handle],
    ))
}

fn shutdown_write(stream: &ForwardStream) {
    let _ = match stream {
        ForwardStream::Tcp(stream) => stream.shutdown(Shutdown::Write),
        #[cfg(unix)]
        ForwardStream::Unix(stream) => stream.shutdown(Shutdown::Write),
    };
}

#[cfg(windows)]
fn write_all_cancellable(
    writer: &mut ForwardStream,
    mut remaining: &[u8],
    cancel: &channel::Receiver<()>,
) -> io::Result<bool> {
    while !remaining.is_empty() {
        if cancellation_requested(cancel) {
            return Ok(false);
        }
        match writer.write(remaining) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => remaining = &remaining[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn cancellation_requested(cancel: &channel::Receiver<()>) -> bool {
    !matches!(cancel.try_recv(), Err(channel::TryRecvError::Empty))
}

pub(crate) fn close_write(io: &mut ActiveIo) -> bool {
    if io.write_closed {
        return true;
    }
    let admitted = channel::select! {
        send(io.writer, WriteCommand::Stop) -> result => result.is_ok(),
        recv(io.cancel) -> _ => false,
    };
    if admitted {
        io.write_closed = true;
    }
    admitted
}

pub(crate) fn stop_io(mut io: ActiveIo) {
    // Keep the control socket alive while Stop waits for queue capacity so
    // hard cancellation can still abort an in-flight write and release it.
    if close_write(&mut io) {
        io.control.shutdown_read();
    } else {
        if io.pending_bytes.load(Ordering::Acquire) != 0 {
            io.abandoned.store(true, Ordering::Release);
        }
        io.control.shutdown();
    }
}

pub(crate) fn abort_io(io: ActiveIo) {
    // Hard cancellation abandons queued output and closes both socket halves
    // before joining, waking a writer blocked inside write_all.
    io.control.shutdown();
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{self, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use crossbeam_channel as channel;

    use super::{spawn_io, stop_io, ForwardStream, Role, WriteCommand};
    use crate::forward_worker::command_channel;

    const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn stop_io_cancellation_bypasses_a_full_writer_queue() {
        // Given: the writer owns one command in a blocked socket write and its
        // bounded queue is full. Admission of the final command proves this
        // state without scheduler timing assumptions.
        let (stream, peer) = UnixStream::pair().unwrap();
        socket2::SockRef::from(&stream)
            .set_send_buffer_size(2 * 1024)
            .unwrap();
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(2 * 1024)
            .unwrap();
        let mut saturator = stream.try_clone().unwrap();
        saturator.set_nonblocking(true).unwrap();
        loop {
            match saturator.write(&[0u8; 16 * 1024]) {
                Ok(0) => panic!("forward socket closed before reaching backpressure"),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not saturate forward socket: {error}"),
            }
        }
        saturator.set_nonblocking(false).unwrap();
        let control = stream.try_clone().unwrap();
        let (commands, _command_receiver) = command_channel(1);
        let (cancel, cancel_receiver) = channel::bounded(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let (active, handles) = spawn_io(
            Role::Destination,
            1,
            ForwardStream::Unix(stream),
            commands,
            cancel_receiver,
            abandoned,
        )
        .unwrap();
        for _ in 0..64 {
            active.writer.send(WriteCommand::Data(vec![1])).unwrap();
        }
        let writer = active.writer.clone();
        let (admitted_tx, admitted_rx) = mpsc::sync_channel(0);
        let admission = std::thread::spawn(move || {
            writer.send(WriteCommand::Data(vec![1])).unwrap();
            admitted_tx.send(()).unwrap();
        });
        admitted_rx.recv_timeout(EVENT_TIMEOUT).unwrap();
        admission.join().unwrap();

        // When: hard cancellation races graceful Stop admission.
        let (done_tx, done_rx) = mpsc::sync_channel(0);
        let stopping = std::thread::spawn(move || {
            stop_io(active);
            done_tx.send(()).unwrap();
        });
        drop(cancel);
        let completed_before_abort = done_rx.recv_timeout(EVENT_TIMEOUT).is_ok();

        // Then: cancellation itself must complete removal; the retained clone
        // is used only to guarantee cleanup after observing a regression.
        let _ = control.shutdown(std::net::Shutdown::Both);
        let _ = done_rx.recv_timeout(EVENT_TIMEOUT);
        stopping.join().unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
        drop(peer);
        assert!(
            completed_before_abort,
            "stop_io remained blocked behind the full writer queue after cancellation"
        );
    }
}
