use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicUsize, Ordering};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowWindow {
    pub(crate) bytes: i64,
    pub(crate) packets: i64,
}

pub(crate) fn subtract_saturating(counter: &AtomicI64, amount: i64) -> i64 {
    if amount <= 0 {
        return counter.load(Ordering::Acquire);
    }
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.saturating_sub(amount).max(0))
        })
        .unwrap_or(0)
}

pub(crate) fn commit_reservation(active: &ActiveIo, bytes: i64) {
    if bytes <= 0 || active.window.load(Ordering::Acquire) < 0 {
        return;
    }
    subtract_saturating(&active.reserved_bytes, bytes);
    subtract_saturating(&active.reserved_packets, 1);
    active.in_flight.fetch_add(bytes, Ordering::AcqRel);
    active.packets_in_flight.fetch_add(1, Ordering::AcqRel);
}

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
    /// Bytes sent on this socket but not yet confirmed delivered by the peer.
    pub(crate) in_flight: Arc<AtomicI64>,
    /// Data packets sent but not yet confirmed delivered by the peer.
    pub(crate) packets_in_flight: Arc<AtomicI64>,
    /// Bytes read or being read but not yet emitted by the worker.
    pub(crate) reserved_bytes: Arc<AtomicI64>,
    /// Reads pending emission by the worker.
    pub(crate) reserved_packets: Arc<AtomicI64>,
    /// The peer's advertised byte window, or `-1` for a legacy peer.
    pub(crate) window: Arc<AtomicI64>,
    /// The peer's advertised packet window, or `-1` for a legacy peer.
    pub(crate) packet_window: Arc<AtomicI64>,
    /// Signals the parked reader that either in-flight counter dropped.
    pub(crate) in_flight_wake: channel::Sender<()>,
    /// Unit-test synchronization: reports both in-flight counts at a wait.
    #[cfg(test)]
    pub(crate) reader_window_blocked: channel::Receiver<FlowWindow>,
    /// Unit-test synchronization: reports sent counters before a read begins.
    #[cfg(test)]
    pub(crate) reader_read_started: channel::Receiver<FlowWindow>,
    /// Bytes received but not yet confirmed drained, batched for credit.
    pub(crate) credit_to_return: i64,
    /// Packets received but not yet confirmed drained, batched for credit.
    pub(crate) packet_credit_to_return: i64,
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
    peer_window: Option<FlowWindow>,
    commands: CommandSender,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
) -> io::Result<(ActiveIo, [JoinHandle<()>; 2])> {
    spawn_io_inner(
        ReaderSetup {
            role,
            socket_id,
            peer_window,
            read_limit: READ_CHUNK,
        },
        stream,
        commands,
        cancel,
        abandoned,
    )
}

#[cfg(test)]
fn spawn_io_with_read_limit(
    socket: (Role, i32),
    stream: ForwardStream,
    peer_window: Option<FlowWindow>,
    commands: CommandSender,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
    read_limit: usize,
) -> io::Result<(ActiveIo, [JoinHandle<()>; 2])> {
    spawn_io_inner(
        ReaderSetup {
            role: socket.0,
            socket_id: socket.1,
            peer_window,
            read_limit,
        },
        stream,
        commands,
        cancel,
        abandoned,
    )
}

struct ReaderSetup {
    role: Role,
    socket_id: i32,
    peer_window: Option<FlowWindow>,
    read_limit: usize,
}

fn spawn_io_inner(
    setup: ReaderSetup,
    stream: ForwardStream,
    commands: CommandSender,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
) -> io::Result<(ActiveIo, [JoinHandle<()>; 2])> {
    let ReaderSetup {
        role,
        socket_id,
        peer_window,
        read_limit,
    } = setup;
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
    let in_flight = Arc::new(AtomicI64::new(0));
    let packets_in_flight = Arc::new(AtomicI64::new(0));
    let reserved_bytes = Arc::new(AtomicI64::new(0));
    let reserved_packets = Arc::new(AtomicI64::new(0));
    // Install the negotiated window before the reader starts. Starting with a
    // disabled sentinel and applying the window after spawn let a ready socket
    // enqueue uncharged data during the handshake.
    let window = Arc::new(AtomicI64::new(peer_window.map_or(-1, |limit| limit.bytes)));
    let packet_window = Arc::new(AtomicI64::new(
        peer_window.map_or(-1, |limit| limit.packets),
    ));
    let (in_flight_wake_tx, in_flight_wake_rx) = channel::bounded::<()>(1);
    #[cfg(test)]
    let (reader_window_blocked_tx, reader_window_blocked_rx) = channel::bounded::<FlowWindow>(2);
    #[cfg(test)]
    let (reader_read_started_tx, reader_read_started_rx) = channel::bounded::<FlowWindow>(2);
    let reader_in_flight = in_flight.clone();
    let reader_packets_in_flight = packets_in_flight.clone();
    let reader_reserved_bytes = reserved_bytes.clone();
    let reader_reserved_packets = reserved_packets.clone();
    let reader_window = window.clone();
    let reader_packet_window = packet_window.clone();
    let reader_handle = thread::spawn(move || {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            #[cfg(windows)]
            if cancellation_requested(&reader_cancel) {
                return;
            }
            let (read_len, windowed) = loop {
                let byte_window = reader_window.load(Ordering::Acquire);
                let packet_window = reader_packet_window.load(Ordering::Acquire);
                if byte_window < 0 || packet_window < 0 {
                    break (read_limit, false);
                }
                let bytes = reader_in_flight
                    .load(Ordering::Acquire)
                    .saturating_add(reader_reserved_bytes.load(Ordering::Acquire));
                let packets = reader_packets_in_flight
                    .load(Ordering::Acquire)
                    .saturating_add(reader_reserved_packets.load(Ordering::Acquire));
                let remaining_bytes = byte_window.saturating_sub(bytes);
                let remaining_packets = packet_window.saturating_sub(packets);
                if remaining_bytes <= 0 || remaining_packets <= 0 {
                    #[cfg(test)]
                    let _ = reader_window_blocked_tx.try_send(FlowWindow { bytes, packets });
                    channel::select! {
                        recv(in_flight_wake_rx) -> result => {
                            if result.is_err() {
                                return;
                            }
                        }
                        recv(reader_cancel) -> _ => return,
                    }
                    continue;
                }
                let read_len = remaining_bytes.min(read_limit as i64);
                reader_reserved_bytes.fetch_add(read_len, Ordering::AcqRel);
                reader_reserved_packets.fetch_add(1, Ordering::AcqRel);
                break (usize::try_from(read_len).unwrap_or(read_limit), true);
            };
            #[cfg(test)]
            let _ = reader_read_started_tx.try_send(FlowWindow {
                bytes: reader_reserved_bytes.load(Ordering::Acquire),
                packets: reader_reserved_packets.load(Ordering::Acquire),
            });
            let release_reservation = |bytes: i64| {
                if windowed {
                    subtract_saturating(&reader_reserved_bytes, bytes);
                    subtract_saturating(&reader_reserved_packets, 1);
                }
            };
            match reader.read(&mut buffer[..read_len]) {
                Ok(0) => {
                    release_reservation(i64::try_from(read_len).unwrap_or(i64::MAX));
                    if !cancellation_requested(&reader_cancel) {
                        let _ = reader_commands.send(Command::Closed { role, socket_id });
                    }
                    return;
                }
                Ok(count) => {
                    let actual = i64::try_from(count).unwrap_or(i64::MAX);
                    if windowed {
                        subtract_saturating(
                            &reader_reserved_bytes,
                            i64::try_from(read_len - count).unwrap_or(i64::MAX),
                        );
                    }
                    if cancellation_requested(&reader_cancel) {
                        release_reservation(actual);
                        return;
                    }
                    let (committed, commit_received) = channel::bounded(1);
                    if reader_commands
                        .send(Command::Read {
                            role,
                            socket_id,
                            buffer: buffer[..count].to_vec(),
                            committed,
                        })
                        .is_err()
                    {
                        release_reservation(actual);
                        return;
                    }
                    channel::select! {
                        recv(commit_received) -> result => {
                            if result.is_err() {
                                return;
                            }
                        }
                        recv(reader_cancel) -> _ => return,
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    release_reservation(i64::try_from(read_len).unwrap_or(i64::MAX));
                }
                #[cfg(windows)]
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    release_reservation(i64::try_from(read_len).unwrap_or(i64::MAX));
                }
                Err(error) => {
                    release_reservation(i64::try_from(read_len).unwrap_or(i64::MAX));
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
                    // The local socket absorbed these bytes; only now may the
                    // peer's window grow back.
                    let _ = writer_commands.send(Command::Drained {
                        role,
                        socket_id,
                        bytes: buffer.len(),
                    });
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
            in_flight,
            packets_in_flight,
            reserved_bytes,
            reserved_packets,
            window,
            packet_window,
            in_flight_wake: in_flight_wake_tx,
            #[cfg(test)]
            reader_window_blocked: reader_window_blocked_rx,
            #[cfg(test)]
            reader_read_started: reader_read_started_rx,
            credit_to_return: 0,
            packet_credit_to_return: 0,
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use crossbeam_channel as channel;

    use super::{
        commit_reservation, spawn_io, spawn_io_with_read_limit, stop_io, FlowWindow, ForwardStream,
        Role, WriteCommand, READ_CHUNK,
    };
    use crate::forward_worker::state::apply_delivery;
    use crate::forward_worker::{command_channel, Command};

    const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn one_byte_reads_park_at_packet_window_and_resume_after_delivery() {
        // Given: a reader forced to emit one-byte packets and a two-packet
        // window whose byte allowance is intentionally much larger.
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let limit = FlowWindow {
            bytes: i64::try_from(READ_CHUNK).unwrap(),
            packets: 2,
        };
        let (commands, command_receiver) = command_channel(8);
        let (cancel, cancel_receiver) = channel::bounded(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let (active, handles) = spawn_io_with_read_limit(
            (Role::Source, 1),
            ForwardStream::Unix(stream),
            Some(limit),
            commands.clone(),
            cancel_receiver.clone(),
            abandoned.clone(),
            1,
        )
        .unwrap();
        peer.write_all(&[1, 2, 3, 4]).unwrap();

        for _ in 0..2 {
            let Command::Read {
                socket_id: 1,
                buffer,
                committed,
                ..
            } = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap()
            else {
                panic!("first reader did not emit its one-byte packet");
            };
            commit_reservation(&active, i64::try_from(buffer.len()).unwrap());
            committed.try_send(()).unwrap();
        }
        let first = active
            .reader_window_blocked
            .recv_timeout(EVENT_TIMEOUT)
            .unwrap();

        // Then: packet credit, not the generous byte credit, is the bound;
        // returning both credits resumes that reader for exactly two more.
        assert_eq!(first.bytes, 2);
        assert_eq!(first.packets, 2);

        // A sibling socket sharing the same worker command queue still reads
        // while socket 1 is parked at its own packet window.
        let (sibling_stream, mut sibling_peer) = UnixStream::pair().unwrap();
        let (sibling, sibling_handles) = spawn_io_with_read_limit(
            (Role::Source, 2),
            ForwardStream::Unix(sibling_stream),
            Some(limit),
            commands,
            cancel_receiver,
            abandoned,
            1,
        )
        .unwrap();
        sibling_peer.write_all(&[9]).unwrap();
        let Command::Read {
            socket_id: 2,
            buffer,
            committed,
            ..
        } = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap()
        else {
            panic!("sibling reader did not progress");
        };
        assert_eq!(buffer, [9]);
        commit_reservation(&sibling, 1);
        committed.try_send(()).unwrap();

        apply_delivery(
            &active,
            FlowWindow {
                bytes: 2,
                packets: 2,
            },
        );
        for _ in 0..2 {
            let Command::Read {
                socket_id: 1,
                buffer,
                committed,
                ..
            } = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap()
            else {
                panic!("first reader did not resume");
            };
            commit_reservation(&active, i64::try_from(buffer.len()).unwrap());
            committed.try_send(()).unwrap();
        }
        let second = active
            .reader_window_blocked
            .recv_timeout(EVENT_TIMEOUT)
            .unwrap();
        assert_eq!(second.bytes, 2);
        assert_eq!(second.packets, 2);

        drop(cancel);
        stop_io(active);
        stop_io(sibling);
        for handle in handles {
            handle.join().unwrap();
        }
        for handle in sibling_handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn hostile_credit_during_pending_read_cannot_consume_unsent_reservation() {
        // Given: a windowed reader has begun a read but no byte or packet has
        // yet been handed to the forwarding worker.
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let limit = FlowWindow {
            bytes: i64::try_from(READ_CHUNK).unwrap(),
            packets: 1,
        };
        let (commands, command_receiver) = command_channel(8);
        let (cancel, cancel_receiver) = channel::bounded(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let (active, handles) = spawn_io(
            Role::Source,
            1,
            ForwardStream::Unix(stream),
            Some(limit),
            commands,
            cancel_receiver,
            abandoned,
        )
        .unwrap();
        let started = active
            .reader_read_started
            .recv_timeout(EVENT_TIMEOUT)
            .unwrap();
        assert_eq!(
            started,
            FlowWindow {
                bytes: i64::try_from(READ_CHUNK).unwrap(),
                packets: 1,
            }
        );

        // When: a hostile peer returns impossible credit while that read is
        // pending, then one byte becomes readable.
        apply_delivery(
            &active,
            FlowWindow {
                bytes: i64::MAX,
                packets: i64::MAX,
            },
        );
        peer.write_all(&[9]).unwrap();
        let command = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap();

        // Then: only the byte actually handed to the worker is outstanding;
        // neither counter underflows or grants unaccounted capacity.
        let Command::Read {
            buffer, committed, ..
        } = command
        else {
            panic!("reader did not emit its one-byte packet");
        };
        assert_eq!(buffer, [9]);
        assert_eq!(active.in_flight.load(Ordering::Acquire), 0);
        assert_eq!(active.packets_in_flight.load(Ordering::Acquire), 0);
        assert_eq!(active.reserved_bytes.load(Ordering::Acquire), 1);
        assert_eq!(active.reserved_packets.load(Ordering::Acquire), 1);

        commit_reservation(&active, 1);
        committed.try_send(()).unwrap();
        assert_eq!(active.in_flight.load(Ordering::Acquire), 1);
        assert_eq!(active.packets_in_flight.load(Ordering::Acquire), 1);
        assert_eq!(active.reserved_bytes.load(Ordering::Acquire), 0);
        assert_eq!(active.reserved_packets.load(Ordering::Acquire), 0);

        drop(cancel);
        stop_io(active);
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn same_reader_parks_at_exact_window_and_resumes_after_delivery() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let window = FlowWindow {
            bytes: 2,
            packets: 4,
        };
        let transfer = 4;
        let (commands, command_receiver) = command_channel(4);
        let (cancel, cancel_receiver) = channel::bounded(1);
        let abandoned = Arc::new(AtomicBool::new(false));
        let (active, handles) = spawn_io_with_read_limit(
            (Role::Source, 1),
            ForwardStream::Unix(stream),
            Some(window),
            commands,
            cancel_receiver,
            abandoned,
            1,
        )
        .unwrap();
        let (write_done_tx, write_done_rx) = mpsc::sync_channel(0);
        let writer = std::thread::spawn(move || {
            peer.write_all(&vec![7_u8; transfer]).unwrap();
            write_done_tx.send(()).unwrap();
        });

        for _ in 0..2 {
            let Command::Read {
                buffer, committed, ..
            } = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap()
            else {
                panic!("reader did not emit its reserved packet");
            };
            commit_reservation(&active, i64::try_from(buffer.len()).unwrap());
            committed.try_send(()).unwrap();
        }
        let first = active
            .reader_window_blocked
            .recv_timeout(EVENT_TIMEOUT)
            .unwrap();
        assert_eq!(first.bytes, window.bytes);
        assert_eq!(active.in_flight.load(Ordering::Acquire), window.bytes);

        apply_delivery(&active, first);

        for _ in 0..2 {
            let Command::Read {
                buffer, committed, ..
            } = command_receiver.recv_timeout(EVENT_TIMEOUT).unwrap()
            else {
                panic!("reader did not resume its reserved packet");
            };
            commit_reservation(&active, i64::try_from(buffer.len()).unwrap());
            committed.try_send(()).unwrap();
        }
        let second = active
            .reader_window_blocked
            .recv_timeout(EVENT_TIMEOUT)
            .unwrap();
        assert_eq!(second.bytes, window.bytes);
        assert_eq!(active.in_flight.load(Ordering::Acquire), window.bytes);
        write_done_rx.recv_timeout(EVENT_TIMEOUT).unwrap();

        drop(cancel);
        stop_io(active);
        for handle in handles {
            handle.join().unwrap();
        }
        writer.join().unwrap();
    }

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
            None,
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
