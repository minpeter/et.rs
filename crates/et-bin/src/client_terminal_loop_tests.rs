#![cfg(unix)]

use super::*;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use crate::client_terminal::send_buffer;
use et_core::proto::TerminalBuffer;
use prost::Message;

thread_local! {
    static FORWARD_WRITE_STARTED: std::cell::RefCell<Option<mpsc::SyncSender<()>>> = const {
        std::cell::RefCell::new(None)
    };
}

thread_local! {
    static POLL_RETURNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn note_poll_return() {
    POLL_RETURNS.with(|count| count.set(count.get() + 1));
}

pub(super) fn note_forward_write(packet: &et_core::packet::Packet) {
    if packet.payload().len() < 16 * 1024 {
        return;
    }
    FORWARD_WRITE_STARTED.with(|observer| {
        if let Some(observer) = observer.borrow_mut().take() {
            observer.send(()).unwrap();
        }
    });
}

#[test]
fn pump_services_inbound_while_forwarding_peer_refuses_to_read() {
    use et_core::proto::{PortForwardDestinationRequest, SocketEndpoint};
    use std::net::Shutdown;

    // Given: real TCP with a tiny negotiated receive window and a real
    // forwarder producing more responses than that window can absorb.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let control = client.try_clone().unwrap();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection.shrink_transport_window_for_tests(4096).unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    forwarder
        .receive(et_core::packet::Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(42),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let (mut application, _) = destination.accept().unwrap();
    application
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    application.write_all(&vec![3; 1024 * 1024]).unwrap();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (mut wake, _wake_writer) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        FORWARD_WRITE_STARTED.with(|observer| *observer.borrow_mut() = Some(started_tx));
        let mut recoveries = 0;
        let result = pump(
            &mut connection,
            &mut wake,
            PumpOptions {
                read_stdin: false,
                keepalive_seconds: 30,
                flow_control: et_cli::client::FlowControlMode::None,
                terminal_enabled: false,
                auto_cursor_report: false,
                binary_stdio: false,
                terminal_modes: &mut TerminalModeState::default(),
                hangup: &crate::client_hangup::HangupClose::disabled(),
                remote_exit: &crate::client_terminal::RemoteExit::new(false),
                stdio_forward: false,
            },
            &mut forwarder,
            |_| {
                recoveries += 1;
                Ok(ReconnectOutcome::SessionEnded)
            },
        );
        done_tx
            .send((result, recoveries, connection.reader_sequence()))
            .unwrap();
    });

    // When: after the pump begins draining forwarding output, an encrypted
    // inbound packet requires dispatch. The peer still never reads output.
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    peer.write_packet(255, b"dispatch-before-output-drain")
        .unwrap();
    let observed = done_rx.recv_timeout(Duration::from_secs(1));
    // Dropping the completed pump's pending frame may already have shut
    // down this socket (Darwin reports ENOTCONN on a second shutdown).
    let _ = control.shutdown(Shutdown::Both);
    worker.join().unwrap();

    // Then: dispatch ended the pump, not a write timeout/reconnect. No API
    // contract requires ordinary synchronous Connection writes to be async.
    assert!(
        matches!(observed, Ok((Err(_), 0, 1))),
        "pump starved inbound dispatch behind forwarding output: {observed:?}"
    );
}

#[test]
fn saturated_forwarding_upload_yields_to_terminal_input() {
    use et_core::proto::{PortForwardDestinationRequest, SocketEndpoint};

    // Given: a tiny transport window, a peer that keeps reading, and a
    // forwarded application whose upload never runs dry.
    let (client, server) = tcp_streams();
    let control = client.try_clone().unwrap();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection.shrink_transport_window_for_tests(4096).unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    forwarder
        .receive(et_core::packet::Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(42),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let (mut application, _) = destination.accept().unwrap();
    let feeder = thread::spawn(move || {
        let chunk = vec![3; 64 * 1024];
        while application.write_all(&chunk).is_ok() {}
    });
    let (input, mut keys) = io::pipe().unwrap();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        FORWARD_WRITE_STARTED.with(|observer| *observer.borrow_mut() = Some(started_tx));
        let (mut wake, _wake_writer) = UnixStream::pair().unwrap();
        wake.set_nonblocking(true).unwrap();
        let result = pump_with_stdin(
            &mut connection,
            &mut wake,
            PumpOptions {
                read_stdin: true,
                keepalive_seconds: 30,
                flow_control: et_cli::client::FlowControlMode::None,
                terminal_enabled: false,
                auto_cursor_report: false,
                binary_stdio: true,
                terminal_modes: &mut TerminalModeState::default(),
                hangup: &crate::client_hangup::HangupClose::disabled(),
                remote_exit: &crate::client_terminal::RemoteExit::new(false),
                stdio_forward: false,
            },
            &mut forwarder,
            |_| Ok(ReconnectOutcome::SessionEnded),
            input,
        );
        drop(forwarder);
        done_tx.send(result.is_err()).unwrap();
    });

    // When: a keystroke arrives after the upload has claimed the transport.
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    keys.write_all(b"k").unwrap();
    let mut forwarded_before_input = 0usize;
    let keystroke = loop {
        let packet = peer.read_packet().unwrap();
        if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
            break Some(packet);
        }
        forwarded_before_input += packet.payload().len();
        if forwarded_before_input > 8 * 1024 * 1024 {
            break None;
        }
    };
    peer.write_packet(255, b"end-pump").unwrap();
    let ended = done_rx.recv_timeout(Duration::from_secs(5));
    let _ = control.shutdown(std::net::Shutdown::Both);
    worker.join().unwrap();
    feeder.join().unwrap();

    // Then: the keystroke overtakes the endless upload within a few frames.
    let keystroke = keystroke.unwrap_or_else(|| {
        panic!("keystroke starved behind {forwarded_before_input} forwarded bytes")
    });
    let buffer = TerminalBuffer::decode(keystroke.payload()).unwrap();
    assert_eq!(buffer.buffer.as_deref(), Some(b"k".as_slice()));
    assert!(
        forwarded_before_input < 1024 * 1024,
        "keystroke waited behind {forwarded_before_input} forwarded bytes"
    );
    assert!(ended.unwrap(), "pump did not end on the unknown packet");
}

#[test]
fn pending_frame_does_not_spin_on_hung_up_resize_wake() {
    // Given: a frame the peer never reads and a resize wake whose writer
    // is gone, so poll(2) reports HUP for it on every call.
    let (client, _server) = tcp_streams();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection
        .start_write_packet_owned(7, &vec![73; 1024 * 1024])
        .unwrap();
    assert!(connection.write_pending());
    let (mut wake, writer) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    drop(writer);
    POLL_RETURNS.with(|count| count.set(0));

    // When: the pump waits out the live write deadline.
    pump_with_stdin(
        &mut connection,
        &mut wake,
        PumpOptions {
            read_stdin: false,
            keepalive_seconds: 30,
            flow_control: et_cli::client::FlowControlMode::None,
            terminal_enabled: false,
            auto_cursor_report: false,
            binary_stdio: true,
            terminal_modes: &mut TerminalModeState::default(),
            hangup: &crate::client_hangup::HangupClose::disabled(),
            remote_exit: &crate::client_terminal::RemoteExit::new(false),
            stdio_forward: false,
        },
        &mut Forwarder::start(Vec::new()).unwrap(),
        |_| Ok(ReconnectOutcome::SessionEnded),
        io::stdin(),
    )
    .unwrap();

    // Then: poll slept on its caps instead of returning for the dead fd.
    let returns = POLL_RETURNS.with(std::cell::Cell::get);
    assert!(returns < 200, "pump spun {returns} polls during one frame");
}

#[test]
fn full_forwarding_backlog_stops_polling_network_readability() {
    let flags = network_poll_flags(false, true);

    assert!(!flags.contains(PollFlags::IN));
    assert!(flags.contains(PollFlags::HUP | PollFlags::ERR));
}

#[test]
fn close_on_hangup_sends_terminal_close_and_exits_the_loop() {
    use et_core::crypto::KEY_LEN;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::time::Duration;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let stream = client.join().unwrap();
    server_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server = thread::spawn(move || {
        let mut receiver =
            et_net::connection::Connection::new_server(server_stream, &[7u8; KEY_LEN]);
        let packet = receiver.read_packet().unwrap();
        assert_eq!(
            packet.header(),
            et_core::proto::TerminalPacketType::TerminalClose as u8
        );
        assert!(packet.payload().is_empty());
    });
    let mut connection = et_net::connection::Connection::new_client(stream, &[7u8; KEY_LEN]);
    let (mut wake, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    let mut modes = TerminalModeState::default();
    let hangup = crate::client_hangup::HangupClose::disabled();
    hangup.request();
    pump(
        &mut connection,
        &mut wake,
        PumpOptions {
            read_stdin: false,
            keepalive_seconds: 5,
            flow_control: et_cli::client::FlowControlMode::None,
            terminal_enabled: false,
            auto_cursor_report: false,
            binary_stdio: false,
            terminal_modes: &mut modes,
            hangup: &hangup,
            remote_exit: &crate::client_terminal::RemoteExit::new(false),
            stdio_forward: false,
        },
        &mut et_net::forward::Forwarder::start(Vec::new()).unwrap(),
        |_| panic!("hangup close must not reconnect"),
    )
    .unwrap();
    assert!(hangup.completed());
    server.join().unwrap();
}

#[test]
fn available_forwarding_backlog_keeps_polling_network_readability() {
    let flags = network_poll_flags(false, false);

    assert!(flags.contains(PollFlags::IN));
}

fn tcp_streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    socket2::SockRef::from(&client)
        .set_send_buffer_size(4096)
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let server = listener.accept().unwrap().0;
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    (client, server)
}

// Fill the live socket before creating a Connection so even a tiny close
// record cannot complete in its first send. The receiver strips this prefix.
fn fill_transport(stream: &TcpStream) -> usize {
    // MSG_DONTWAIT alone does not prevent a Darwin send-buffer-space wait.
    // This is fixture setup, before any Connection/other clone can use it.
    stream.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut count = 0;
    loop {
        assert!(Instant::now() < deadline, "transport never saturated");
        match rustix::net::send(stream, &[0; 4096], rustix::net::SendFlags::DONTWAIT) {
            Ok(n) => count += n,
            Err(rustix::io::Errno::AGAIN) => {
                // A first EAGAIN can precede ACKs for bytes still moving to
                // the peer's receive queue. Fill that newly freed capacity
                // too; only an unread, settled window proves backpressure.
                let mut descriptors = [PollFd::new(stream, PollFlags::OUT)];
                let timeout = Timespec::try_from(Duration::from_millis(250)).unwrap();
                if poll(&mut descriptors, Some(&timeout)).unwrap() != 0 {
                    continue;
                }
                // Poll's low-water mark can hide room for a tiny close.
                // Prove that even one more byte cannot be accepted.
                match rustix::net::send(stream, &[0], rustix::net::SendFlags::DONTWAIT) {
                    Ok(n) => {
                        count += n;
                        continue;
                    }
                    Err(rustix::io::Errno::AGAIN) => {}
                    Err(error) => panic!("probing saturated transport: {error}"),
                }
                stream.set_nonblocking(false).unwrap();
                return count;
            }
            Err(error) => panic!("filling transport: {error}"),
        }
    }
}

fn run_exit_pump<R, F>(connection: &mut Connection, stdio_forward: bool, input: R, reconnect: F)
where
    R: Read + std::os::fd::AsFd,
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let (mut wake, _writer) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    pump_with_stdin(
        connection,
        &mut wake,
        PumpOptions {
            read_stdin: !stdio_forward,
            keepalive_seconds: 30,
            flow_control: et_cli::client::FlowControlMode::None,
            terminal_enabled: false,
            auto_cursor_report: false,
            binary_stdio: true,
            terminal_modes: &mut TerminalModeState::default(),
            hangup: &crate::client_hangup::HangupClose::disabled(),
            remote_exit: &crate::client_terminal::RemoteExit::new(true),
            stdio_forward,
        },
        &mut Forwarder::start(Vec::new()).unwrap(),
        reconnect,
        input,
    )
    .unwrap();
}

#[test]
fn stdio_exit_finishes_close_under_transport_backpressure() {
    let (client, mut server) = tcp_streams();
    let prefix = fill_transport(&client);
    let control = client.try_clone().unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut connection = Connection::new_client(client, &[19; 32]);
        run_exit_pump(&mut connection, true, io::stdin(), |_| {
            panic!("healthy transport must not recover")
        });
        done_tx.send(connection.write_pending()).unwrap();
    });
    let early = done_rx.recv_timeout(Duration::from_millis(100));
    server.read_exact(&mut vec![0; prefix]).unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    let close = peer.read_packet();
    if close.is_err() {
        let _ = control.shutdown(std::net::Shutdown::Both);
    }
    worker.join().unwrap();
    assert!(early.is_err(), "pump returned before close could be sent");
    assert!(!done_rx.recv_timeout(Duration::from_secs(3)).unwrap());
    let close = close.unwrap();
    assert_eq!(close.header(), TerminalPacketType::TerminalClose as u8);
    assert!(close.payload().is_empty());
    assert_eq!(peer.reader_sequence(), 1);
}

#[test]
fn stdio_exit_recovers_failed_pending_frame_before_close() {
    let (client, server) = tcp_streams();
    let mut connection = Connection::new_client(client, &[19; 32]);
    let mut peer = Connection::new_server(server, &[19; 32]);
    let payload = vec![73; 1024 * 1024];
    connection.start_write_packet_owned(7, &payload).unwrap();
    assert!(connection.write_pending());
    connection
        .try_clone_stream()
        .unwrap()
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    peer.disconnect();
    let (replacement, server) = tcp_streams();
    let receiver = thread::spawn(move || {
        peer.recover(server).unwrap();
        peer.set_io_timeout(Some(Duration::from_secs(3))).unwrap();
        (peer.read_packet().unwrap(), peer.read_packet().unwrap())
    });
    let mut replacement = Some(replacement);
    let mut recoveries = 0;
    run_exit_pump(&mut connection, true, io::stdin(), |connection| {
        recoveries += 1;
        connection.recover(replacement.take().unwrap()).unwrap();
        Ok(ReconnectOutcome::Recovered)
    });
    assert_eq!(recoveries, 1);
    assert!(!connection.write_pending());
    assert_eq!(connection.writer_sequence(), 2);
    let (frame, close) = receiver.join().unwrap();
    assert_eq!(frame, et_core::packet::Packet::new(7, payload));
    assert_eq!(close.header(), TerminalPacketType::TerminalClose as u8);
    assert!(close.payload().is_empty());
}

#[test]
fn stdio_exit_replays_close_when_probe_detects_disconnection() {
    let (client, server) = tcp_streams();
    let mut connection = Connection::new_client(client, &[19; 32]);
    let mut peer = Connection::new_server(server, &[19; 32]);
    connection
        .try_clone_stream()
        .unwrap()
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    // No pending frame: the close itself is the first write to discover EOF.
    assert!(connection.connected());
    assert!(!connection.write_pending());
    peer.disconnect();
    let (replacement, server) = tcp_streams();
    let receiver = thread::spawn(move || {
        peer.recover(server).unwrap();
        peer.set_io_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.read_packet().unwrap()
    });
    let mut replacement = Some(replacement);
    let mut recoveries = 0;
    run_exit_pump(&mut connection, true, io::stdin(), |connection| {
        recoveries += 1;
        assert_eq!(connection.writer_sequence(), 1);
        connection.recover(replacement.take().unwrap()).unwrap();
        Ok(ReconnectOutcome::Recovered)
    });
    assert_eq!(recoveries, 1);
    assert_eq!(connection.writer_sequence(), 1);
    let close = receiver.join().unwrap();
    assert_eq!(close.header(), TerminalPacketType::TerminalClose as u8);
    assert!(close.payload().is_empty());
}

#[test]
fn stdio_exit_does_not_enqueue_close_after_recovery_ends_session() {
    let (client, _server) = tcp_streams();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection
        .start_write_packet_owned(7, &vec![73; 1024 * 1024])
        .unwrap();
    assert!(connection.write_pending());
    connection
        .try_clone_stream()
        .unwrap()
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    let mut recoveries = 0;
    run_exit_pump(&mut connection, true, io::stdin(), |_| {
        recoveries += 1;
        Ok(ReconnectOutcome::SessionEnded)
    });
    assert_eq!(recoveries, 1);
    assert_eq!(connection.writer_sequence(), 1);
    assert!(!connection.write_pending());
}

struct ChunkedPipe {
    pipe: io::PipeReader,
    read: mpsc::Sender<()>,
}

impl std::os::fd::AsFd for ChunkedPipe {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.pipe.as_fd()
    }
}

impl Read for ChunkedPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Force multiple reads even on hosts with a small pipe capacity.
        let limit = buffer.len().min(1024);
        let count = self.pipe.read(&mut buffer[..limit])?;
        self.read.send(()).unwrap();
        Ok(count)
    }
}

#[test]
fn stdin_in_hup_drains_all_chunks_and_pending_frames_then_waits_for_remote_exit() {
    let (input, mut output) = io::pipe().unwrap();
    let expected: Vec<u8> = (0..4096).map(|n| (n % 251) as u8).collect();
    output.write_all(&expected).unwrap();
    drop(output);
    let mut descriptors = [PollFd::new(&input, PollFlags::IN | PollFlags::HUP)];
    poll(&mut descriptors, Some(&Timespec::default())).unwrap();
    assert!(descriptors[0]
        .revents()
        .contains(PollFlags::IN | PollFlags::HUP));
    let (client, mut server) = tcp_streams();
    let prefix = fill_transport(&client);
    let control = client.try_clone().unwrap();
    let (read_tx, read_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut connection = Connection::new_client(client, &[19; 32]);
        run_exit_pump(
            &mut connection,
            false,
            ChunkedPipe {
                pipe: input,
                read: read_tx,
            },
            |_| panic!("healthy transport must not recover"),
        );
        done_tx.send(connection.write_pending()).unwrap();
    });
    read_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let early = done_rx.recv_timeout(Duration::from_millis(100));
    server.read_exact(&mut vec![0; prefix]).unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let Ok(packet) = peer.read_packet() else {
            break;
        };
        assert_eq!(packet.header(), TerminalPacketType::TerminalBuffer as u8);
        received.extend(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .unwrap(),
        );
    }
    let after_eof = done_rx.recv_timeout(Duration::from_millis(200));
    peer.write_packet(
        TerminalPacketType::TerminalExitStatus as u8,
        &et_core::proto::TerminalExitStatus { exitcode: Some(0) }.encode_to_vec(),
    )
    .unwrap();
    let completed = done_rx.recv_timeout(Duration::from_secs(3));
    let _ = control.shutdown(std::net::Shutdown::Both);
    worker.join().unwrap();
    assert!(early.is_err(), "pump abandoned a pending stdin frame");
    assert!(after_eof.is_err(), "pipe EOF ended the remote session");
    assert!(!completed.unwrap());
    assert_eq!(received, expected);
    assert_eq!(peer.reader_sequence(), 4);
}

struct ObservedInput {
    ready: UnixStream,
    fail_read: bool,
    reads: mpsc::Sender<()>,
}

impl std::os::fd::AsFd for ObservedInput {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.ready.as_fd()
    }
}

impl Read for ObservedInput {
    fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
        self.reads.send(()).unwrap();
        if self.fail_read {
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::BADF.raw_os_error(),
            ))
        } else {
            Ok(0)
        }
    }
}

#[test]
fn non_tty_eof_or_read_error_disables_input_but_keeps_keepalive_forwarding_and_recovery() {
    use et_core::proto::{
        PortForwardDestinationRequest, PortForwardDestinationResponse, SocketEndpoint,
    };

    for fail_read in [false, true] {
        // Character-device poll readiness differs on Darwin. A socket with an
        // unread byte gives both platforms persistent IN; inject EOF/EBADF at
        // the Read seam and verify neither spins nor ends the ET transport.
        let (ready, mut input_peer) = UnixStream::pair().unwrap();
        input_peer.write_all(b"x").unwrap();
        let (reads, observed) = mpsc::channel();
        let (client, server) = tcp_streams();
        let mut peer = Connection::new_server(server, &[19; 32]);
        let (recovered_client, recovered_server) = tcp_streams();
        let mut recovered_peer = Connection::new_server(recovered_server, &[19; 32]);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut connection = Connection::new_client(client, &[19; 32]);
            let mut recovered_client = Some(recovered_client);
            let (mut wake, _writer) = UnixStream::pair().unwrap();
            wake.set_nonblocking(true).unwrap();
            let mut recoveries = 0;
            let result = pump_with_stdin(
                &mut connection,
                &mut wake,
                PumpOptions {
                    read_stdin: true,
                    keepalive_seconds: 1,
                    flow_control: et_cli::client::FlowControlMode::None,
                    terminal_enabled: false,
                    auto_cursor_report: false,
                    binary_stdio: true,
                    terminal_modes: &mut TerminalModeState::default(),
                    hangup: &crate::client_hangup::HangupClose::disabled(),
                    remote_exit: &crate::client_terminal::RemoteExit::new(false),
                    stdio_forward: false,
                },
                &mut Forwarder::start(Vec::new()).unwrap(),
                |connection| {
                    recoveries += 1;
                    if let Some(stream) = recovered_client.take() {
                        *connection = Connection::new_client(stream, &[19; 32]);
                        Ok(ReconnectOutcome::Recovered)
                    } else {
                        Ok(ReconnectOutcome::SessionEnded)
                    }
                },
                ObservedInput {
                    ready,
                    fail_read,
                    reads,
                },
            );
            done_tx.send((result, recoveries)).unwrap();
        });
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        let keepalive = peer.read_packet().unwrap();
        assert_eq!(keepalive.header(), TerminalPacketType::KeepAlive as u8);
        peer.write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .unwrap();
        let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.write_packet(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            &PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some("127.0.0.1".to_owned()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(93),
                window: None,
            }
            .encode_to_vec(),
        )
        .unwrap();
        let response = peer.read_packet().unwrap();
        assert_eq!(
            response.header(),
            TerminalPacketType::PortForwardDestinationResponse as u8
        );
        let response = PortForwardDestinationResponse::decode(response.payload()).unwrap();
        assert_eq!(response.clientfd, Some(93));
        assert!(response.error.is_none(), "{response:?}");
        let _application = destination.accept().unwrap();
        assert!(done_rx.try_recv().is_err(), "input closure ended ET");
        peer.shutdown().unwrap();
        let keepalive = recovered_peer.read_packet().unwrap();
        assert_eq!(keepalive.header(), TerminalPacketType::KeepAlive as u8);
        recovered_peer
            .write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .unwrap();
        assert!(done_rx.try_recv().is_err(), "recovery did not remain live");
        recovered_peer.shutdown().unwrap();
        let (result, recoveries) = done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        worker.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(recoveries, 2, "one recovery should precede final shutdown");
        assert!(
            observed.try_recv().is_err(),
            "closed input was polled again"
        );
    }
}

#[test]
fn real_tty_eof_still_ends_the_session() {
    let pair = portable_pty::native_pty_system()
        .openpty(portable_pty::PtySize::default())
        .unwrap();
    let input = std::fs::File::open(pair.master.tty_name().unwrap()).unwrap();
    assert!(input.is_terminal());
    // Canonical VEOF returns read(0) without closing the underlying PTY.
    let mut master = pair.master.take_writer().unwrap();
    master.write_all(b"\x04").unwrap();
    let (client, _server) = tcp_streams();
    let control = client.try_clone().unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut connection = Connection::new_client(client, &[19; 32]);
        run_exit_pump(&mut connection, false, input, |_| {
            panic!("TTY EOF must not reconnect")
        });
        done_tx.send(()).unwrap();
    });
    let completed = done_rx.recv_timeout(Duration::from_secs(3));
    let _ = control.shutdown(std::net::Shutdown::Both);
    worker.join().unwrap();
    completed.expect("real TTY EOF must still end the session");
}

#[test]
fn redirected_pipe_reader_delivers_binary_chunks_then_closes_only_input() {
    let (input, mut output) = io::pipe().unwrap();
    let receiver = redirected_input(input).unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let expected: Vec<u8> = (0..40001).map(|n| (n % 256) as u8).collect();
    let sent = expected.clone();
    let writer = thread::spawn(move || output.write_all(&sent).unwrap());
    let mut received = Vec::new();
    loop {
        match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(bytes) => {
                assert!(bytes.len() <= 16 * 1024);
                received.extend(bytes);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(error) => panic!("redirected reader stalled: {error}"),
        }
    }
    writer.join().unwrap();
    assert_eq!(received, expected);
}

#[test]
fn redirected_reader_retries_interrupts_and_disables_unusable_handles() {
    struct InterruptedInput(u8);
    impl Read for InterruptedInput {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            match self.0 {
                1 => Err(io::ErrorKind::Interrupted.into()),
                2 => {
                    bytes[0] = 0xff;
                    Ok(1)
                }
                _ => Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
    let receiver = redirected_input(InterruptedInput(0)).unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(3)).unwrap(),
        [0xff]
    );
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(3)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
}

struct GatedConsole {
    entered: mpsc::SyncSender<usize>,
    release: mpsc::Receiver<()>,
}

impl Write for GatedConsole {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered
            .send(bytes.len())
            .map_err(|_| io::Error::other("console observer closed"))?;
        self.release
            .recv()
            .map_err(|_| io::Error::other("console release closed"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn pending_console_output_does_not_block_terminal_input() {
    // Given: a deliberately blocked console and a completely full queue.
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = crate::client_output::ConsoleOutput::new(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(GatedConsole {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(&vec![1; 64 * 1024], &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    assert!(output.try_write(&vec![2; 64 * 1024], &modes).unwrap());
    let packet = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(b"pending".to_vec()),

            is_stderr: None,
        }
        .encode_to_vec(),
    );
    let mut modes = TerminalModeState::default();
    assert!(matches!(
        route_server_packet(
            packet,
            true,
            false,
            &mut modes,
            &output,
            &crate::client_terminal::RemoteExit::new(false),
        )
        .unwrap(),
        DisplayOutcome::Pending(_)
    ));

    // When: Ctrl-C input is sent while output remains blocked.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [31u8; 32];
    let mut sender = Connection::new_client(client_stream, &key);
    let mut receiver = Connection::new_server(server_stream, &key);
    send_buffer(&mut sender, b"\x03").unwrap();

    // Then: input arrives before either console write is released.
    let received = receiver.read_packet().unwrap();
    let input = TerminalBuffer::decode(received.payload()).unwrap();
    assert_eq!(input.buffer.as_deref(), Some(b"\x03".as_slice()));
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    release_tx.send(()).unwrap();
    drop(output);
}

#[test]
fn remote_completion_bounds_a_retained_packet_behind_stalled_output() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::channel();
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let cancel_observer = std::sync::Arc::clone(&cancelled);
    let output = crate::client_output::ConsoleOutput::new_with_cancel(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(GatedConsole {
            entered: entered_tx,
            release: release_rx,
        }),
        Box::new(move || cancel_observer.store(true, Ordering::Release)),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(&vec![1; 64 * 1024], &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    assert!(output.try_write(&vec![2; 64 * 1024], &modes).unwrap());
    let retained = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(b"retained".to_vec()),

            is_stderr: None,
        }
        .encode_to_vec(),
    );
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let (done_tx, done_rx) = mpsc::sync_channel(0);
    thread::spawn(move || {
        let mut terminal_modes = TerminalModeState::default();
        done_tx
            .send(finish_remote_completion(
                output,
                Some(retained),
                VecDeque::new(),
                true,
                false,
                &mut terminal_modes,
                &mut forwarder,
                None,
                &crate::client_terminal::RemoteExit::new(false),
            ))
            .unwrap();
    });

    assert!(done_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("retained output kept remote completion blocked")
        .is_ok());
    assert!(cancelled.load(Ordering::Acquire));

    // Let the detached writer finish so the test leaves no blocked thread.
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    release_tx.send(()).unwrap();
}

#[test]
fn remote_completion_attempts_retained_output_before_draining() {
    let output = crate::client_output::ConsoleOutput::new(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(Vec::<u8>::new()),
    )
    .unwrap();
    let retained = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(vec![b'x'; 64 * 1024 + 1]),

            is_stderr: None,
        }
        .encode_to_vec(),
    );
    let mut terminal_modes = TerminalModeState::default();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();

    let error = finish_remote_completion(
        output,
        Some(retained),
        VecDeque::new(),
        true,
        false,
        &mut terminal_modes,
        &mut forwarder,
        None,
        &crate::client_terminal::RemoteExit::new(false),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("terminal output packet exceeds console queue capacity"),
        "unexpected error: {error}"
    );
}
