use super::*;
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::TerminalPacketType;

fn streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    (client, listener.accept().unwrap().0)
}

fn pair() -> (Connection, Connection) {
    let (client, server) = streams();
    let sender = Connection::new_client(client, &[19; 32]);
    sender.shrink_transport_window_for_tests(4096).unwrap();
    sender.set_io_timeout(Some(Duration::from_secs(3))).unwrap();
    let peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(3))).unwrap();
    (sender, peer)
}

fn drain(sender: &mut Connection) {
    let stream = sender.try_clone_stream().unwrap();
    while sender.write_pending() {
        let remaining = sender
            .pending_write_deadline()
            .unwrap()
            .saturating_duration_since(Instant::now());
        let timeout = Timespec::try_from(remaining).unwrap();
        let mut descriptors = [PollFd::new(&stream, PollFlags::OUT)];
        assert_eq!(poll(&mut descriptors, Some(&timeout)).unwrap(), 1);
        sender.advance_write().unwrap();
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn pending_send_enables_socket_sigpipe_suppression_on_apple() {
    let (mut sender, _peer) = pair();
    let stream = sender.try_clone_stream().unwrap();
    // TcpStream may already suppress SIGPIPE; clear it to prove that our
    // raw send path establishes its own per-socket protection.
    rustix::net::sockopt::set_socket_nosigpipe(&stream, false).unwrap();
    sender.start_write_packet_owned(7, b"first").unwrap();
    assert!(rustix::net::sockopt::socket_nosigpipe(&stream).unwrap());
    assert!(rustix::fs::fcntl_getfl(&stream)
        .unwrap()
        .contains(rustix::fs::OFlags::NONBLOCK));
}

#[test]
fn synchronous_read_after_live_write_waits_for_delayed_response() {
    let (mut sender, mut peer) = pair();
    sender.start_write_packet_owned(7, b"request").unwrap();
    drain(&mut sender);
    let receiver = thread::spawn(move || {
        assert_eq!(peer.read_packet().unwrap().payload(), b"request");
        thread::sleep(Duration::from_millis(50));
        peer.write_packet(8, b"response").unwrap();
    });
    assert_eq!(sender.read_packet().unwrap(), Packet::new(8, b"response"));
    receiver.join().unwrap();
    assert!(sender.connected());
}

#[test]
fn synchronous_read_after_live_write_honors_deadline() {
    let (mut sender, _peer) = pair();
    sender.start_write_packet_owned(7, b"request").unwrap();
    drain(&mut sender);
    let started = Instant::now();
    let error = sender
        .read_packet_deadline(started + Duration::from_millis(50))
        .unwrap_err();
    assert!(matches!(error, ConnError::Io(ref error)
        if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)));
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn synchronous_write_after_live_write_waits_until_deadline() {
    let (mut sender, _peer) = pair();
    sender.start_write_packet_owned(7, b"request").unwrap();
    drain(&mut sender);
    let started = Instant::now();
    let error = sender
        .write_packet_live_until(
            8,
            &vec![42; 1024 * 1024],
            started + Duration::from_millis(100),
        )
        .unwrap_err();
    assert!(matches!(error, ConnError::Io(ref error)
        if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)));
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!sender.connected());
}

#[test]
fn partial_frame_services_reads_and_serializes_competing_writes() {
    // Given: one encrypted forwarding frame larger than the socket capacity.
    let (mut sender, mut peer) = pair();
    let packet = Packet::new(
        TerminalPacketType::PortForwardData as u8,
        vec![3; 1024 * 1024],
    );
    sender
        .start_write_packet_owned(packet.header(), packet.payload())
        .unwrap();
    assert!(sender.write_pending());
    let original_deadline = sender.pending_write_deadline();

    // When: an unrelated writer competes and inbound traffic arrives before
    // the peer starts draining this frame.
    assert!(matches!(
        sender.write_packet_owned(0, b"next"),
        Err(WritePacketError::BeforeReplay(ConnError::Backpressure))
    ));
    peer.write_packet(0, b"input-before-drain").unwrap();
    assert_eq!(
        sender
            .read_packet_deadline(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .payload(),
        b"input-before-drain"
    );
    assert!(sender.connected());
    assert_eq!(sender.writer_sequence(), 1);
    assert_eq!(sender.pending_write_deadline(), original_deadline);
    let receiver = thread::spawn(move || {
        let first = peer.read_packet().unwrap();
        let second = peer.read_packet().unwrap();
        (first, second, peer.reader_sequence())
    });
    drain(&mut sender);
    sender.start_write_packet_owned(0, b"next").unwrap();
    drain(&mut sender);

    // Then: exact encrypted records arrive once, in nonce/sequence order.
    let (first, second, sequence) = receiver.join().unwrap();
    assert_eq!(first, packet);
    assert_eq!(second, Packet::new(0, b"next"));
    assert_eq!(sequence, 2);
    assert_eq!(sender.writer_sequence(), 2);
}

#[test]
fn recovery_replays_partial_frame_once_before_later_live_traffic() {
    // Given: a partially sent frame, including bytes already in the peer's
    // decoder but not yet delivered as an authenticated packet.
    let (mut sender, mut peer) = pair();
    let packet = Packet::new(
        TerminalPacketType::PortForwardData as u8,
        vec![5; 1024 * 1024],
    );
    sender
        .start_write_packet_owned(packet.header(), packet.payload())
        .unwrap();
    assert!(sender.write_pending());
    assert!(peer.try_read_packet().unwrap().is_none());
    assert_eq!(peer.reader_sequence(), 0);
    peer.disconnect();
    let (replacement, peer_replacement) = streams();

    // When: recovery replaces the old transport with its replay-owned frame
    // still pending. No plaintext is resubmitted to the backed writer.
    let receiver = thread::spawn(move || {
        peer.recover(peer_replacement).unwrap();
        let first = peer.read_packet().unwrap();
        let second = peer
            .read_packet_deadline(Instant::now() + Duration::from_secs(3))
            .unwrap();
        (first, second, peer.reader_sequence())
    });
    sender.recover(replacement).unwrap();
    assert!(!sender.write_pending());
    assert_eq!(sender.writer_sequence(), 1);
    sender.write_packet(0, b"after-recovery").unwrap();

    // Then: replay reconstructs precisely one frame ahead of new live bytes.
    let (first, second, sequence) = receiver.join().unwrap();
    assert_eq!(first, packet);
    assert_eq!(second, Packet::new(0, b"after-recovery"));
    assert_eq!(sequence, 2);
    assert!(sender.connected());
}

#[test]
fn finish_pending_write_lets_a_final_close_follow_the_partial_frame() {
    // Given: a retained partial frame that refuses any competing writer.
    let (mut sender, mut peer) = pair();
    let packet = Packet::new(
        TerminalPacketType::PortForwardData as u8,
        vec![9; 1024 * 1024],
    );
    sender
        .start_write_packet_owned(packet.header(), packet.payload())
        .unwrap();
    assert!(sender.write_pending());
    let receiver = thread::spawn(move || {
        let first = peer.read_packet().unwrap();
        let second = peer.read_packet().unwrap();
        (first, second, peer.reader_sequence())
    });

    // When: a terminal path (hangup / stdio-forward close) must send one
    // final synchronous packet, so it completes the retained frame first.
    sender.finish_pending_write().unwrap();
    assert!(!sender.write_pending());
    sender
        .write_packet(TerminalPacketType::TerminalClose as u8, &[])
        .unwrap();

    // Then: the close is not refused and follows the frame in sequence order.
    let (first, second, sequence) = receiver.join().unwrap();
    assert_eq!(first, packet);
    assert_eq!(
        second,
        Packet::new(TerminalPacketType::TerminalClose as u8, Vec::new())
    );
    assert_eq!(sequence, 2);
    assert!(sender.connected());
}

#[test]
fn expired_partial_write_retains_replay_and_the_original_timeout() {
    // Given: a replay-owned partial write whose absolute deadline expires.
    let (mut sender, _peer) = pair();
    sender
        .start_write_packet_owned(7, &vec![3; 1024 * 1024])
        .unwrap();
    assert!(sender.write_pending());
    assert_eq!(
        sender.live_write_timeout,
        super::super::DEFAULT_LIVE_WRITE_TIMEOUT
    );
    sender.pending_live.as_mut().unwrap().deadline = Instant::now();

    // When: readiness advancement observes expiry (no sleeps or deadline
    // extension are needed to test the actual timeout branch).
    let error = sender.advance_write().unwrap_err();

    // Then: the dead transport cannot accept later bytes, but replay still
    // owns the one encrypted sequence; it was neither retried nor discarded.
    assert!(
        matches!(error, WritePacketError::ReplayOwned(ConnError::Io(ref error))
        if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(!sender.connected());
    assert!(!sender.write_pending());
    assert_eq!(sender.writer_sequence(), 1);
    assert_eq!(sender.writer.recover(0).unwrap().len(), 1);
}
