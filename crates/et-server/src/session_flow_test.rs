#![cfg(test)]

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use et_core::proto::FlowControlMode;
use et_net::connection::{ConnError, Connection, WritePacketError};
use prost::Message;

use super::{
    session_flow::{FlowControl, FlowWriteResult},
    ActiveSession, SessionError, SessionWriteError,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

fn connection_pair() -> (Connection, Connection) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (server, _) = listener.accept().unwrap();
    let client = client.join().unwrap();
    let key = [7u8; 32];
    (
        Connection::new_server(server, &key),
        Connection::new_client(client, &key),
    )
}

#[test]
fn default_none_preserves_write_ownership_for_exact_once_retry() {
    let (server, mut client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = ActiveSession::new(server, &terminal, None).unwrap();
    let mut writes = 0;

    let error = session
        .send_packet_owned_with(46, b"exactly-once", |_, _, _| {
            writes += 1;
            Err(WritePacketError::BeforeReplay(ConnError::Io(
                std::io::Error::other("injected clone failure"),
            )))
        })
        .unwrap_err();
    assert!(matches!(error, SessionWriteError::BeforeReplay(_)));
    assert_eq!(writes, 1);

    session.send_packet_owned(46, b"exactly-once").unwrap();
    let packet = client.read_packet().unwrap();
    assert_eq!(
        (packet.header(), packet.payload()),
        (46, b"exactly-once".as_slice())
    );

    let error = session
        .send_packet_owned_with(47, b"replay-owned", |_, _, _| {
            writes += 1;
            Err(WritePacketError::ReplayOwned(ConnError::Io(
                std::io::Error::other("injected post-admission failure"),
            )))
        })
        .unwrap_err();
    assert!(matches!(error, SessionWriteError::ReplayOwned(_)));
    assert_eq!(writes, 2);
}

#[test]
fn graceful_hup_drains_and_joins_a_deliberately_blocked_writer() {
    for mode in [FlowControlMode::Backpressure, FlowControlMode::Discard] {
        // Given: a flow writer has removed the final packet from its queue but
        // is deterministically blocked before taking the connection lock.
        let (server, mut client) = connection_pair();
        let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
        let session = Arc::new(ActiveSession::new(server, &terminal, Some(mode as i32)).unwrap());
        session.start_flow_writer();
        let connection = session.connection.lock().unwrap();
        session.send_packet(47, b"final-packet").unwrap();
        let flow = session.flow_control.as_ref().unwrap();
        flow.wait_in_flight();

        // When: terminal HUP requests graceful completion while the write is blocked.
        let (finished_tx, finished_rx) = mpsc::sync_channel(0);
        let finishing = Arc::clone(&session);
        let worker = thread::spawn(move || finished_tx.send(finishing.finish_terminal()).unwrap());
        flow.wait_for_stop(true);
        drop(connection);

        // Then: the retained packet arrives before the joined writer permits half-close.
        assert!(finished_rx.recv_timeout(TEST_TIMEOUT).unwrap().is_ok());
        worker.join().unwrap();
        let packet = client.read_packet().unwrap();
        assert_eq!(
            (packet.header(), packet.payload()),
            (47, b"final-packet".as_slice())
        );
    }
}

#[test]
fn terminal_finish_fails_and_joins_after_unrecoverable_before_replay() {
    let (server, mut client) = connection_pair();
    client.set_io_timeout(Some(TEST_TIMEOUT)).unwrap();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            server,
            &terminal,
            Some(FlowControlMode::Backpressure as i32),
        )
        .unwrap(),
    );
    let flow = Arc::clone(session.flow_control.as_ref().unwrap());
    flow.enqueue(et_core::packet::Packet::new(55, b"retained".as_slice()))
        .unwrap();
    let (attempt_tx, attempt_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let worker_session = Arc::clone(&session);
    let worker_flow = Arc::clone(&flow);
    let handle = thread::spawn(move || {
        while let Some(packet) = worker_flow.next_packet() {
            attempt_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let (result, connected) = super::session_flow::writer::write_packet_with(
                &worker_session,
                &worker_flow,
                &packet,
                |connection, packet| {
                    connection.prepare_write_packet_with(packet.header(), packet.payload(), |_| {
                        Err(std::io::Error::other("injected clone failure"))
                    })
                },
            );
            if !worker_flow.complete(packet, &result, connected) {
                break;
            }
        }
    });
    *session.flow_writer.lock().unwrap() = Some(handle);
    attempt_rx.recv().unwrap();

    let (finished_tx, finished_rx) = mpsc::sync_channel(0);
    let finishing = Arc::clone(&session);
    let finisher = thread::spawn(move || finished_tx.send(finishing.finish_terminal()).unwrap());
    flow.wait_for_stop(true);
    release_tx.send(()).unwrap();

    let error = finished_rx.recv_timeout(TEST_TIMEOUT).unwrap().unwrap_err();
    assert!(matches!(error, SessionError::Connection(ConnError::Io(_))));
    finisher.join().unwrap();
    assert!(attempt_rx.try_recv().is_err());
    assert!(session.flow_writer.lock().unwrap().is_none());
    assert!(client.read_packet().is_err());
}

#[test]
fn hard_shutdown_wakes_and_joins_a_deliberately_blocked_writer() {
    // Given: a writer blocked after taking ownership of a queued packet.
    let (server, _client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(server, &terminal, Some(FlowControlMode::Discard as i32)).unwrap(),
    );
    session.start_flow_writer();
    let connection = session.connection.lock().unwrap();
    session.send_packet(48, b"discardable").unwrap();
    let flow = session.flow_control.as_ref().unwrap();
    flow.wait_in_flight();

    // When: hard shutdown is requested and wakes the worker.
    let (finished_tx, finished_rx) = mpsc::sync_channel(0);
    let stopping = Arc::clone(&session);
    let worker = thread::spawn(move || finished_tx.send(stopping.shutdown()).unwrap());
    flow.wait_for_stop(false);
    drop(connection);

    // Then: shutdown returns only after the writer has joined.
    assert!(finished_rx.recv_timeout(TEST_TIMEOUT).unwrap().is_ok());
    worker.join().unwrap();
}

#[test]
fn before_replay_failure_waits_for_resume_then_delivers_once() {
    // Given: the flow writer owns one packet and socket cloning fails before replay admission.
    let (server, _client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = ActiveSession::new(
        server,
        &terminal,
        Some(FlowControlMode::Backpressure as i32),
    )
    .unwrap();
    let flow = session.flow_control.as_ref().unwrap();
    flow.enqueue(et_core::packet::Packet::new(40, b"clone-retry".as_slice()))
        .unwrap();
    let packet = flow.next_packet().unwrap();

    // When: preparation injects a clone failure, then normal preparation retries it.
    let (failed, connected) = super::session_flow::writer::write_packet_with(
        &session,
        flow,
        &packet,
        |connection, packet| {
            connection.prepare_write_packet_with(packet.header(), packet.payload(), |_| {
                Err(std::io::Error::other("injected clone failure"))
            })
        },
    );
    assert!(matches!(failed, FlowWriteResult::BeforeReplay(_)));
    assert!(!connected);
    assert!(!session.connection.lock().unwrap().connected());
    assert!(flow.complete(packet, &failed, connected));
    let (restored_tx, restored_rx) = mpsc::sync_channel(0);
    let flow_waiter = Arc::clone(session.flow_control.as_ref().unwrap());
    let waiting = thread::spawn(move || restored_tx.send(flow_waiter.next_packet()).unwrap());
    assert!(restored_rx.try_recv().is_err());
    let (recovered_server, mut recovered_client) = connection_pair();
    recovered_client.set_io_timeout(Some(TEST_TIMEOUT)).unwrap();
    *session.connection.lock().unwrap() = recovered_server;
    flow.resume(true);
    let restored = restored_rx.recv_timeout(TEST_TIMEOUT).unwrap().unwrap();
    waiting.join().unwrap();
    let (delivered, connected) =
        super::session_flow::writer::write_packet(&session, flow, &restored);
    assert!(flow.complete(restored, &delivered, connected));

    // Then: the restored plaintext is encrypted under one sequence and delivered once.
    let received = recovered_client.read_packet().unwrap();
    assert_eq!(
        (received.header(), received.payload()),
        (40, b"clone-retry".as_slice())
    );
    recovered_client
        .set_io_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert!(recovered_client.read_packet().is_err());
}

#[test]
fn non_transport_before_replay_is_fatal_instead_of_pausing_as_disconnected() {
    let (server, _client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = ActiveSession::new(
        server,
        &terminal,
        Some(FlowControlMode::Backpressure as i32),
    )
    .unwrap();
    let flow = session.flow_control.as_ref().unwrap();
    flow.enqueue(et_core::packet::Packet::new(
        53,
        b"semantic-failure".as_slice(),
    ))
    .unwrap();
    let packet = flow.next_packet().unwrap();
    let (result, connected) =
        super::session_flow::writer::write_packet_with(&session, flow, &packet, |_, _| {
            Err(WritePacketError::BeforeReplay(ConnError::Backpressure))
        });

    assert!(matches!(result, FlowWriteResult::Fatal(_)));
    assert!(connected);
    assert!(!flow.complete(packet, &result, connected));
}

#[test]
fn before_replay_waits_for_explicit_resume_while_session_is_recoverable() {
    let (server, _client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            server,
            &terminal,
            Some(FlowControlMode::Backpressure as i32),
        )
        .unwrap(),
    );
    let flow = Arc::clone(session.flow_control.as_ref().unwrap());
    flow.enqueue(et_core::packet::Packet::new(
        54,
        b"graceful-retry".as_slice(),
    ))
    .unwrap();
    let (attempt_tx, attempt_rx) = mpsc::sync_channel(0);
    let (result_tx, result_rx) = mpsc::sync_channel(0);
    let (completed_tx, completed_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(0);
    let worker_session = Arc::clone(&session);
    let worker_flow = Arc::clone(&flow);
    let worker = thread::spawn(move || {
        let mut attempt = 0;
        while let Some(packet) = worker_flow.next_packet() {
            attempt += 1;
            attempt_tx.send(attempt).unwrap();
            let fail = result_rx.recv().unwrap();
            let (result, connected) = match (attempt, fail) {
                (1, true) => super::session_flow::writer::write_packet_with(
                    &worker_session,
                    &worker_flow,
                    &packet,
                    |connection, packet| {
                        connection.prepare_write_packet_with(
                            packet.header(),
                            packet.payload(),
                            |_| Err(std::io::Error::other("persistent clone failure")),
                        )
                    },
                ),
                (_, true) => (
                    FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(
                        std::io::Error::other("persistent clone failure"),
                    ))),
                    false,
                ),
                (_, false) => (FlowWriteResult::Delivered, true),
            };
            if !worker_flow.complete(packet, &result, connected) {
                break;
            }
            completed_tx.send(attempt).unwrap();
        }
        done_tx.send(()).unwrap();
    });

    assert_eq!(attempt_rx.recv().unwrap(), 1);
    result_tx.send(true).unwrap();
    assert_eq!(completed_rx.recv().unwrap(), 1);
    assert!(!session.connection.lock().unwrap().connected());
    assert!(attempt_rx.try_recv().is_err());
    assert!(done_rx.try_recv().is_err());

    flow.resume(true);
    assert_eq!(attempt_rx.recv().unwrap(), 2);
    result_tx.send(true).unwrap();
    assert_eq!(completed_rx.recv().unwrap(), 2);
    assert!(attempt_rx.try_recv().is_err());
    assert!(done_rx.try_recv().is_err());

    // Installing/authorizing a usable transport and resuming permits exactly
    // one final delivery, after which graceful join can complete.
    flow.resume(true);
    assert_eq!(attempt_rx.recv().unwrap(), 3);
    result_tx.send(false).unwrap();
    assert_eq!(completed_rx.recv().unwrap(), 3);
    flow.stop_gracefully();
    done_rx.recv().unwrap();
    worker.join().unwrap();
}

#[test]
fn live_send_reset_disconnects_without_requeueing_replay_owned_packet() {
    // Given: one in-flight packet followed by queued output.
    let flow = FlowControl::new(et_core::flow_control::FlowControlMode::Backpressure);
    flow.enqueue(et_core::packet::Packet::new(41, b"in-flight".as_slice()))
        .unwrap();
    flow.enqueue(et_core::packet::Packet::new(42, b"queued".as_slice()))
        .unwrap();
    let in_flight = flow.next_packet().unwrap();

    // When: the live socket resets after replay accepted the packet.
    let error = FlowWriteResult::ReplayOwned(SessionError::Connection(
        et_net::connection::ConnError::Io(std::io::ErrorKind::ConnectionReset.into()),
    ));
    assert!(flow.complete(in_flight, &error, false));
    flow.resume(true);

    // Then: recovery sends only the still-queued packet; replay owns the first.
    let queued = flow.next_packet().unwrap();
    assert_eq!(
        (queued.header(), queued.payload()),
        (42, b"queued".as_slice())
    );
}

#[test]
fn live_send_reset_recovers_replay_then_sends_queued_and_subsequent_once() {
    // Given: replay has accepted one packet when its live socket resets, with
    // another packet still reserved in the flow queue.
    let (mut sender, mut receiver) = connection_pair();
    let flow = FlowControl::new(et_core::flow_control::FlowControlMode::Backpressure);
    flow.enqueue(et_core::packet::Packet::new(51, b"replay".as_slice()))
        .unwrap();
    flow.enqueue(et_core::packet::Packet::new(52, b"queued".as_slice()))
        .unwrap();
    let replay = flow.next_packet().unwrap();
    let prepared = sender
        .prepare_write_packet(replay.header(), replay.payload())
        .unwrap();
    drop(prepared);
    sender.disconnect();
    let reset = FlowWriteResult::ReplayOwned(SessionError::Connection(
        et_net::connection::ConnError::Io(std::io::ErrorKind::ConnectionReset.into()),
    ));
    assert!(flow.complete(replay, &reset, false));

    // When: both peers recover on a replacement socket.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (new_sender, _) = listener.accept().unwrap();
    let new_receiver = connector.join().unwrap();
    let (receiver_tx, receiver_rx) = mpsc::sync_channel(0);
    let recovering_receiver = thread::spawn(move || {
        receiver.recover(new_receiver).unwrap();
        receiver_tx.send(receiver).unwrap();
    });
    sender.recover(new_sender).unwrap();
    let mut receiver = receiver_rx.recv_timeout(TEST_TIMEOUT).unwrap();
    recovering_receiver.join().unwrap();
    flow.resume(true);

    // Then: replay delivers the failed live packet, while the still-queued
    // packet and output produced after recovery each follow exactly once.
    for (header, payload) in [(52, b"queued".as_slice()), (53, b"subsequent".as_slice())] {
        if header == 53 {
            flow.enqueue(et_core::packet::Packet::new(header, payload))
                .unwrap();
        }
        let packet = flow.next_packet().unwrap();
        sender
            .write_packet(packet.header(), packet.payload())
            .unwrap();
        assert!(flow.complete(packet, &FlowWriteResult::Delivered, sender.connected()));
    }
    for expected in [
        (51, b"replay".as_slice()),
        (52, b"queued".as_slice()),
        (53, b"subsequent".as_slice()),
    ] {
        let packet = receiver.read_packet().unwrap();
        assert_eq!((packet.header(), packet.payload()), expected);
    }
    receiver
        .set_io_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert!(
        receiver.read_packet().is_err(),
        "recovered output was duplicated"
    );
}

#[test]
fn recover_hold_post_admission_failure_replays_without_plaintext_duplicate() {
    // Given: post-install held plaintext is accepted by replay, then live send fails.
    let (server, mut client) = connection_pair();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = ActiveSession::new(server, &terminal, None).unwrap();
    session
        .recover_hold
        .lock()
        .unwrap()
        .push((54, b"held-once".to_vec()));
    let result = session.flush_recover_hold_with(|connection, header, payload| {
        let prepared = connection.prepare_write_packet(header, payload)?;
        drop(prepared);
        connection.disconnect();
        Err(et_net::connection::WritePacketError::ReplayOwned(
            et_net::connection::ConnError::Io(std::io::ErrorKind::ConnectionReset.into()),
        ))
    });
    assert!(result.is_err());
    assert!(session.recover_hold.lock().unwrap().is_empty());

    // When: the installed connection recovers again.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (new_server, _) = listener.accept().unwrap();
    let new_client = connector.join().unwrap();
    let (client_tx, client_rx) = mpsc::sync_channel(0);
    let recovering_client = thread::spawn(move || {
        client.recover(new_client).unwrap();
        client_tx.send(client).unwrap();
    });
    session
        .connection
        .lock()
        .unwrap()
        .recover(new_server)
        .unwrap();
    let mut client = client_rx.recv_timeout(TEST_TIMEOUT).unwrap();
    recovering_client.join().unwrap();

    // Then: replay supplies the packet exactly once; no plaintext duplicate was retained.
    let packet = client.read_packet().unwrap();
    assert_eq!(
        (packet.header(), packet.payload()),
        (54, b"held-once".as_slice())
    );
    client
        .set_io_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert!(client.read_packet().is_err());
}

#[test]
fn full_control_lane_rejects_nonblocking_while_discard_terminal_and_recovery_progress() {
    // Given: discard mode's lossless control lane is full.
    let flow = FlowControl::new(et_core::flow_control::FlowControlMode::Discard);
    let control = et_core::packet::Packet::new(61, vec![1; 1024]);
    loop {
        match flow.enqueue(control.clone()) {
            Ok(()) => {}
            Err(SessionError::Connection(et_net::connection::ConnError::Backpressure)) => break,
            Err(error) => panic!("unexpected control admission: {error}"),
        }
    }

    // When: terminal output arrives and a recovery pause/resume completes.
    let terminal = et_core::packet::Packet::new(
        et_core::proto::TerminalPacketType::TerminalBuffer as u8,
        et_core::proto::TerminalBuffer {
            buffer: Some(b"newest".to_vec()),
        }
        .encode_to_vec(),
    );
    flow.enqueue(terminal).unwrap();
    flow.pause().unwrap();
    flow.resume(true);

    // Then: the bridge-facing full result was immediate and terminal remains serviceable.
    let next = flow.next_packet().unwrap();
    assert_eq!(
        next.header(),
        et_core::proto::TerminalPacketType::TerminalBuffer as u8
    );
}

#[test]
fn oversized_control_fails_permanently_without_waiting() {
    let flow = FlowControl::new(et_core::flow_control::FlowControlMode::Backpressure);
    let oversized = et_core::packet::Packet::new(62, vec![0; 64 * 1024]);

    assert!(matches!(
        flow.enqueue(oversized),
        Err(SessionError::Connection(
            et_net::connection::ConnError::PacketTooLarge
        ))
    ));
}

#[test]
fn concurrent_hard_stop_cannot_be_downgraded_to_graceful_drain() {
    // Given: a packet removed from the queue while transport preparation is blocked.
    let (server, mut client) = connection_pair();
    client.set_io_timeout(Some(TEST_TIMEOUT)).unwrap();
    let (terminal, _terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            server,
            &terminal,
            Some(FlowControlMode::Backpressure as i32),
        )
        .unwrap(),
    );
    session.start_flow_writer();
    let connection = session.connection.lock().unwrap();
    session.send_packet(49, b"must-not-drain").unwrap();
    let flow = session.flow_control.as_ref().unwrap();
    flow.wait_in_flight();

    // When: hard shutdown wins before a concurrent terminal HUP asks for graceful stop.
    flow.stop_hard();
    flow.stop_gracefully();
    drop(connection);
    session.join_flow_writer(true).unwrap();

    // Then: the hard-stopped writer does not drain the packet after transport unblocks.
    assert!(client.read_packet().is_err());
}
