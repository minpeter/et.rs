#![cfg(test)]

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use et_core::proto::FlowControlMode;
use et_net::connection::Connection;

use super::{session_flow::FlowControl, ActiveSession, SessionError};

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
fn live_send_reset_disconnects_without_requeueing_replay_owned_packet() {
    // Given: one in-flight packet followed by queued output.
    let flow = FlowControl::new(et_core::flow_control::FlowControlMode::Backpressure);
    flow.enqueue(et_core::packet::Packet::new(41, b"in-flight".as_slice()))
        .unwrap();
    flow.enqueue(et_core::packet::Packet::new(42, b"queued".as_slice()))
        .unwrap();
    let in_flight = flow.next_packet().unwrap();

    // When: the live socket resets after replay accepted the packet.
    let error = Err(SessionError::Connection(et_net::connection::ConnError::Io(
        std::io::ErrorKind::ConnectionReset.into(),
    )));
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
    let reset = Err(SessionError::Connection(et_net::connection::ConnError::Io(
        std::io::ErrorKind::ConnectionReset.into(),
    )));
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
        let result = sender
            .write_packet(packet.header(), packet.payload())
            .map_err(SessionError::Connection);
        assert!(flow.complete(packet, &result, sender.connected()));
        assert!(result.is_ok());
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
