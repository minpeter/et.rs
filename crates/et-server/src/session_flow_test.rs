#![cfg(test)]

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use et_core::proto::FlowControlMode;
use et_net::connection::Connection;

use super::ActiveSession;

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
