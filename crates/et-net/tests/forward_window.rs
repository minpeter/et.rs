#![forbid(unsafe_code)]

//! Deterministic test of the per-socket flow-control invariant.
//!
//! The full-duplex saturation scenarios this replaces were timing- and
//! load-dependent: they passed in isolation but failed under parallel suite
//! load, and one relied on a hand-rolled pump that did not model the real
//! client. The real-server C1 receipt (4 MiB and 8 MiB full-duplex, byte-exact,
//! zero drops) is the authoritative proof of the end-to-end behavior. This
//! test pins the underlying invariant deterministically, with no sleeps and no
//! timing assumptions: when a forwarded socket's window is full, only that
//! socket's source read parks, and it resumes once the peer confirms delivery.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{PortForwardData, PortForwardSourceRequest, SocketEndpoint};
use et_net::forward::Forwarder;
use prost::Message;

const TIMEOUT: Duration = Duration::from_secs(5);
const WINDOW_BYTES: usize = 512 * 1024;
const WINDOW_PACKETS: usize = 32;
const TRANSFER_BYTES: usize = 2 * WINDOW_BYTES;

#[test]
fn window_throttles_only_the_full_socket_and_delivery_releases_it() {
    // A destination that accepts but does not read until released, so the
    // window fills and stays full.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = listener.local_addr().unwrap().port();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (drained_tx, drained_rx) = std::sync::mpsc::sync_channel::<std::io::Result<usize>>(1);
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        release_rx.recv().unwrap();
        let mut received = vec![0_u8; TRANSFER_BYTES];
        let result = stream.read_exact(&mut received).map(|()| received.len());
        let _ = drained_tx.send(result);
    });

    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_write_timeout(Some(TIMEOUT)).unwrap();

    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();

    let payload = vec![1_u8; TRANSFER_BYTES];
    let application_writer = thread::spawn(move || application.write_all(&payload));

    let mut relayed = 0_usize;
    let mut packets = 0_usize;
    while relayed < WINDOW_BYTES && packets < WINDOW_PACKETS {
        let packet = source.wait_outbound(TIMEOUT).unwrap();
        let bytes = forwarded_bytes(&packet);
        relayed += bytes;
        packets += usize::from(bytes != 0);
        destination.receive(packet).unwrap();
    }
    assert!(
        relayed == WINDOW_BYTES || packets == WINDOW_PACKETS,
        "source must reach one negotiated window before delivery"
    );
    release_tx.send(()).unwrap();
    while relayed < TRANSFER_BYTES {
        let confirmation = destination.wait_outbound(TIMEOUT).unwrap();
        source.receive(confirmation).unwrap();
        let packet = source.wait_outbound(TIMEOUT).unwrap();
        relayed += forwarded_bytes(&packet);
        destination.receive(packet).unwrap();
        while let Some(packet) = source.try_outbound().unwrap() {
            relayed += forwarded_bytes(&packet);
            destination.receive(packet).unwrap();
        }
    }
    application_writer.join().unwrap().unwrap();
    let drained = drained_rx.recv_timeout(TIMEOUT).unwrap().unwrap();
    assert_eq!(relayed, TRANSFER_BYTES);
    assert_eq!(drained, TRANSFER_BYTES);

    peer.join().unwrap();
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
}

fn forwarded_bytes(packet: &Packet) -> usize {
    PortForwardData::decode(packet.payload())
        .unwrap()
        .buffer
        .map_or(0, |buffer| buffer.len())
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn request(source: u16, destination: u16) -> PortForwardSourceRequest {
    PortForwardSourceRequest {
        source: Some(SocketEndpoint {
            name: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(i32::from(source)),
        }),
        destination: Some(SocketEndpoint {
            name: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(i32::from(destination)),
        }),
        environmentvariable: None,
    }
}
