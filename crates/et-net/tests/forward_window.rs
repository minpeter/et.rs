#![forbid(unsafe_code)]

//! Deterministic tests of the per-socket flow-control invariant.
//!
//! The full-duplex saturation scenarios this replaces were timing- and
//! load-dependent: they passed in isolation but failed under parallel suite
//! load, and one relied on a hand-rolled pump that did not model the real
//! client. The real-server C1 receipt (4 MiB and 8 MiB full-duplex, byte-exact,
//! zero drops) is the authoritative proof of the end-to-end behavior. The
//! window test pins the underlying invariant with no timing assumptions: when
//! a forwarded socket's window is full, only that socket's source read parks,
//! and it resumes once the peer confirms delivery. The credit-cadence test
//! only needs a quiet period longer than any credit timer, and passes
//! whenever none exists.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{PortForwardData, PortForwardSourceRequest, SocketEndpoint};
use et_net::forward::Forwarder;
use prost::Message;

const TIMEOUT: Duration = Duration::from_secs(5);
const WINDOW_BYTES: usize = 4 * 1024 * 1024;
const WINDOW_PACKETS: usize = 127;
/// The window before it was sized for a 50 ms WAN bandwidth-delay product.
const PREVIOUS_WINDOW_BYTES: usize = 2 * 1024 * 1024;
/// How long the full-window source must stay silent without credit.
const STALL_PROBE: Duration = Duration::from_millis(300);
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
    assert!(
        relayed > PREVIOUS_WINDOW_BYTES,
        "a single socket must keep more than {PREVIOUS_WINDOW_BYTES} bytes in flight, got {relayed}"
    );
    // Without credit the full window must hold: no further data leaves.
    assert!(
        source.wait_outbound(STALL_PROBE).is_err(),
        "source sent past its window without credit"
    );
    release_tx.send(()).unwrap();
    // Relay both ways as packets appear, as a session loop does. Credit only
    // comes back in eighth-window batches, so a pump that waited for credit
    // before relaying data the source already sent would wait forever.
    let deadline = Instant::now() + 4 * TIMEOUT;
    while relayed < TRANSFER_BYTES {
        assert!(
            Instant::now() < deadline,
            "transfer stalled after {relayed} bytes"
        );
        let mut moved = false;
        while let Some(confirmation) = destination.try_outbound().unwrap() {
            source.receive(confirmation).unwrap();
            moved = true;
        }
        while let Some(packet) = source.try_outbound().unwrap() {
            relayed += forwarded_bytes(&packet);
            destination.receive(packet).unwrap();
            moved = true;
        }
        if !moved {
            if let Ok(packet) = source.wait_outbound(Duration::from_millis(10)) {
                relayed += forwarded_bytes(&packet);
                destination.receive(packet).unwrap();
            }
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

/// Small request/response exchanges must not cost a window-credit packet
/// each way per exchange. Upstream sends none (it has no window); on a lossy
/// link every extra packet is another chance of a loss that cuts the
/// transport's congestion window right before the next bulk transfer. The
/// Windows threaded engine still returns a quiet socket's credit after 2 ms.
#[cfg(unix)]
#[test]
fn request_response_exchanges_return_no_credit_until_a_batch_drains() {
    /// Request/response exchanges, fewer than the 15-packet credit batch.
    const EXCHANGES: usize = 8;
    /// Quiet time after each exchange: three times the 50 ms after which an
    /// idle socket used to return the credit of every exchange.
    const QUIET: Duration = Duration::from_millis(150);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = listener.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 64];
        while let Ok(count @ 1..) = stream.read(&mut buffer) {
            if stream.write_all(&buffer[..count]).is_err() {
                break;
            }
        }
    });

    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(TIMEOUT)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();

    for exchange in 0..EXCHANGES {
        application.write_all(b"ping").unwrap();
        let request = source.wait_outbound(TIMEOUT).unwrap();
        assert_eq!(forwarded_bytes(&request), 4, "exchange {exchange} request");
        destination.receive(request).unwrap();
        let reply = destination.wait_outbound(TIMEOUT).unwrap();
        assert_eq!(forwarded_bytes(&reply), 4, "exchange {exchange} reply");
        source.receive(reply).unwrap();
        let mut echoed = [0_u8; 4];
        application.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");

        // Each side delivered one packet and went quiet.
        thread::sleep(QUIET);
        for (side, forwarder) in [("source", &source), ("destination", &destination)] {
            if let Some(packet) = forwarder.try_outbound().unwrap() {
                panic!(
                    "exchange {exchange}: {side} sent {:?} while idle",
                    PortForwardData::decode(packet.payload()).unwrap()
                );
            }
        }
    }

    drop(application);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
    echo.join().unwrap();
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
