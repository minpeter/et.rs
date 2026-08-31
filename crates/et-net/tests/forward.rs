#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{
    PortForwardDestinationRequest, PortForwardSourceRequest, SocketEndpoint, TerminalPacketType,
};
use et_net::forward::Forwarder;
use prost::Message;

const TIMEOUT: Duration = Duration::from_secs(3);
const REFUSED_DESTINATION_TIMEOUT: Duration = Duration::from_secs(7);

#[test]
fn two_forwarders_relay_a_real_tcp_round_trip() {
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = destination.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).unwrap();
        stream.write_all(&payload).unwrap();
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
    application.write_all(b"hello").unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    let mut echoed = [0u8; 5];
    application.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");

    drop(application);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
    echo.join().unwrap();
}

#[test]
fn refused_destination_closes_the_accepted_source() {
    let destination_port = reserve_port();
    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(TIMEOUT)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(
            destination
                .wait_outbound(REFUSED_DESTINATION_TIMEOUT)
                .unwrap(),
        )
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(application.read(&mut byte).unwrap(), 0);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
}

/// Regression test for the forwarder deadlock cycle: the worker can block
/// emitting outbound packets, which only the session loop drains, while a
/// blocking `receive` would leave the session loop stuck handing the worker
/// its next packet — wedging the session permanently. `try_receive` must
/// report a full worker instead of blocking, and draining outbound packets
/// (the session loop's next step) must make the held packet deliverable.
#[test]
fn hard_shutdown_cancels_worker_blocked_on_full_command_and_outbound_queues() {
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let request = |fd: i32| {
        Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: None,
                    port: Some(0),
                }),
                fd: Some(fd),
            }
            .encode_to_vec(),
        )
    };

    let mut held = None;
    for fd in 1..=4096 {
        if let Some(packet) = forwarder.try_receive(request(fd)).unwrap() {
            held = Some(packet);
            break;
        }
    }
    assert!(held.is_some(), "bounded forwarding queues never filled");

    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
    let worker = thread::spawn(move || done_tx.send(forwarder.shutdown_hard()).unwrap());
    assert!(done_rx.recv_timeout(TIMEOUT).unwrap().unwrap());
    worker.join().unwrap();
}

#[test]
fn try_receive_reports_backpressure_and_outbound_drain_recovers() {
    let forwarder = Forwarder::start(Vec::new()).unwrap();
    // Every destination request with an unparseable destination (port 0)
    // makes the worker emit exactly one error response. Nothing drains the
    // outbound queue yet, so the worker eventually blocks emitting and the
    // command queue fills — the exact state that used to deadlock.
    let request = |fd: i32| {
        Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: None,
                    port: Some(0),
                }),
                fd: Some(fd),
            }
            .encode_to_vec(),
        )
    };
    let mut delivered: usize = 0;
    let mut held = None;
    for fd in 1..=4096 {
        match forwarder.try_receive(request(fd)).unwrap() {
            None => delivered += 1,
            Some(packet) => {
                held = Some(packet);
                break;
            }
        }
    }
    // With a blocking send this loop would never return once both queues
    // filled; try_receive must surface the backpressure instead.
    let held = held.expect("the worker queues never filled");

    // Mirror the session loops: drain outbound, retry the held packet.
    let deadline = Instant::now() + TIMEOUT;
    let mut outbound: usize = 0;
    let mut held = Some(held);
    while let Some(packet) = held.take() {
        assert!(
            Instant::now() < deadline,
            "held packet was never accepted after draining outbound"
        );
        while forwarder.try_outbound().unwrap().is_some() {
            outbound += 1;
        }
        held = forwarder.try_receive(packet).unwrap();
        if held.is_some() {
            thread::sleep(Duration::from_millis(1));
        }
    }
    delivered += 1;

    // Every delivered request produces exactly one response; drain the rest
    // so the worker is idle before shutting down.
    while outbound < delivered {
        forwarder.wait_outbound(TIMEOUT).unwrap();
        outbound += 1;
    }
    forwarder.shutdown().unwrap();
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
            name: Some("127.0.0.1".to_owned()),
            port: Some(i32::from(source)),
        }),
        destination: Some(SocketEndpoint {
            name: Some("127.0.0.1".to_owned()),
            port: Some(i32::from(destination)),
        }),
        environmentvariable: None,
    }
}
