#![forbid(unsafe_code)]

use std::io::{Read, Write};
#[cfg(unix)]
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{
    PortForwardDestinationRequest, PortForwardSourceRequest, SocketEndpoint, TerminalPacketType,
};
use et_net::forward::{ForwardError, Forwarder};
use prost::Message;

const TIMEOUT: Duration = Duration::from_secs(3);

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
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
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

#[cfg(unix)]
#[test]
fn reverse_tcp_bind_uses_session_identity() {
    let root = rustix::process::geteuid().as_raw() == 0;
    let source_port = if root { 1 } else { reserve_port() };
    let owner = (65_534, 65_534);

    let error = match Forwarder::start_with_user(vec![request(source_port, 1)], Some(owner)) {
        Ok((forwarder, _)) => {
            forwarder.shutdown().unwrap();
            panic!("TCP bind retained daemon authority");
        }
        Err(error) => error,
    };

    match error {
        ForwardError::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        other => panic!("unexpected TCP bind result: {other}"),
    }
}

#[cfg(unix)]
#[test]
fn authenticated_reverse_tcp_wildcard_bind_exposes_session_to_external_network() {
    let owner = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    assert_authenticated_wildcard_rejected(
        Ipv4Addr::LOCALHOST.into(),
        Ipv4Addr::UNSPECIFIED.into(),
        owner,
    );

    if let Ok(ipv6_probe) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        drop(ipv6_probe);
        assert_authenticated_wildcard_rejected(
            Ipv6Addr::LOCALHOST.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            owner,
        );
    }
}

#[test]
fn reverse_listener_limit_is_transactional() {
    let reservations: Vec<TcpListener> = (0..33)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let ports: Vec<u16> = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    let requests = ports.iter().map(|port| request(*port, 1)).collect();

    let error = match Forwarder::start(requests) {
        Ok(forwarder) => {
            forwarder.shutdown().unwrap();
            panic!("listener cap was not enforced");
        }
        Err(error) => error,
    };

    assert!(error.to_string().contains("listener limit"));
    drop(reservations);
    let rebound: Vec<TcpListener> = ports
        .iter()
        .map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).unwrap())
        .collect();
    assert_eq!(rebound.len(), 33);
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[cfg(unix)]
fn assert_authenticated_wildcard_rejected(loopback: IpAddr, wildcard: IpAddr, owner: (u32, u32)) {
    let reservation = TcpListener::bind((loopback, 0)).unwrap();
    let allowed_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let (allowed, _) = Forwarder::start_with_user(
        vec![request_on(&loopback.to_string(), allowed_port, 1)],
        Some(owner),
    )
    .unwrap();
    allowed.shutdown().unwrap();

    let reservations: Vec<TcpListener> = (0..2)
        .map(|_| TcpListener::bind((loopback, 0)).unwrap())
        .collect();
    let ports: Vec<u16> = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    drop(reservations);
    let error = match Forwarder::start_with_user(
        vec![
            request_on(&loopback.to_string(), ports[0], 1),
            request_on(&wildcard.to_string(), ports[1], 1),
        ],
        Some(owner),
    ) {
        Ok((forwarder, _)) => {
            forwarder.shutdown().unwrap();
            panic!("authenticated wildcard reverse bind was exposed")
        }
        Err(error) => error,
    };
    match error {
        ForwardError::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        other => panic!("unexpected wildcard bind result: {other}"),
    }
    let rebound: Vec<TcpListener> = [
        SocketAddr::new(loopback, ports[0]),
        SocketAddr::new(wildcard, ports[1]),
    ]
    .into_iter()
    .map(|address| TcpListener::bind(address).unwrap())
    .collect();
    assert_eq!(rebound.len(), ports.len());
}

fn request(source: u16, destination: u16) -> PortForwardSourceRequest {
    request_on("127.0.0.1", source, destination)
}

fn request_on(host: &str, source: u16, destination: u16) -> PortForwardSourceRequest {
    PortForwardSourceRequest {
        source: Some(SocketEndpoint {
            name: Some(host.to_owned()),
            port: Some(i32::from(source)),
        }),
        destination: Some(SocketEndpoint {
            name: Some("127.0.0.1".to_owned()),
            port: Some(i32::from(destination)),
        }),
        environmentvariable: None,
    }
}
