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
use et_net::forward::{ForwardError, ForwardOrigin, ForwardSource, Forwarder};
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

    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    let error = match Forwarder::start_with_user_report(
        vec![request_on(&Ipv4Addr::UNSPECIFIED.to_string(), port, 1)],
        Some(owner),
    ) {
        Ok((forwarder, _, _)) => {
            forwarder.shutdown().unwrap();
            panic!("authority failure was downgraded to a row report")
        }
        Err(error) => error,
    };
    match error {
        ForwardError::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        other => panic!("unexpected wildcard report result: {other}"),
    }

    if let Ok(ipv6_probe) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        drop(ipv6_probe);
        assert_authenticated_wildcard_rejected(
            Ipv6Addr::LOCALHOST.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            owner,
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn imported_local_wildcard_is_externally_reachable_while_loopback_is_not() {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
    let external = match probe.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() => address,
        address => panic!("route probe did not select a non-loopback IPv4 address: {address}"),
    };

    let loopback_port = reserve_port();
    let loopback = Forwarder::start(vec![request(loopback_port, 1)]).unwrap();
    assert!(
        TcpStream::connect_timeout(&SocketAddr::from((external, loopback_port)), TIMEOUT,).is_err()
    );
    loopback.shutdown().unwrap();

    let wildcard_port = reserve_port();
    let request = request_on("", wildcard_port, 1);
    let (wildcard, skipped) = Forwarder::start_with_origins(vec![ForwardSource {
        request,
        origin: ForwardOrigin::SshConfig,
    }])
    .unwrap();
    assert!(skipped.is_empty());
    let connection =
        TcpStream::connect_timeout(&SocketAddr::from((external, wildcard_port)), TIMEOUT).unwrap();
    drop(connection);
    wildcard.shutdown().unwrap();
}

#[cfg(unix)]
#[test]
fn reverse_listener_limit_is_transactional() {
    struct RemoveDir(std::path::PathBuf);
    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let directory = std::env::temp_dir().join(format!("etrl-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let _cleanup = RemoveDir(directory.clone());
    let paths: Vec<_> = (0..33)
        .map(|index| directory.join(format!("source-{index}.sock")))
        .collect();
    let requests = paths
        .iter()
        .map(|path| PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(path.to_string_lossy().into_owned()),
                port: None,
            }),
            destination: Some(SocketEndpoint {
                name: Some("/tmp/destination.sock".to_owned()),
                port: None,
            }),
            environmentvariable: None,
        })
        .collect();

    let error = match Forwarder::start(requests) {
        Ok(forwarder) => {
            forwarder.shutdown().unwrap();
            panic!("listener cap was not enforced");
        }
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("listener limit"),
        "unexpected error: {error}"
    );
    assert!(paths.iter().all(|path| !path.exists()));
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
    assert_eq!(reservations.len(), ports.len());
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
