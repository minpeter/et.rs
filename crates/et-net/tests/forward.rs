#![forbid(unsafe_code)]

use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(unix)]
use std::net::{IpAddr, Ipv6Addr};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{
    PortForwardData, PortForwardDestinationRequest, PortForwardSourceRequest, SocketEndpoint,
    TerminalPacketType,
};
#[cfg(unix)]
use et_net::forward::ForwardError;
use et_net::forward::Forwarder;
#[cfg(unix)]
use et_net::forward::{ForwardOrigin, ForwardSource};
use prost::Message;

const TIMEOUT: Duration = Duration::from_secs(3);
const REFUSED_DESTINATION_TIMEOUT: Duration = Duration::from_secs(7);
const HARD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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
    let response = wait_for_destination_response(&destination, &source);
    source.receive(response).unwrap();
    application.write_all(b"hello").unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    loop {
        let packet = destination.wait_outbound(TIMEOUT).unwrap();
        let reply = PortForwardData::decode(packet.payload())
            .ok()
            .and_then(|data| data.buffer)
            .is_some_and(|buffer| !buffer.is_empty());
        source.receive(packet).unwrap();
        if reply {
            break;
        }
    }
    let mut echoed = [0u8; 5];
    application.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");

    drop(application);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
    echo.join().unwrap();
}

#[test]
fn forwarded_tcp_delivers_reply_after_client_write_shutdown() {
    // Given: a real forwarded TCP stream to an echo server that replies only
    // after it observes EOF, then half-closes its own write side.
    const PAYLOAD_LEN: usize = 20 * 1024;
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|index| index as u8).collect();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = destination.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        stream.write_all(&received).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(TIMEOUT)).unwrap();
    application.set_write_timeout(Some(TIMEOUT)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();

    // When: the client writes the whole payload and half-closes its write side.
    application.write_all(&payload).unwrap();
    application.shutdown(Shutdown::Write).unwrap();
    relay_forward_data_until_close(&source, &destination);
    relay_forward_data_until_close(&destination, &source);

    // Then: the echoed bytes arrive byte-exact before EOF.
    let mut reply = Vec::new();
    application.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, payload);

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
                window: None,
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
    assert!(done_rx
        .recv_timeout(HARD_SHUTDOWN_TIMEOUT)
        .unwrap()
        .unwrap());
    worker.join().unwrap();
}

#[test]
fn hard_shutdown_cancels_active_destination_write_after_socket_backpressure() {
    // Given: a real forwarding destination accepts but never drains its socket.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let peer = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        socket2::SockRef::from(&stream)
            .set_recv_buffer_size(4096)
            .unwrap();
        accepted_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    let source_port = reserve_port();
    let mut source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let mut destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    accepted_rx.recv_timeout(TIMEOUT).unwrap();
    let application_writer = thread::spawn(move || {
        let payload = vec![7u8; 64 * 1024 * 1024];
        let _ = application.write_all(&payload);
    });

    // When: the destination's writer is blocked on socket I/O because its peer
    // never drains. Flow control throttles the SOURCE at the window, so the
    // old "flood until the destination's command queue is full" precondition
    // no longer forms on its own. Drive the destination into backpressure
    // directly: admit data until its bounded writer queue reports Full, which
    // is exactly the blocked-writer state hard cancellation must release.
    let held = loop {
        let packet = match source.wait_outbound(TIMEOUT) {
            Ok(packet) => packet,
            // The source parked at its window: the destination already holds
            // the window's worth of undelivered data, which is the same
            // backpressure. A held packet is not required to proceed.
            Err(_) => break None,
        };
        if let Some(held) = destination.try_receive(packet).unwrap() {
            break Some(held);
        }
    };
    drop(held);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
    let shutdown = thread::spawn(move || done_tx.send(destination.shutdown_hard()).unwrap());

    // Then: hard cancellation completes within the bound. Flow control keeps
    // the destination's undelivered backlog within the window, so whether any
    // bytes are reported abandoned depends on timing; what must hold is that
    // shutdown_hard itself finishes and releases the blocked writer, not the
    // pre-flow-control guarantee of a large abandoned backlog.
    let _abandoned = done_rx
        .recv_timeout(HARD_SHUTDOWN_TIMEOUT)
        .unwrap()
        .unwrap();
    shutdown.join().unwrap();
    source.shutdown_hard().unwrap();
    application_writer.join().unwrap();
    release_tx.send(()).unwrap();
    peer.join().unwrap();
}

#[test]
fn hard_shutdown_reports_admitted_socket_bytes_abandoned() {
    // Given: a destination writer is blocked by a peer that never drains, but
    // every forwarding command has crossed the worker boundary. The trailing
    // response is a FIFO barrier proving the outer command queue is empty.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let peer = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        socket2::SockRef::from(&stream)
            .set_recv_buffer_size(4096)
            .unwrap();
        accepted_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    let source_port = reserve_port();
    let mut source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let mut destination = Forwarder::start(Vec::new()).unwrap();
    let application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    let response_packet = destination.wait_outbound(TIMEOUT).unwrap();
    let response =
        et_core::proto::PortForwardDestinationResponse::decode(response_packet.payload()).unwrap();
    let socket_id = response.socketid.unwrap();
    source.receive(response_packet).unwrap();
    accepted_rx.recv_timeout(TIMEOUT).unwrap();
    let data_packet = || {
        Packet::new(
            TerminalPacketType::PortForwardData as u8,
            et_core::proto::PortForwardData {
                sourcetodestination: Some(true),
                socketid: Some(socket_id),
                buffer: Some(vec![9u8; 64 * 1024]),
                error: None,
                closed: None,
                window: None,
            }
            .encode_to_vec(),
        )
    };
    for _ in 0..65 {
        destination.receive(data_packet()).unwrap();
    }
    destination
        .receive(Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: None,
                    port: Some(0),
                }),
                fd: Some(777),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let barrier = wait_for_destination_response(&destination, &source);
    let barrier =
        et_core::proto::PortForwardDestinationResponse::decode(barrier.payload()).unwrap();
    assert_eq!(barrier.clientfd, Some(777));
    assert!(barrier.error.is_some());

    // When: hard shutdown aborts the admitted writer queue and in-flight write.
    let abandoned = destination.shutdown_hard().unwrap();

    // Then: payload ownership loss is reported even though outer lanes drained.
    release_tx.send(()).unwrap();
    peer.join().unwrap();
    drop(application);
    source.shutdown_hard().unwrap();
    assert!(
        abandoned,
        "hard shutdown discarded admitted socket bytes without reporting abandonment"
    );
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
                window: None,
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
fn imported_local_bind_failure_obeys_strict_policy_transactionally() {
    // Given
    struct RemoveDir(std::path::PathBuf);
    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!("et-fp-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let _cleanup = RemoveDir(directory.clone());
    let usable_path = directory.join("usable.sock");
    let occupied_path = directory.join("occupied.sock");
    let occupied = std::os::unix::net::UnixListener::bind(&occupied_path).unwrap();
    let imported = |path: &std::path::Path, strict| ForwardSource {
        request: PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(path.to_string_lossy().into_owned()),
                port: None,
            }),
            destination: Some(SocketEndpoint {
                name: Some("/tmp/destination.sock".to_owned()),
                port: None,
            }),
            environmentvariable: None,
        },
        origin: ForwardOrigin::SshConfig { strict },
    };

    // When: nonfatal import contains one occupied row.
    let (forwarder, skipped) = Forwarder::start_with_origins(vec![
        imported(&usable_path, false),
        imported(&occupied_path, false),
    ])
    .unwrap();

    // Then: one warning record remains and the usable sibling stays bound.
    assert_eq!(skipped.len(), 1);
    assert!(usable_path.exists());
    forwarder.shutdown().unwrap();

    // When: strict import contains the same occupied row after a usable sibling.
    let error = match Forwarder::start_with_origins(vec![
        imported(&usable_path, true),
        imported(&occupied_path, true),
    ]) {
        Ok((forwarder, _)) => {
            forwarder.shutdown().unwrap();
            panic!("strict imported bind failure was downgraded")
        }
        Err(error) => error,
    };

    // Then: strict setup fails and rolls the provisional sibling back.
    assert!(matches!(error, ForwardError::Io(_)));
    assert!(!usable_path.exists());
    drop(occupied);
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
    let error = match Forwarder::start_with_user(
        vec![request_on(&Ipv4Addr::UNSPECIFIED.to_string(), port, 1)],
        Some(owner),
    ) {
        Ok((forwarder, _)) => {
            forwarder.shutdown().unwrap();
            panic!("authority failure was not fatal")
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
fn authenticated_reverse_tcp_accepts_resolved_non_loopback_address() {
    // Given
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
    let external = match probe.local_addr().unwrap().ip() {
        IpAddr::V4(address) if !address.is_loopback() => address,
        address => panic!("route probe did not select a non-loopback IPv4 address: {address}"),
    };
    let owner = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let reservation = TcpListener::bind((external, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    // When
    let (forwarder, _) = Forwarder::start_with_user(
        vec![request_on(&external.to_string(), port, 1)],
        Some(owner),
    )
    .unwrap();
    let connection =
        TcpStream::connect_timeout(&SocketAddr::from((external, port)), TIMEOUT).unwrap();

    // Then
    drop(connection);
    forwarder.shutdown().unwrap();
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
        origin: ForwardOrigin::SshConfig { strict: false },
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
fn local_forwarding_exceeds_reverse_cap_while_reverse_limit_is_transactional() {
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
    let requests: Vec<PortForwardSourceRequest> = paths
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

    // When: client-local forwarding owns more than the server reverse cap.
    let local = Forwarder::start(requests.clone()).unwrap();

    // Then: every local listener is usable and cleanup is deterministic.
    assert!(paths.iter().all(|path| path.exists()));
    local.shutdown().unwrap();
    assert!(paths.iter().all(|path| !path.exists()));

    // When: the same multiset is requested as authenticated server reverse forwarding.
    let owner = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let error = match Forwarder::start_with_user(requests, Some(owner)) {
        Ok((forwarder, _)) => {
            forwarder.shutdown().unwrap();
            panic!("reverse listener cap was not enforced");
        }
        Err(error) => error,
    };

    // Then: the cap fails transactionally before any sibling bind.
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

fn port_forward_data_closed(packet: &Packet) -> bool {
    if packet.header() != TerminalPacketType::PortForwardData as u8 {
        return false;
    }
    et_core::proto::PortForwardData::decode(packet.payload())
        .ok()
        .is_some_and(|data| data.closed.unwrap_or(false) || data.error.is_some())
}

fn wait_for_destination_response(from: &Forwarder, peer: &Forwarder) -> Packet {
    loop {
        let packet = from.wait_outbound(TIMEOUT).unwrap();
        if packet.header() == TerminalPacketType::PortForwardDestinationResponse as u8 {
            return packet;
        }
        peer.receive(packet).unwrap();
    }
}

fn relay_forward_data_until_close(from: &Forwarder, to: &Forwarder) {
    loop {
        let packet = from.wait_outbound(TIMEOUT).unwrap();
        let closed = port_forward_data_closed(&packet);
        to.receive(packet).unwrap();
        if closed {
            break;
        }
    }
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
