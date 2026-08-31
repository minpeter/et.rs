#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::sync::mpsc;
use std::thread;

use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectResponse, ConnectStatus, TerminalPacketType};
use et_net::connection::DEFAULT_LIVE_WRITE_TIMEOUT;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use et_net::local_packet::read_local_packet;
use et_server::SessionState;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};

#[test]
fn same_id_startup_is_newest_wins_then_returning() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (mut stale, stale_response) = server.handshake(ID_A);
    assert_eq!(stale_response.status, Some(ConnectStatus::NewClient as i32));

    let (new_stream, new_response) = server.handshake(ID_A);
    assert_eq!(new_response.status, Some(ConnectStatus::NewClient as i32));
    let mut probe = [0u8; 1];
    assert_eq!(std::io::Read::read(&mut stale, &mut probe).unwrap_or(0), 0);

    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(new_stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    let (returning_stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    client.recover(returning_stream).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    server.runtime.shutdown().unwrap();
}

#[test]
fn returning_client_receives_exact_buffered_server_catchup() {
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let initial_terminal_packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        initial_terminal_packet.header(),
        TerminalPacketType::TerminalInit as u8
    );

    client.shutdown().unwrap();
    server.handle.send_packet(ID_A, 31, b"buffer-one").unwrap();
    server.handle.send_packet(ID_A, 32, b"buffer-two").unwrap();

    let (returning, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    client.recover(returning).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    let first = client.read_packet().unwrap();
    let second = client.read_packet().unwrap();
    assert_eq!(
        (first.header(), first.payload()),
        (31, b"buffer-one".as_slice())
    );
    assert_eq!(
        (second.header(), second.payload()),
        (32, b"buffer-two".as_slice())
    );
    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"post-recovery")
        .unwrap();
    let forwarded = read_local_packet(&mut terminal).unwrap();
    assert_eq!(forwarded.header(), TerminalPacketType::TerminalInfo as u8);
    assert_eq!(forwarded.payload(), b"post-recovery");
    server.runtime.shutdown().unwrap();
}

#[test]
fn hard_client_drop_keeps_session_for_returning_recover() {
    // Regression: laptop sleep / Wi-Fi drop aborts the TCP socket. The server
    // used to tear the terminal down (bridge exit → session removed →
    // InvalidKey on reconnect). The session must stay Active so a returning
    // client recovers the same shell and any buffered catch-up.
    use std::net::Shutdown;

    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let initial_terminal_packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        initial_terminal_packet.header(),
        TerminalPacketType::TerminalInit as u8
    );

    // Hard-drop the OS socket (FIN/RST) without Connection::shutdown's local
    // bookkeeping — closer to what a sleeping laptop's stack does.
    client
        .try_clone_stream()
        .unwrap()
        .shutdown(Shutdown::Both)
        .unwrap();

    server.handle.send_packet(ID_A, 31, b"while-away").unwrap();
    server.handle.send_packet(ID_A, 32, b"still-here").unwrap();
    // Give the bridge a moment to observe the dead peer and soft-disconnect.
    thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(
        server.handle.session_state(ID_A).unwrap(),
        Some(SessionState::Active),
        "client transport loss must not remove the session"
    );

    let (returning, response) = server.handshake(ID_A);
    assert_eq!(
        response.status,
        Some(ConnectStatus::ReturningClient as i32),
        "expected ReturningClient after hard drop, got {response:?}"
    );
    client.recover(returning).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    let first = client.read_packet().unwrap();
    let second = client.read_packet().unwrap();
    assert_eq!(
        (first.header(), first.payload()),
        (31, b"while-away".as_slice())
    );
    assert_eq!(
        (second.header(), second.payload()),
        (32, b"still-here".as_slice())
    );
    server.runtime.shutdown().unwrap();
}

#[test]
fn repeated_recovery_does_not_let_stale_hup_disconnect_the_new_stream() {
    // Recover can both wake poll() with an old-socket HUP and read the first
    // post-recovery packets into BackedReader while authenticating the peer.
    // The stale event must not invalidate the new stream, and buffered input
    // must be drained even if the new socket has no remaining POLLIN state.
    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let initial_terminal_packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        initial_terminal_packet.header(),
        TerminalPacketType::TerminalInit as u8
    );

    for iteration in 0..32u8 {
        client.shutdown().unwrap();
        let (returning, response) = server.handshake(ID_A);
        assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
        client.recover(returning).unwrap();
        client
            .write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .unwrap();
        client
            .write_packet(TerminalPacketType::TerminalInfo as u8, &[iteration])
            .unwrap();
        let forwarded = read_local_packet(&mut terminal)
            .unwrap_or_else(|error| panic!("iteration {iteration}: {error}"));
        assert_eq!(forwarded.header(), TerminalPacketType::TerminalInfo as u8);
        assert_eq!(forwarded.payload(), &[iteration]);
    }

    server.runtime.shutdown().unwrap();
}

/// Regression: when the live client path blackholes (peer stops reading, no
/// FIN), terminal output used to block forever inside `write_all` while holding
/// the session mutex. Returning clients then sat behind that lock after
/// `ReturningClient` and timed out with "bootstrap timed out while recovering".
///
/// Flood the live socket without draining it, then recover on a new stream —
/// both the soft-disconnect write path and recover must finish within a tight
/// bound, proving the shipped mutex/write timeout path works end-to-end.
#[test]
fn recover_succeeds_while_old_peer_blackholes_writes() {
    use std::time::Instant;

    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let initial_terminal_packet = read_local_packet(&mut terminal).unwrap();
    assert_eq!(
        initial_terminal_packet.header(),
        TerminalPacketType::TerminalInit as u8
    );

    // Keep the client socket open but stop reading so the server's send buffer
    // fills and the bounded live write path soft-disconnects.
    let _live = client.try_clone_stream().unwrap();

    let payload = vec![b'x'; 32 * 1024];
    let mut timed_out_live_write = false;
    for round in 0..1_024u32 {
        let send_started = Instant::now();
        server
            .handle
            .send_packet(ID_A, 40, &payload)
            .unwrap_or_else(|error| panic!("flood round {round}: {error}"));
        let elapsed = send_started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(8),
            "send_packet round {round} blocked for {:?} — live write timeout not applied",
            elapsed
        );
        if elapsed >= DEFAULT_LIVE_WRITE_TIMEOUT / 2 {
            timed_out_live_write = true;
            break;
        }
    }
    assert!(
        timed_out_live_write,
        "socket flood never reached the bounded live-write timeout"
    );

    let recover_started = Instant::now();
    let (returning, response) = server.handshake(ID_A);
    assert_eq!(
        response.status,
        Some(ConnectStatus::ReturningClient as i32),
        "expected ReturningClient after blackhole, got {response:?}"
    );
    client.recover(returning).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    assert!(
        recover_started.elapsed() < std::time::Duration::from_secs(8),
        "recover took {:?} — session mutex still blocked by live write",
        recover_started.elapsed()
    );

    // Post-recovery traffic must flow on the new stream.
    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"after-blackhole")
        .unwrap();
    let forwarded = read_local_packet(&mut terminal).unwrap();
    assert_eq!(forwarded.header(), TerminalPacketType::TerminalInfo as u8);
    assert_eq!(forwarded.payload(), b"after-blackhole");
    server.runtime.shutdown().unwrap();
}

/// Concurrent returning clients must not stack for minutes on one recover.
/// While the first recover is mid-handshake (peer deliberately stalls after
/// ReturningClient), a second returning connection should still get a
/// response promptly instead of parking behind the session mutex forever.
#[test]
fn concurrent_returning_recover_does_not_block_accept_path() {
    use std::time::Instant;

    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let _ = read_local_packet(&mut terminal).unwrap();

    // First returning client: complete handshake to ReturningClient, then
    // stall without speaking recovery so the server is inside
    // ActiveSession::recover / exchange_recovery.
    let address = server.address;
    let stall = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        runtime_support::bound(&stream);
        write_proto(&mut stream, &client_request(ID_A)).unwrap();
        let response: ConnectResponse = read_proto_limited(&mut stream, 64 * 1024).unwrap();
        assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
        // Hold the TCP connection open without speaking recovery.
        thread::sleep(std::time::Duration::from_millis(500));
        // Closing ends the server's stalled recover promptly.
        drop(stream);
    });

    // Give the stalled recover a moment to enter ActiveSession::recover.
    thread::sleep(std::time::Duration::from_millis(50));

    // Second returning client must finish promptly. While the first recover
    // holds the single-flight permit the server drops the connection *without*
    // ReturningClient so the peer retries instead of entering sequence exchange.
    let second_started = Instant::now();
    let mut second_stream = std::net::TcpStream::connect(server.address).unwrap();
    runtime_support::bound(&second_stream);
    write_proto(&mut second_stream, &client_request(ID_A)).unwrap();
    let second_response: Result<ConnectResponse, _> =
        read_proto_limited(&mut second_stream, 64 * 1024);
    assert!(
        second_started.elapsed() < std::time::Duration::from_secs(2),
        "second reconnect attempt took {:?} — accept path blocked behind recover",
        second_started.elapsed()
    );
    // Either a fast ReturningClient (stall already finished) or a short-read /
    // error from the busy drop is acceptable; hanging is not.
    if let Ok(response) = second_response {
        assert_eq!(
            response.status,
            Some(ConnectStatus::ReturningClient as i32),
            "unexpected ConnectStatus for concurrent recover: {response:?}"
        );
    }
    drop(second_stream);

    stall.join().unwrap();
    // Allow the server recover worker to observe EOF and clear `recovering`.
    thread::sleep(std::time::Duration::from_millis(100));

    // A clean recover after the stall ends must still work on the shipped path.
    let (returning, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    client.recover(returning).unwrap();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"post-concurrent")
        .unwrap();
    let forwarded = read_local_packet(&mut terminal).unwrap();
    assert_eq!(forwarded.payload(), b"post-concurrent");
    server.runtime.shutdown().unwrap();
}

/// ANT-2026-VAMER5RC: a returning client that supplies an ahead-of-server
/// sequence must not close or displace the live victim session.
#[test]
fn failed_recover_leaves_live_session_intact() {
    use et_core::proto::SequenceHeader;
    use std::io::Write;

    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    terminal.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();
    let _ = read_local_packet(&mut terminal).unwrap();

    let address = server.address;
    let attacker = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        runtime_support::bound(&stream);
        write_proto(&mut stream, &client_request(ID_A)).unwrap();
        let response: ConnectResponse = read_proto_limited(&mut stream, 4 * 1024).unwrap();
        assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
        let _: SequenceHeader = read_proto_limited(&mut stream, 4 * 1024).unwrap();
        write_proto(
            &mut stream,
            &SequenceHeader {
                sequence_number: Some(999_999),
            },
        )
        .unwrap();
        // Hold the attack socket briefly so the server observes the bad sequence.
        thread::sleep(std::time::Duration::from_millis(200));
        let _ = stream.write(&[]);
    });

    attacker.join().unwrap();
    thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(
        server.handle.session_state(ID_A).unwrap(),
        Some(SessionState::Active)
    );

    client
        .write_packet(TerminalPacketType::TerminalInfo as u8, b"still-live")
        .unwrap();
    let forwarded = read_local_packet(&mut terminal).unwrap();
    assert_eq!(forwarded.payload(), b"still-live");
    server.runtime.shutdown().unwrap();
}

#[test]
fn keepalive_echo_acknowledges_everything_read_from_the_client() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut client, initial) = initialize(stream, &key, default_payload());
    assert_eq!(initial.error, None);
    server
        .handle
        .wait_for_state(ID_A, SessionState::Active, TIMEOUT)
        .unwrap();

    // An acknowledging keep-alive is echoed with the server's own ack: the
    // count of every packet the client has written (the server processes
    // packets in order, so by the time it echoes it has read them all).
    let ack = client.keepalive_ack();
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
        .unwrap();
    let written = client.writer_sequence();
    let echo = client.read_packet().unwrap();
    assert_eq!(echo.header(), TerminalPacketType::KeepAlive as u8);
    assert_eq!(
        et_core::keepalive::decode_ack(echo.payload()),
        Some(written)
    );

    // A legacy empty keep-alive still gets an echo.
    client
        .write_packet(TerminalPacketType::KeepAlive as u8, &[])
        .unwrap();
    let echo = client.read_packet().unwrap();
    assert_eq!(echo.header(), TerminalPacketType::KeepAlive as u8);
    server.runtime.shutdown().unwrap();
}

#[test]
fn library_shutdown_interrupts_partial_handshakes_and_joins_workers() {
    let mut server = TestRuntime::start();
    let path = server.dir.socket();
    let address = server.address;
    let _partial = std::net::TcpStream::connect(address).unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = server.runtime.shutdown();
        let _ = done_tx.send(result);
    });
    assert!(done_rx.recv_timeout(TIMEOUT).unwrap().is_ok());
    worker.join().unwrap();
    assert!(!path.exists());
    assert!(std::net::TcpStream::connect(address).is_err());
}
