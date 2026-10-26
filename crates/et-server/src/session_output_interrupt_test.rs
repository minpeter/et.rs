#![cfg(unix)]

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalExitStatus, TerminalPacketType};
use et_net::connection::Connection;
use et_net::forward::Forwarder;
use et_net::local_packet::{read_local_packet, write_local_packet, RouterFraming};
use prost::Message;
use rustix::event::{poll, PollFd, PollFlags};

use super::{ActiveSession, OutputPump};
use crate::terminal_bridge::BridgeMode;

const TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn pending_terminal_frame_and_synchronous_control_preserve_encrypted_frame_order() {
    // Given a real terminal frame the session loop has only partly written.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut client = Connection::new_client(client, &[7; 32]);
    client.set_io_timeout(Some(TIMEOUT)).unwrap();
    let (terminal_socket, _peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            Connection::new_server(server, &[7; 32]),
            &terminal_socket,
            None,
        )
        .unwrap(),
    );
    session
        .connection
        .lock()
        .unwrap()
        .shrink_transport_window_for_tests(4 * 1024)
        .unwrap();
    session.start_output();
    let mut output = OutputPump::new(&session);
    let terminal = terminal(&vec![b't'; 60 * 1024]);
    session
        .send_packet(terminal.header(), terminal.payload())
        .unwrap();
    assert!(
        output.run(true).deadline.is_some(),
        "the terminal frame must wait for transport room"
    );

    // When synchronous control traffic is sent before that frame completes.
    let sending = Arc::clone(&session);
    let control = control();
    let expected_control = control.clone();
    let sender =
        std::thread::spawn(move || sending.send_packet(control.header(), control.payload()));
    let first = client.read_packet();
    let second = client.read_packet();
    sender.join().unwrap().unwrap();
    // The synchronous writer finished the loop's frame; nothing is left.
    assert!(output.run(true).deadline.is_none());
    drop(output);
    session.shutdown().unwrap();

    // Then the actual peer decrypts whole frames in their assigned nonce order.
    assert_eq!(first.unwrap(), terminal);
    assert_eq!(second.unwrap(), expected_control);
}

fn terminal(bytes: &[u8]) -> Packet {
    Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(bytes.to_vec()),

            is_stderr: None,
        }
        .encode_to_vec(),
    )
}

#[test]
fn output_interrupt_default_runtime_flushes_only_unsent_packets() {
    // Given / When: a large unsequenced flood and Ctrl+C traverse a native
    // encrypted session; the recovery admission permit is only a queue gate.
    let packets = output_after_interrupt(&vec![b'x'; 128 * 1024]);
    // Then: the client decrypts control and the subsequent prompt, not flood.
    assert_eq!(
        packets,
        vec![control(), terminal(b"ET_CTRL_C_OK")],
        "interrupted unsent flood reached the encrypted client"
    );
}

#[test]
fn output_interrupt_preserves_small_terminal_output() {
    // Given / When: the same real transport path with less than 64KiB pending.
    let packets = output_after_interrupt(b"small output\n");
    // Then: terminal bytes survive exactly; the control packet also survives.
    let mut bytes = Vec::new();
    let mut controls = Vec::new();
    for packet in packets {
        if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
            bytes.extend(
                TerminalBuffer::decode(packet.payload())
                    .unwrap()
                    .buffer
                    .unwrap(),
            );
        } else {
            controls.push(packet);
        }
    }
    assert_eq!(bytes, b"small output\nET_CTRL_C_OK");
    assert_eq!(controls, vec![control()]);
}

/// Upstream `drainWriteBufferToClient` starts a packet only while the client
/// socket is writable. The session loop used to write until the kernel
/// refused more, leaving one frame partly sent and already sequenced, so
/// Ctrl+C could not drop it and a slow link delivered it before the prompt.
#[cfg(target_os = "linux")]
#[test]
fn output_waits_for_transport_room_before_starting_a_frame() {
    // Given: a session flooding a client that stopped reading.
    let (session, mut client) = session_pair();
    let mut output = OutputPump::new(&session);
    let (stream, _) = session.try_clone_stream().unwrap();
    let flood = flood_lines();

    // When: the session loop writes until it has to wait for the client.
    flood_until_no_room(&session, &mut output, &flood);

    // Then: no frame is left partly written; the flood that found no room
    // is still queued and unsequenced.
    let sequenced = {
        let connection = session.connection.lock().unwrap();
        assert!(
            !connection.write_pending(),
            "a frame started without transport room"
        );
        connection.writer_sequence()
    };

    // And: Ctrl+C drops all of it, so the client sees only the frames the
    // kernel had taken before, then the prompt.
    for _ in 0..8 {
        session
            .send_packet(flood.header(), flood.payload())
            .unwrap();
    }
    let interrupt = terminal(b"\x03");
    client
        .write_packet(interrupt.header(), interrupt.payload())
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let input = loop {
        if let Some(packet) = session.try_read_packet().unwrap() {
            break packet;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("encrypted interrupt was not readable before deadline");
        let timeout = rustix::time::Timespec::try_from(remaining).unwrap();
        let mut descriptors = [PollFd::new(&stream, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => panic!("interrupt readiness failed: {error}"),
        }
    };
    assert_eq!(input, interrupt);
    let prompt = terminal(b"ET_CTRL_C_OK");
    session
        .send_packet(prompt.header(), prompt.payload())
        .unwrap();
    let reader = std::thread::spawn(move || {
        let mut packets = Vec::new();
        loop {
            let packet = client.read_packet().unwrap();
            let done = packet == prompt;
            packets.push(packet);
            if done {
                return packets;
            }
        }
    });
    output.run_until_idle(&stream);
    let packets = reader.join().unwrap();
    drop(output);
    session.shutdown().unwrap();
    assert_eq!(packets.len() as i64, sequenced + 1);
    assert!(packets[..packets.len() - 1]
        .iter()
        .all(|packet| *packet == flood));
}

/// Output that waited a whole live-write timeout for transport room starts
/// its frame with that deadline already spent, so a client that never drains
/// still fails as a stuck frame did when every frame started at once.
#[cfg(target_os = "linux")]
#[test]
fn output_without_room_for_a_live_write_timeout_starts_an_expired_frame() {
    use super::session_flow::writer::{write_nonblocking, NonblockingWrite};
    use et_net::connection::FLOW_CONTROL_LIVE_WRITE_TIMEOUT;

    // Given: a client that stopped reading and a transport that no longer
    // takes bytes (a raw fill; nothing reads this stream as frames).
    let (session, _client) = session_pair();
    session
        .connection
        .lock()
        .unwrap()
        .shrink_transport_window_for_tests(4 * 1024)
        .unwrap();
    let (stream, _) = session.try_clone_stream().unwrap();
    loop {
        match rustix::net::send(&stream, &[0; 4096], rustix::net::SendFlags::DONTWAIT) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => break,
            Err(error) => panic!("filling the transport failed: {error}"),
        }
    }
    let flood = flood_lines();
    let flow = session.output_flow().unwrap();
    let sequenced = session.connection.lock().unwrap().writer_sequence();

    // When: it has waited for less than the live-write timeout.
    let mut room_wait = Some(Instant::now());
    let waiting = write_nonblocking(&session, flow, &flood, false, &mut room_wait);
    // Then: nothing starts.
    assert!(matches!(waiting, NonblockingWrite::NoRoom(_)));
    assert_eq!(
        session.connection.lock().unwrap().writer_sequence(),
        sequenced
    );

    // When: it has waited for the whole timeout.
    let mut room_wait = Instant::now().checked_sub(FLOW_CONTROL_LIVE_WRITE_TIMEOUT);
    let started = write_nonblocking(&session, flow, &flood, false, &mut room_wait);
    // Then: the frame starts, its live-write deadline already due.
    let NonblockingWrite::Pending(deadline) = started else {
        panic!("a frame must start once output waited a live-write timeout");
    };
    assert!(deadline <= Instant::now());
    assert_eq!(room_wait, None);
    assert_eq!(
        session.connection.lock().unwrap().writer_sequence(),
        sequenced + 1
    );
    session.shutdown().unwrap();
}

#[cfg(target_os = "linux")]
fn session_pair() -> (Arc<ActiveSession>, Connection) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let client = Connection::new_client(client, &[7; 32]);
    client.set_io_timeout(Some(TIMEOUT)).unwrap();
    let (terminal_socket, _peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            Connection::new_server(server, &[7; 32]),
            &terminal_socket,
            None,
        )
        .unwrap(),
    );
    session.start_output();
    (session, client)
}

/// 16 KiB of whole lines, so dropping it never cuts a line the client saw.
#[cfg(target_os = "linux")]
fn flood_lines() -> Packet {
    let mut line = vec![b'x'; 63];
    line.push(b'\n');
    terminal(&line.repeat(256))
}

/// Queue `flood` and pump until the session loop has to wait for a client
/// that never reads.
#[cfg(target_os = "linux")]
fn flood_until_no_room(session: &ActiveSession, output: &mut OutputPump<'_>, flood: &Packet) {
    let mut rounds = 0;
    while output.run(true).deadline.is_none() {
        rounds += 1;
        assert!(
            rounds < 4096,
            "a client that never reads must fill the transport"
        );
        for _ in 0..4 {
            session
                .send_packet(flood.header(), flood.payload())
                .unwrap();
        }
    }
}

#[test]
fn output_interrupt_discards_output_the_terminal_already_emitted() {
    assert_interrupt_discards_emitted_output(BridgeMode::Terminal(RouterFraming::Packets), false);
}

#[test]
fn output_interrupt_discards_output_the_jump_terminal_already_relayed() {
    assert_interrupt_discards_emitted_output(BridgeMode::Jumphost, false);
}

#[test]
fn output_interrupt_discards_emitted_output_the_bridge_read_ahead() {
    assert_interrupt_discards_emitted_output(BridgeMode::Terminal(RouterFraming::Packets), true);
    assert_interrupt_discards_emitted_output(BridgeMode::Jumphost, true);
}

/// With `read_ahead`, the lane keeps room for one more frame: the bridge's
/// one socket read takes every emitted packet, it queues the first and holds
/// the rest read ahead when the interrupt arrives.
fn assert_interrupt_discards_emitted_output(mode: BridgeMode, read_ahead: bool) {
    // Given: a default-buffered session whose terminal lane is full of unsent
    // flood. More flood and then an exit status wait on the terminal socket,
    // which the bridge does not read while the lane refuses output.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut client = Connection::new_client(client, &[7; 32]);
    client.set_io_timeout(Some(TIMEOUT)).unwrap();
    let (terminal_socket, mut terminal_peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            Connection::new_server(server, &[7; 32]),
            &terminal_socket,
            None,
        )
        .unwrap(),
    );
    session.set_forward_exit_status(true);
    session.start_output();
    // Recovery admission holds output in the queue, so the lane stays full
    // without depending on socket timing.
    let permit = session.try_begin_recover().unwrap();
    let queued = terminal(&[b'x'; 16 * 1024]);
    let room = if read_ahead { 48 * 1024 } else { 32 * 1024 };
    while session.can_buffer_write(room).unwrap() {
        session
            .send_packet(queued.header(), queued.payload())
            .unwrap();
    }
    if read_ahead {
        assert!(session.can_buffer_write(32 * 1024).unwrap());
    }
    let emitted = terminal(&[b'y'; 16 * 1024]);
    for _ in 0..3 {
        write_local_packet(&mut terminal_peer, &emitted).unwrap();
    }
    let exit_status = Packet::new(
        TerminalPacketType::TerminalExitStatus as u8,
        TerminalExitStatus {
            exitcode: Some(130),
        }
        .encode_to_vec(),
    );
    write_local_packet(&mut terminal_peer, &exit_status).unwrap();
    let interrupt = terminal(b"\x03");
    client
        .write_packet(interrupt.header(), interrupt.payload())
        .unwrap();
    let bridge_session = Arc::clone(&session);
    let bridge = std::thread::spawn(move || {
        crate::terminal_bridge::run_mode(
            bridge_session,
            terminal_socket,
            Forwarder::start(Vec::new()).unwrap(),
            mode,
        )
    });

    // When: Ctrl+C reaches the terminal, which answers with a prompt once
    // the client has seen the exit status.
    let (interrupted_tx, interrupted_rx) = mpsc::sync_channel(1);
    let (prompt_tx, prompt_rx) = mpsc::sync_channel::<()>(1);
    let prompt = terminal(b"ET_CTRL_C_OK");
    let terminal_prompt = prompt.clone();
    // The terminal answers the interrupt at once (an echo), before the
    // bridge can have finished dropping what it emitted earlier.
    let echo = terminal(b"^C\r\n");
    let terminal_echo = echo.clone();
    let local = std::thread::spawn(move || {
        let interrupt = read_local_packet(&mut terminal_peer).unwrap();
        write_local_packet(&mut terminal_peer, &terminal_echo).unwrap();
        interrupted_tx.send(interrupt).unwrap();
        prompt_rx.recv_timeout(TIMEOUT).unwrap();
        write_local_packet(&mut terminal_peer, &terminal_prompt).unwrap();
        terminal_peer
    });
    assert_eq!(interrupted_rx.recv_timeout(TIMEOUT).unwrap(), interrupt);
    drop(permit);
    // The exit status the terminal emitted before the interrupt and the echo
    // it wrote after are independent; either may arrive first.
    let mut delivered = Vec::new();
    while !(delivered.contains(&exit_status) && delivered.contains(&echo)) {
        delivered.push(client.read_packet().unwrap());
    }
    prompt_tx.send(()).unwrap();
    delivered.push(client.read_packet().unwrap());
    let _terminal_peer = local.join().unwrap();
    session.shutdown().unwrap();
    bridge.join().unwrap().unwrap();

    // Then: neither the queued nor the already-emitted flood reaches the
    // client; the exit status, the echo written after the interrupt and the
    // later prompt do, in order.
    assert_eq!(
        delivered.len(),
        3,
        "interrupted flood reached the encrypted client"
    );
    assert_eq!(delivered.last(), Some(&prompt));
}

fn control() -> Packet {
    Packet::new(TerminalPacketType::KeepAlive as u8, b"control".as_slice())
}

fn output_after_interrupt(bytes: &[u8]) -> Vec<Packet> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut client = Connection::new_client(client, &[7; 32]);
    client.set_io_timeout(Some(TIMEOUT)).unwrap();
    let (terminal_socket, _peer) = et_net::local::wake_pair().unwrap();
    let session = Arc::new(
        ActiveSession::new(
            Connection::new_server(server, &[7; 32]),
            &terminal_socket,
            None,
        )
        .unwrap(),
    );
    session.start_output();
    let mut output = OutputPump::new(&session);
    let (stream, _) = session.try_clone_stream().unwrap();
    let first = terminal(b"replay prefix\n");
    session
        .send_packet(first.header(), first.payload())
        .unwrap();
    output.run_until_idle(&stream);
    assert_eq!(client.read_packet().unwrap(), first);

    // Existing recovery admission deterministically retains output before any
    // sequence is assigned. No socket timing or writer callback is asserted.
    let permit = session.try_begin_recover().unwrap();
    for chunk in bytes.chunks(16 * 1024) {
        let packet = terminal(chunk);
        session
            .send_packet(packet.header(), packet.payload())
            .unwrap();
    }
    let control = control();
    session
        .send_packet(control.header(), control.payload())
        .unwrap();

    let interrupt = terminal(b"\x03");
    client
        .write_packet(interrupt.header(), interrupt.payload())
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let input = loop {
        if let Some(packet) = session.try_read_packet().unwrap() {
            break packet;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("encrypted interrupt was not readable before deadline");
        let timeout = rustix::time::Timespec::try_from(remaining).unwrap();
        let mut descriptors = [PollFd::new(&stream, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => panic!("interrupt readiness failed: {error}"),
        }
    };
    assert_eq!(input, interrupt);
    let prompt = terminal(b"ET_CTRL_C_OK");
    session
        .send_packet(prompt.header(), prompt.payload())
        .unwrap();

    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut packets = Vec::new();
        loop {
            let packet = client.read_packet().unwrap();
            // Output still queued behind the interrupt may share the
            // prompt's packet (the queue merges terminal output).
            let done = packet == prompt
                || et_core::packet::decode_terminal_buffer(packet.payload())
                    .is_some_and(|(bytes, _)| bytes.ends_with(b"ET_CTRL_C_OK"));
            packets.push(packet);
            if done {
                break;
            }
        }
        done_tx.send(packets).unwrap();
    });
    drop(permit);
    output.run_until_idle(&stream);
    let packets = done_rx.recv_timeout(TIMEOUT).unwrap();
    reader.join().unwrap();
    drop(output);
    session.shutdown().unwrap();
    packets
}
