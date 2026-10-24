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
        output.run().deadline.is_some(),
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
    assert!(output.run().deadline.is_none());
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

#[test]
fn output_interrupt_discards_output_the_terminal_already_emitted() {
    assert_interrupt_discards_emitted_output(BridgeMode::Terminal(RouterFraming::Packets));
}

#[test]
fn output_interrupt_discards_output_the_jump_terminal_already_relayed() {
    assert_interrupt_discards_emitted_output(BridgeMode::Jumphost);
}

fn assert_interrupt_discards_emitted_output(mode: BridgeMode) {
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
    while session.can_buffer_write(32 * 1024).unwrap() {
        session
            .send_packet(queued.header(), queued.payload())
            .unwrap();
    }
    let emitted = terminal(&[b'y'; 16 * 1024]);
    write_local_packet(&mut terminal_peer, &emitted).unwrap();
    write_local_packet(&mut terminal_peer, &emitted).unwrap();
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
