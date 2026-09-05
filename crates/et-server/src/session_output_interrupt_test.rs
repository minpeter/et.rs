#![cfg(unix)]

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::connection::Connection;
use prost::Message;
use rustix::event::{poll, PollFd, PollFlags};

use super::ActiveSession;

const TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn prepared_terminal_and_synchronous_control_preserve_encrypted_frame_order() {
    // Given a real terminal frame paused after encryption but before socket send.
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
    let (prepared_tx, prepared_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    *session.prepared_write_hook.lock().unwrap() = Some((prepared_tx, release_rx));
    session.start_flow_writer();
    let terminal = terminal(b"terminal-first\n");
    session
        .send_packet(terminal.header(), terminal.payload())
        .unwrap();
    prepared_rx.recv_timeout(TIMEOUT).unwrap();

    // When synchronous control traffic arrives at that exact physical-write gap.
    // The lock probe only chooses a deterministic schedule, never the assertion:
    // before the fix the control send completes before releasing the first frame;
    // after the fix it must wait behind the physical writer.
    let writer_owned = match session.write_serial.try_lock() {
        Ok(guard) => {
            drop(guard);
            false
        }
        Err(std::sync::TryLockError::WouldBlock) => true,
        Err(error) => panic!("write lock poisoned: {error}"),
    };
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let sending = Arc::clone(&session);
    let control = control();
    let expected_control = control.clone();
    let sender = std::thread::spawn(move || {
        done_tx
            .send(sending.send_packet(control.header(), control.payload()))
            .unwrap();
    });
    if !writer_owned {
        done_rx.recv_timeout(TIMEOUT).unwrap().unwrap();
    }
    release_tx.send(()).unwrap();
    let first = client.read_packet();
    let second = client.read_packet();
    if writer_owned {
        done_rx.recv_timeout(TIMEOUT).unwrap().unwrap();
    }
    sender.join().unwrap();
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
    session.start_flow_writer();
    let first = terminal(b"replay prefix\n");
    session
        .send_packet(first.header(), first.payload())
        .unwrap();
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
    let (stream, _) = session.try_clone_stream().unwrap();
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
            let done = packet == prompt;
            packets.push(packet);
            if done {
                break;
            }
        }
        done_tx.send(packets).unwrap();
    });
    drop(permit);
    let packets = done_rx.recv_timeout(TIMEOUT).unwrap();
    reader.join().unwrap();
    session.shutdown().unwrap();
    packets
}
