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
