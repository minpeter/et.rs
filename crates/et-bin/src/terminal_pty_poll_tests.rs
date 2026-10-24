use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{TermInit, TerminalBuffer, TerminalPacketType};
use et_net::local_packet::{
    write_local_packet, write_router_message, LocalPacketDecoder, RouterFraming,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use prost::Message;
use rustix::termios::{LocalModes, SpecialCodeIndex};

use super::{interrupts_output, PollPty};

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn interrupt_characters_follow_the_terminal_settings() {
    // Given: a fresh PTY with the kernel's default line discipline settings.
    let pair = native_pty_system().openpty(PtySize::default()).unwrap();
    let pty = PollPty::open(pair.master.as_ref()).expect("Linux poll runtime");
    let mut termios = rustix::termios::tcgetattr(&pty.master).unwrap();

    // Then: INTR, QUIT and SUSP signal the job and flush its output.
    assert!(interrupts_output(&termios, b"\x03"));
    assert!(interrupts_output(&termios, b"ls\x1c"));
    assert!(interrupts_output(&termios, b"\x1a"));
    assert!(!interrupts_output(&termios, b"plain input\r"));

    // And: a remapped interrupt character is the one that counts.
    termios.special_codes[SpecialCodeIndex::VINTR] = 0x18;
    assert!(interrupts_output(&termios, b"\x18"));
    assert!(!interrupts_output(&termios, b"\x03"));

    // And: no signal without ISIG (raw mode), and no flush with NOFLSH.
    termios.local_modes.remove(LocalModes::ISIG);
    assert!(!interrupts_output(&termios, b"\x18"));
    termios
        .local_modes
        .insert(LocalModes::ISIG | LocalModes::NOFLSH);
    assert!(!interrupts_output(&termios, b"\x18"));
}

/// While etterminal drained the PTY as fast as a flood refilled it, the
/// job's write never blocked, and the line discipline applies Ctrl+C only
/// once that write call ends: everything the job wrote meanwhile still
/// reached etserver (25 to 290 KB of a `yes` flood). Pausing reads blocks
/// the job on a full PTY, and the kernel flushes that tail.
#[test]
fn interrupt_into_a_flood_forwards_little_of_its_tail() {
    // Given: a terminal flooding output, read by a peer acting as etserver.
    let (router, mut peer) = et_net::local::wake_pair().unwrap();
    peer.set_read_timeout(Some(TIMEOUT)).unwrap();
    write_local_packet(
        &mut peer,
        &Packet::new(
            TerminalPacketType::TerminalInit as u8,
            TermInit::default().encode_to_vec(),
        ),
    )
    .unwrap();
    // `yes` prints "y" lines: each line is a separate PTY write inside one
    // long write call, which outlasts even a debug build's reads.
    let mut command = CommandBuilder::new("/bin/sh");
    command.args(["-c", "trap 'printf \"\\nINTERRUPTED\\n\"; exit 0' INT; yes"]);
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let result = super::super::run_with_command(
            router,
            "xterm",
            command,
            Duration::ZERO,
            RouterFraming::Upstream,
            None,
            |_| Ok(()),
        );
        done_tx.send(result).unwrap();
    });
    let mut decoder = LocalPacketDecoder::new();
    let mut flood = 0;
    while flood < 64 * 1024 {
        flood += flood_lines(&next_output(&mut peer, &mut decoder).unwrap());
    }

    // When: as etserver does on Ctrl+C, drain what is readable, then send the
    // interrupt.
    peer.set_nonblocking(true).unwrap();
    while next_output(&mut peer, &mut decoder).is_some() {}
    peer.set_nonblocking(false).unwrap();
    let interrupt = Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(b"\x03".to_vec()),
            is_stderr: None,
        }
        .encode_to_vec(),
    );
    write_router_message(&mut peer, &interrupt, RouterFraming::Upstream).unwrap();

    // Then: the job's reply to the interrupt arrives behind at most a frame
    // already read and the line discipline's read buffer of the flood.
    let mut tail = 0;
    let mut text: Vec<u8> = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while !text.windows(11).any(|window| window == b"INTERRUPTED") {
        assert!(
            Instant::now() < deadline,
            "the interrupted job never replied"
        );
        let output = next_output(&mut peer, &mut decoder).unwrap();
        tail += flood_lines(&output);
        text.extend(output.iter().filter(|byte| **byte != b'y'));
    }
    assert!(tail < 8 * 1024, "{tail} flood lines followed the interrupt");
    assert_eq!(done_rx.recv_timeout(TIMEOUT).unwrap(), Ok(0));
}

/// The next terminal output packet's bytes; `None` once `peer` has nothing
/// complete to read (nonblocking) or its read timeout passed.
fn next_output(
    peer: &mut et_net::local::LocalStream,
    decoder: &mut LocalPacketDecoder,
) -> Option<Vec<u8>> {
    loop {
        match decoder.read_from(peer) {
            Ok(Some(packet)) => {
                *decoder = LocalPacketDecoder::new();
                if packet.header() != TerminalPacketType::TerminalBuffer as u8 {
                    continue;
                }
                return Some(
                    TerminalBuffer::decode(packet.payload())
                        .unwrap()
                        .buffer
                        .unwrap_or_default(),
                );
            }
            Ok(None) => return None,
            Err(error) => panic!("reading terminal output failed: {error}"),
        }
    }
}

fn flood_lines(output: &[u8]) -> usize {
    output.iter().filter(|byte| **byte == b'y').count()
}
