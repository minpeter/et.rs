#![forbid(unsafe_code)]

use et_core::flow_control::{FlowControlMode, OutputQueue};
use et_core::output_interrupt::InterruptInput;
use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use prost::Message;

fn terminal(bytes: &[u8]) -> Packet {
    Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(bytes.to_vec()),
        }
        .encode_to_vec(),
    )
}

fn queue() -> OutputQueue {
    OutputQueue::new(FlowControlMode::Backpressure, 1024 * 1024)
}

fn drain(queue: &mut OutputQueue) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(packet) = queue.pop() {
        bytes.extend(
            TerminalBuffer::decode(packet.payload())
                .unwrap()
                .buffer
                .unwrap(),
        );
    }
    bytes
}

#[test]
fn prompt_is_next_when_large_unsent_flood_is_interrupted() {
    // Given: an unsent flood, with no encryption sequence assigned.
    let mut queue = queue();
    queue.push(terminal(&vec![b'x'; 200 * 1024])).unwrap();
    // When: an interrupt flushes it, followed by new shell output.
    assert_eq!(queue.flush_terminal_on_interrupt(), 200 * 1024);
    queue.push(terminal(b"ET_CTRL_C_OK")).unwrap();
    // Then: the prompt is next and all queue reservations are released.
    assert_eq!(drain(&mut queue), b"ET_CTRL_C_OK");
    assert_eq!(queue.bytes(), 0);
}

#[test]
fn small_output_is_preserved_when_interrupted() {
    for size in [0, 1, 64 * 1024 - 1] {
        // Given: output below the upstream 64KiB threshold.
        let mut queue = queue();
        let bytes = vec![b'x'; size];
        queue.push(terminal(&bytes)).unwrap();
        // When / Then: an interrupt leaves it byte-exact.
        assert_eq!(queue.flush_terminal_on_interrupt(), 0);
        assert_eq!(drain(&mut queue), bytes);
    }
}

#[test]
fn in_flight_and_control_packets_survive_when_unsent_terminal_is_flushed() {
    // Given: one taken packet and independently queued control traffic.
    let mut queue = queue();
    queue.push(terminal(b"already replay owned\n")).unwrap();
    let in_flight = queue.take().unwrap();
    let keepalive = Packet::new(TerminalPacketType::KeepAlive as u8, b"ack".as_slice());
    let forward = Packet::new(
        TerminalPacketType::PortForwardData as u8,
        b"data".as_slice(),
    );
    queue.push(keepalive.clone()).unwrap();
    queue.push(terminal(&vec![b'x'; 64 * 1024])).unwrap();
    queue.push(forward.clone()).unwrap();
    // When: only pending terminal output is flushed.
    assert_eq!(queue.flush_terminal_on_interrupt(), 64 * 1024);
    queue.complete(&in_flight);
    // Then: control order and in-flight capacity accounting remain valid.
    assert_eq!(queue.pop(), Some(keepalive));
    assert_eq!(queue.pop(), Some(forward));
    assert_eq!(queue.bytes(), 0);
}

#[test]
fn tmux_control_and_response_blocks_survive_when_pane_flood_is_flushed() {
    // Given: pane output split across packets, with a command response block.
    let mut queue = queue();
    queue.push(terminal(b"%out")).unwrap();
    queue
        .push(terminal(
            format!("put %0 {}\n%begin 1 2\n", "x".repeat(70 * 1024)).as_bytes(),
        ))
        .unwrap();
    queue
        .push(terminal(
            b"%output is response text\nplain response\n%end 1 2\n%layout-change @1 layout\n",
        ))
        .unwrap();
    // When: the large unsent pane stream is interrupted.
    assert!(queue.flush_terminal_on_interrupt() >= 70 * 1024);
    // Then: notifications and every response byte remain intact.
    assert_eq!(drain(&mut queue), b"%begin 1 2\n%output is response text\nplain response\n%end 1 2\n%layout-change @1 layout\n");
}

#[test]
fn partial_tmux_line_is_finished_when_its_prefix_was_already_taken() {
    // Given: a prefix already owned by the transport.
    let mut queue = queue();
    queue.push(terminal(b"%extended-output %0 0 : ")).unwrap();
    let sent = queue.take().unwrap();
    queue
        .push(terminal(
            format!(
                "{}\n%output %0 {}\n%window-add @1\n",
                "y".repeat(1024),
                "z".repeat(70 * 1024)
            )
            .as_bytes(),
        ))
        .unwrap();
    // When: interrupt cannot remove the prefix or its line continuation.
    assert!(queue.flush_terminal_on_interrupt() >= 70 * 1024);
    queue.complete(&sent);
    // Then: finish that line before the next notification.
    assert_eq!(
        drain(&mut queue),
        format!("{}\n%window-add @1\n", "y".repeat(1024)).as_bytes()
    );
}

#[test]
fn incomplete_dropped_tmux_line_is_skipped_until_its_newline() {
    // Given: the final pane line is incomplete at the interrupt.
    let mut queue = queue();
    queue
        .push(terminal(
            format!("%output %0 {}", "z".repeat(70 * 1024)).as_bytes(),
        ))
        .unwrap();
    // When: drop it, including a continuation arriving later.
    assert!(queue.flush_terminal_on_interrupt() > 0);
    queue.push(terminal(b"continuation")).unwrap();
    queue.push(terminal(b"\n%window-add @2\n")).unwrap();
    // Then: no orphan pane fragment leaks into the control stream.
    assert_eq!(drain(&mut queue), b"%window-add @2\n");
}

#[test]
fn response_block_is_preserved_when_begin_was_already_delivered() {
    // Given: a split response to a tmux control command.
    let mut queue = queue();
    queue.push(terminal(b"%begin 1 2\n")).unwrap();
    queue.pop().unwrap();
    let rest = format!("{}\n%end 1 2\n", "r".repeat(70 * 1024));
    queue.push(terminal(rest.as_bytes())).unwrap();
    // When / Then: response text is never treated as pane output.
    assert_eq!(queue.flush_terminal_on_interrupt(), 0);
    assert_eq!(drain(&mut queue), rest.as_bytes());
}

#[test]
fn interrupts_are_recognized_when_raw_or_split_tmux_commands_arrive() {
    // Given / When / Then: supported raw and tmux encodings request a flush.
    for input in [
        b"\x03".as_slice(),
        b"\x1a",
        b"\x1c",
        b"send-keys C-c\n",
        b"send -Ht %0 03\n",
        b"send -t %0 0x1a\r",
        b"send-keys ^C\n",
        b"send-keys C-\\\n",
    ] {
        assert!(InterruptInput::default().feed(input), "{input:?}");
    }
    let mut input = InterruptInput::default();
    assert!(!input.feed(b"send-keys -t %0 -H "));
    assert!(input.feed(b"03\n"));
}

#[test]
fn ordinary_input_is_preserved_when_it_mentions_interrupt_spellings() {
    // Given / When / Then: literal keys, target arguments and output are not interrupts.
    for input in [
        b"hello".as_slice(),
        b"send-keys -l C-c\n",
        b"send-keys 3\n",
        b"send-keys -t C-c hello\n",
        b"%output %0 send-keys -H 3\n",
        b"send-keys -H 41\n",
    ] {
        assert!(!InterruptInput::default().feed(input), "{input:?}");
    }
}

#[test]
fn tmux_responses_precede_queued_pane_flood_without_dropping_bytes() {
    // Given a saturated tmux stream with a response behind pane output.
    let mut queue = queue();
    let pane = format!("%output %0 {}\n", "x".repeat(70 * 1024));
    queue.push(terminal(pane.as_bytes())).unwrap();
    let response = b"%begin 1 2\nresponse\n%end 1 2\n";
    queue.push(terminal(response)).unwrap();
    // When the writer resumes before any interrupt can be issued by the UI.
    let bytes = drain(&mut queue);
    // Then the command response is available first; all pane bytes still follow.
    assert_eq!(bytes, [response.as_slice(), pane.as_bytes()].concat());
    assert_eq!(queue.bytes(), 0);
}
