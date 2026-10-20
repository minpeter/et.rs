#![forbid(unsafe_code)]

use et_core::flow_control::{FlowControlMode, OutputQueue};
use et_core::output_interrupt::{InterruptInput, TerminalStream};
use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalExitStatus, TerminalPacketType};
use prost::Message;

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
fn exit_status_survives_an_interrupt_flush_of_terminal_flood() {
    let mut queue = queue();
    let status = Packet::new(
        TerminalPacketType::TerminalExitStatus as u8,
        TerminalExitStatus {
            exitcode: Some(143),
        }
        .encode_to_vec(),
    );
    queue.push(status.clone()).unwrap();
    queue.push(terminal(&vec![b'x'; 80 * 1024])).unwrap();
    assert!(queue.flush_terminal_on_interrupt() > 0);
    let mut saw_status = false;
    while let Some(packet) = queue.pop() {
        if packet.header() == TerminalPacketType::TerminalExitStatus as u8 {
            let decoded = TerminalExitStatus::decode(packet.payload()).unwrap();
            assert_eq!(decoded.exitcode, Some(143));
            saw_status = true;
        }
    }
    assert!(saw_status);
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

#[test]
fn incomplete_tmux_records_remain_ordering_barriers_during_promotion() {
    for (fragment, ending) in [
        (b"%window-add @".as_slice(), b"2\n".as_slice()),
        (b"%begin 1 2\nreply\n".as_slice(), b"%end 1 2\n".as_slice()),
    ] {
        // Given a complete pane record followed by incomplete control output.
        let mut queue = queue();
        let pane = format!("%output %0 {}\n", "x".repeat(70 * 1024));
        queue.push(terminal(pane.as_bytes())).unwrap();
        queue.push(terminal(fragment)).unwrap();
        // When the writer drains before the control terminator arrives.
        let mut actual = drain(&mut queue);
        queue.push(terminal(ending)).unwrap();
        actual.extend(drain(&mut queue));
        // Then earlier pane bytes never become part of the incomplete record.
        assert_eq!(actual, [pane.as_bytes(), fragment, ending].concat());
    }
}

fn mid_line_control() -> TerminalStream {
    let mut stream = TerminalStream::default();
    stream.observe(b"%output %0 partial");
    stream
}

#[test]
fn mid_line_tmux_backlog_is_kept_without_recursion() {
    let stream = mid_line_control();
    let mut backlog = Vec::with_capacity(1 + 200_000 * 2);
    backlog.push(b'x');
    for _ in 0..200_000 {
        backlog.extend_from_slice(b"y\n");
    }
    let filtered = stream.filter(&backlog);
    assert_eq!(filtered.kept.len(), backlog.len());
    assert_eq!(filtered.dropped, 0);
}

#[test]
fn mid_line_prelude_keeps_lines_until_the_next_command() {
    let stream = mid_line_control();
    let data = b"aa\nbb\n%exit\n";
    assert_eq!(stream.filter(data).kept, data);
    assert_eq!(stream.filter(data).dropped, 0);
    let data = b"aa\nbb\n\n%foo\n";
    assert_eq!(stream.filter(data).kept, data);
    assert_eq!(stream.filter(data).dropped, 0);
}

#[test]
fn plain_percent_lines_do_not_enter_tmux_control_mode_or_reorder_output() {
    // Upstream #899: plain output like `top` (`%Cpu(s):`, `%MEM`) or a `% `
    // shell prompt must not latch tmux control mode or reorder lines.
    let mut stream = TerminalStream::default();
    let sample = b"PID USER\n%Cpu(s):  3.0 us\nload ok\n% echo prompt\n%MEM 41.2\nnext line\n";
    stream.observe(sample);
    assert_eq!(stream.promote_control(sample), None);

    let mut queue = queue();
    queue
        .push(terminal(b"%Cpu(s): 3.0 us\n% echo prompt\n"))
        .unwrap();
    assert!(queue.pop().is_some());

    let flood = format!(
        "PID USER\n%Cpu(s):  3.0 us\n% echo prompt\n{}\n%MEM 41.2\nnext line\n",
        "x".repeat(70 * 1024)
    );
    queue.push(terminal(flood.as_bytes())).unwrap();
    assert_eq!(drain(&mut queue), flood.as_bytes());

    queue.push(terminal(flood.as_bytes())).unwrap();
    assert_eq!(queue.flush_terminal_on_interrupt(), flood.len());
    assert!(drain(&mut queue).is_empty());
}

#[test]
fn dcs_introducer_and_exit_transition_tmux_control_mode_cleanly() {
    let mut queue = queue();
    queue
        .push(terminal(
            b"\x1bP1000p%begin 1 2\nresponse body\n%end 1 2\n%pane-mode-changed %0\n",
        ))
        .unwrap();
    assert!(queue.pop().is_some());

    // An interrupt flush before `ESC \` is delivered must preserve `%exit` and `ESC \`.
    let exit_flood = format!("%output %0 {}\n%exit\n\x1b\\\n", "z".repeat(70 * 1024));
    queue.push(terminal(exit_flood.as_bytes())).unwrap();
    assert!(queue.flush_terminal_on_interrupt() >= 70 * 1024);
    assert_eq!(drain(&mut queue), b"%exit\n\x1b\\\n");

    // After `ESC \`, the session returns to plain mode and does not reorder `%` lines.
    let plain = format!(
        "first line\n{}\n%Cpu(s): 1.0 us\nlast line\n",
        "p".repeat(70 * 1024)
    );
    queue.push(terminal(plain.as_bytes())).unwrap();
    assert_eq!(drain(&mut queue), plain.as_bytes());
}

#[test]
fn a_plain_exit_line_does_not_enter_tmux_control_mode() {
    // Upstream #900: `%exit` only ends control mode. Outside it, a line that
    // reads `%exit` is ordinary output, so later `%` lines must not survive
    // an interrupt as control data.
    let mut queue = queue();
    queue
        .push(terminal(b"$ printf '%%exit\\n'\n%exit\n"))
        .unwrap();
    assert!(queue.pop().is_some());

    let flood = format!("{}\n%Cpu(s): 1.0 us\n", "x".repeat(70 * 1024));
    queue.push(terminal(flood.as_bytes())).unwrap();
    assert_eq!(queue.flush_terminal_on_interrupt(), flood.len());
    assert!(drain(&mut queue).is_empty());
}
