use prost::Message;

use crate::flow_control::{
    FlowControlMode, OutputLane, OutputQueue, QueuePushError, COALESCED_TERMINAL_BYTES,
    MAX_PACKETS_PER_LANE,
};
use crate::packet::{
    append_terminal_buffer, decode_terminal_buffer, encode_terminal_buffer, Packet,
};
use crate::proto::{TerminalBuffer, TerminalPacketType};

const LIMIT: usize = 64;

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

fn control(payload: &[u8]) -> Packet {
    Packet::new(TerminalPacketType::KeepAlive as u8, payload)
}

fn forwarding(payload: &[u8]) -> Packet {
    Packet::new(TerminalPacketType::PortForwardData as u8, payload)
}

#[test]
fn backpressure_is_lossless_and_refuses_capacity_overflow() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);
    let first = terminal(&[1; 40]);
    let second = terminal(&[2; 40]);

    assert!(queue.push(first.clone()).is_ok());
    assert_eq!(
        queue.push(second.clone()),
        Err(QueuePushError::Full(second))
    );
    assert_eq!(queue.pop(), Some(first));
    assert_eq!(queue.pop(), None);
}

#[test]
fn discard_drops_oldest_terminal_output_and_keeps_newest() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, LIMIT);
    let oldest = terminal(&[1; 40]);
    let newest = terminal(&[2; 40]);

    assert!(queue.push(oldest).is_ok());
    assert!(queue.push(newest.clone()).is_ok());
    assert_eq!(queue.pop(), Some(newest));
    assert_eq!(queue.pop(), None);
}

#[test]
fn control_has_reserved_capacity_and_does_not_evict_terminal_output() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, LIMIT);
    let output = terminal(&[1; 40]);
    let keepalive = control(&[9; 40]);

    assert!(queue.push(output.clone()).is_ok());
    assert!(queue.push(keepalive.clone()).is_ok());
    assert_eq!(queue.pop(), Some(output));
    assert_eq!(queue.pop(), Some(keepalive));
}

#[test]
fn oversized_terminal_packet_truncates_decoded_bytes_and_reencodes() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, LIMIT);
    let oversized = terminal(&(0u8..100).collect::<Vec<_>>());

    assert!(queue.push(oversized).is_ok());
    let packet = queue.pop().unwrap();
    let decoded = TerminalBuffer::decode(packet.payload()).unwrap();
    let retained = decoded.buffer.unwrap();
    assert_eq!(retained, (44u8..100).collect::<Vec<_>>());
    assert!(queue.bytes() <= LIMIT);
}

#[test]
fn oversized_control_is_permanent_not_temporary_full() {
    let packet = control(&[0; LIMIT]);
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);

    assert_eq!(
        queue.push(packet.clone()),
        Err(QueuePushError::Oversized(packet))
    );
}

#[test]
fn framing_bytes_are_included_in_capacity() {
    let packet = control(&[0; LIMIT - crate::packet::HEADER_LEN]);
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);

    assert_eq!(
        queue.push(packet.clone()),
        Err(QueuePushError::Oversized(packet))
    );
}

#[test]
fn header_only_packets_are_packet_aware_and_never_look_empty() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);
    let packet = control(&[]);

    assert!(queue.push(packet.clone()).is_ok());
    assert!(!queue.is_empty());
    assert_eq!(queue.pop(), Some(packet));
    assert!(queue.is_empty());
}

#[test]
fn full_control_lane_does_not_prevent_discard_terminal_progress() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, 64);
    let held = control(&[1; 58]);
    queue.push(held.clone()).unwrap();
    let rejected = control(&[]);
    assert_eq!(
        queue.push(rejected.clone()),
        Err(QueuePushError::Full(rejected))
    );
    let output = terminal(&[2; 40]);
    queue.push(output.clone()).unwrap();

    assert_eq!(queue.pop(), Some(output));
    assert_eq!(queue.pop(), Some(held));
}

#[test]
fn shell_output_and_keepalive_progress_during_sustained_forwarding() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, 1024);
    queue.push(forwarding(&[0])).unwrap();
    queue.push(forwarding(&[1])).unwrap();
    queue.push(control(b"keepalive")).unwrap();
    queue.push(forwarding(&[2])).unwrap();
    queue.push(terminal(b"shell-one")).unwrap();
    queue.push(terminal(b"shell-two")).unwrap();

    // Queued shell output leaves as one packet (see the merge tests).
    assert_eq!(queue.pop(), Some(terminal(b"shell-oneshell-two")));
    assert_eq!(queue.pop(), Some(forwarding(&[0])));
    assert_eq!(queue.pop(), Some(forwarding(&[1])));
    assert_eq!(queue.pop(), Some(control(b"keepalive")));
}

#[test]
fn in_flight_packet_retains_exact_packet_count_capacity() {
    let limit = (MAX_PACKETS_PER_LANE + 1) * 8;
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, limit);
    let packet = control(&[]);
    for _ in 0..MAX_PACKETS_PER_LANE {
        queue.push(packet.clone()).unwrap();
    }
    let in_flight = queue.take().unwrap();

    assert_eq!(
        queue.push(packet.clone()),
        Err(QueuePushError::Full(packet))
    );
    queue.complete(&in_flight);
    assert!(queue.push(control(&[])).is_ok());
}

#[test]
fn count_saturated_lane_resumes_only_after_half_its_slots_free() {
    // Given: a control lane saturated by packet count with ample byte budget.
    let limit = (MAX_PACKETS_PER_LANE + 1) * 8;
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, limit);
    let packet = control(&[]);
    for _ in 0..MAX_PACKETS_PER_LANE {
        queue.push(packet.clone()).unwrap();
    }
    assert_eq!(
        queue.push(packet.clone()),
        Err(QueuePushError::Full(packet))
    );

    // When/Then: single freed slots do not resume the producer; half do.
    for _ in 0..MAX_PACKETS_PER_LANE / 2 - 1 {
        queue.pop().unwrap();
        assert!(!queue.can_resume(OutputLane::Control, 0));
    }
    queue.pop().unwrap();
    assert!(queue.can_resume(OutputLane::Control, 0));
    assert!(queue.can_resume(OutputLane::Terminal, 0));
}

#[test]
fn failed_send_restoration_retains_its_capacity_reservation() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);
    let first = terminal(&[1; 40]);
    let second = terminal(&[2; 40]);
    queue.push(first.clone()).unwrap();
    let in_flight = queue.take().unwrap();

    assert_eq!(
        queue.push(second.clone()),
        Err(QueuePushError::Full(second))
    );
    queue.restore_front(in_flight);
    assert!(queue.bytes() <= LIMIT);
    assert_eq!(queue.pop(), Some(first));
}

fn stderr(bytes: &[u8]) -> Packet {
    Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(bytes.to_vec()),
            is_stderr: Some(true),
        }
        .encode_to_vec(),
    )
}

fn body(packet: &Packet) -> Vec<u8> {
    TerminalBuffer::decode(packet.payload())
        .unwrap()
        .buffer
        .unwrap()
}

#[test]
fn queued_terminal_output_merges_into_upstream_sized_packets() {
    // Given: a flood read from the terminal a line at a time while the
    // writer is busy.
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, 1 << 20);
    let line = [b'.'; 66];
    let lines = 2 * COALESCED_TERMINAL_BYTES / line.len() + 3;
    for _ in 0..lines {
        queue.push(terminal(&line)).unwrap();
    }

    // When: the writer takes the backlog.
    let mut taken = Vec::new();
    while let Some(packet) = queue.pop() {
        taken.push(packet);
    }

    // Then: it leaves in a few packets of at most upstream's BUF_SIZE,
    // byte for byte, and the lane accounting returns to empty.
    assert_eq!(taken.len(), 3);
    let mut bytes = Vec::new();
    for packet in &taken {
        let chunk = body(packet);
        assert!(chunk.len() <= COALESCED_TERMINAL_BYTES);
        bytes.extend(chunk);
    }
    assert_eq!(bytes, line.repeat(lines));
    assert_eq!(queue.bytes(), 0);
    assert!(queue.can_resume(OutputLane::Terminal, 1 << 20));
}

#[test]
fn merging_keeps_streams_apart_and_never_touches_taken_output() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, 1 << 20);
    queue.push(terminal(b"out-1")).unwrap();
    let in_flight = queue.take().unwrap();
    queue.push(terminal(b"out-2")).unwrap();
    queue.push(stderr(b"err-1")).unwrap();
    queue.push(stderr(b"err-2")).unwrap();
    queue.push(terminal(b"out-3")).unwrap();

    assert_eq!(in_flight, terminal(b"out-1"));
    queue.complete(&in_flight);
    assert_eq!(queue.pop(), Some(terminal(b"out-2")));
    assert_eq!(queue.pop(), Some(stderr(b"err-1err-2")));
    assert_eq!(queue.pop(), Some(terminal(b"out-3")));
    assert_eq!(queue.bytes(), 0);
}

#[test]
fn append_terminal_buffer_widens_the_length_prefix_in_place() {
    let mut packet = Packet::new(0, encode_terminal_buffer(&[1; 100], true));
    assert!(append_terminal_buffer(
        &mut packet,
        &[2; 100],
        true,
        16 * 1024
    ));
    let mut expected = vec![1; 100];
    expected.extend([2; 100]);
    assert_eq!(packet.payload(), encode_terminal_buffer(&expected, true));
    assert_eq!(
        decode_terminal_buffer(packet.payload()),
        Some((&expected[..], true))
    );
    // Other stream, over the limit, or already encrypted: untouched.
    assert!(!append_terminal_buffer(&mut packet, b"x", false, 16 * 1024));
    assert!(!append_terminal_buffer(&mut packet, &[3; 200], true, 300));
    let mut sealed = Packet::raw(true, 0, encode_terminal_buffer(b"a", false));
    assert!(!append_terminal_buffer(&mut sealed, b"b", false, 16 * 1024));
    assert_eq!(packet.payload(), encode_terminal_buffer(&expected, true));
}
