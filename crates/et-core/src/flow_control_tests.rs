use prost::Message;

use crate::flow_control::{FlowControlMode, OutputQueue, QueuePushError, MAX_PACKETS_PER_LANE};
use crate::packet::Packet;
use crate::proto::{TerminalBuffer, TerminalPacketType};

const LIMIT: usize = 64;

fn terminal(bytes: &[u8]) -> Packet {
    Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(bytes.to_vec()),
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
    let first = terminal(b"shell-one");
    let second = terminal(b"shell-two");
    queue.push(forwarding(&[0])).unwrap();
    queue.push(forwarding(&[1])).unwrap();
    queue.push(control(b"keepalive")).unwrap();
    queue.push(forwarding(&[2])).unwrap();
    queue.push(first.clone()).unwrap();
    queue.push(second.clone()).unwrap();

    assert_eq!(queue.pop(), Some(first));
    assert_eq!(queue.pop(), Some(forwarding(&[0])));
    assert_eq!(queue.pop(), Some(second));
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
