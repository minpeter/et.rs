use crate::flow_control::{FlowControlMode, OutputQueue};
use crate::packet::Packet;
use crate::proto::TerminalPacketType;

const LIMIT: usize = 64;

fn terminal(payload: &[u8]) -> Packet {
    Packet::new(TerminalPacketType::TerminalBuffer as u8, payload)
}

fn control(payload: &[u8]) -> Packet {
    Packet::new(TerminalPacketType::KeepAlive as u8, payload)
}

#[test]
fn backpressure_is_lossless_and_refuses_capacity_overflow() {
    let mut queue = OutputQueue::new(FlowControlMode::Backpressure, LIMIT);
    let first = terminal(&[1; 40]);
    let second = terminal(&[2; 40]);

    assert!(queue.push(first.clone()).is_ok());
    assert_eq!(queue.push(second.clone()), Err(second));
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
fn discard_never_drops_control_packets() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, LIMIT);
    let keepalive = control(&[9; 40]);
    let output = terminal(&[1; 40]);

    assert!(queue.push(keepalive.clone()).is_ok());
    assert_eq!(queue.push(output.clone()), Err(output));
    assert_eq!(queue.pop(), Some(keepalive));
}

#[test]
fn oversized_terminal_packet_keeps_its_newest_tail_in_discard_mode() {
    let mut queue = OutputQueue::new(FlowControlMode::Discard, LIMIT);
    let oversized = terminal(&(0u8..100).collect::<Vec<_>>());

    assert!(queue.push(oversized).is_ok());
    assert_eq!(
        queue.pop().map(|packet| packet.payload().to_vec()),
        Some((36u8..100).collect::<Vec<_>>())
    );
    assert!(queue.bytes() <= LIMIT);
}
