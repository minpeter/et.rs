//! Bounded terminal-output queue used by opt-in flow-control sessions.

use std::collections::VecDeque;

use crate::packet::Packet;
use crate::proto::TerminalPacketType;

/// Behavior when terminal output reaches the configured queue limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControlMode {
    /// Stop accepting output until queued bytes are drained.
    Backpressure,
    /// Remove the oldest terminal output while retaining control packets.
    Discard,
}

/// Packet queue whose capacity is measured in terminal payload bytes.
pub struct OutputQueue {
    mode: FlowControlMode,
    limit: usize,
    bytes: usize,
    packets: VecDeque<Packet>,
}

impl OutputQueue {
    pub fn new(mode: FlowControlMode, limit: usize) -> Self {
        Self {
            mode,
            limit,
            bytes: 0,
            packets: VecDeque::new(),
        }
    }

    pub fn push(&mut self, mut packet: Packet) -> Result<(), Packet> {
        let packet_bytes = packet.payload().len();
        if packet_bytes > self.limit {
            if self.mode == FlowControlMode::Backpressure || !is_terminal_output(&packet) {
                return Err(packet);
            }
            let keep_from = packet_bytes - self.limit;
            packet = Packet::new(packet.header(), &packet.payload()[keep_from..]);
        }

        let wanted = packet.payload().len();
        if self.bytes.saturating_add(wanted) > self.limit {
            match self.mode {
                FlowControlMode::Backpressure => return Err(packet),
                FlowControlMode::Discard => {
                    while self.bytes.saturating_add(wanted) > self.limit {
                        let Some(index) = self.packets.iter().position(is_terminal_output) else {
                            return Err(packet);
                        };
                        let Some(removed) = self.packets.remove(index) else {
                            return Err(packet);
                        };
                        self.bytes -= removed.payload().len();
                    }
                }
            }
        }

        self.bytes += wanted;
        self.packets.push_back(packet);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Packet> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.payload().len();
        Some(packet)
    }

    pub fn push_front(&mut self, packet: Packet) {
        self.bytes += packet.payload().len();
        self.packets.push_front(packet);
    }

    pub fn can_accept_terminal(&self, bytes: usize) -> bool {
        match self.mode {
            FlowControlMode::Backpressure => self.bytes.saturating_add(bytes) <= self.limit,
            FlowControlMode::Discard => {
                bytes <= self.limit
                    && self
                        .packets
                        .iter()
                        .filter(|packet| !is_terminal_output(packet))
                        .map(|packet| packet.payload().len())
                        .sum::<usize>()
                        .saturating_add(bytes)
                        <= self.limit
            }
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

fn is_terminal_output(packet: &Packet) -> bool {
    packet.header() == TerminalPacketType::TerminalBuffer as u8
}
