//! Bounded, fair output lanes used by opt-in flow-control sessions.

use std::collections::VecDeque;

use prost::Message;

use crate::packet::Packet;
use crate::proto::{TerminalBuffer, TerminalPacketType};

const FRAME_BYTES: usize = std::mem::size_of::<u32>();
pub(crate) const MAX_PACKETS_PER_LANE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControlMode {
    Backpressure,
    Discard,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueuePushError {
    Full(Packet),
    Oversized(Packet),
}

pub struct OutputQueue {
    mode: FlowControlMode,
    limit: usize,
    terminal_bytes: usize,
    control_bytes: usize,
    terminal_packets: usize,
    control_packets: usize,
    terminal: VecDeque<Packet>,
    control: VecDeque<Packet>,
    prefer_terminal: bool,
}

impl OutputQueue {
    pub fn new(mode: FlowControlMode, limit: usize) -> Self {
        Self {
            mode,
            limit,
            terminal_bytes: 0,
            control_bytes: 0,
            terminal_packets: 0,
            control_packets: 0,
            terminal: VecDeque::new(),
            control: VecDeque::new(),
            prefer_terminal: true,
        }
    }

    pub fn push(&mut self, packet: Packet) -> Result<(), QueuePushError> {
        if is_terminal_output(&packet) {
            self.push_terminal(packet)
        } else {
            self.push_control(packet)
        }
    }

    fn push_terminal(&mut self, mut packet: Packet) -> Result<(), QueuePushError> {
        if packet_cost(&packet) > self.limit {
            if self.mode == FlowControlMode::Backpressure {
                return Err(QueuePushError::Oversized(packet));
            }
            packet = truncate_terminal(packet, self.limit).map_err(QueuePushError::Oversized)?;
        }
        let wanted = packet_cost(&packet);
        if self.mode == FlowControlMode::Backpressure
            && (self.terminal_bytes.saturating_add(wanted) > self.limit
                || self.terminal_packets >= MAX_PACKETS_PER_LANE)
        {
            return Err(QueuePushError::Full(packet));
        }
        while self.terminal_bytes.saturating_add(wanted) > self.limit
            || self.terminal_packets >= MAX_PACKETS_PER_LANE
        {
            let Some(removed) = self.terminal.pop_front() else {
                return Err(QueuePushError::Full(packet));
            };
            self.terminal_bytes -= packet_cost(&removed);
            self.terminal_packets -= 1;
        }
        self.terminal_bytes += wanted;
        self.terminal_packets += 1;
        self.terminal.push_back(packet);
        Ok(())
    }

    fn push_control(&mut self, packet: Packet) -> Result<(), QueuePushError> {
        let wanted = packet_cost(&packet);
        if wanted > self.limit {
            return Err(QueuePushError::Oversized(packet));
        }
        if self.control_bytes.saturating_add(wanted) > self.limit
            || self.control_packets >= MAX_PACKETS_PER_LANE
        {
            return Err(QueuePushError::Full(packet));
        }
        self.control_bytes += wanted;
        self.control_packets += 1;
        self.control.push_back(packet);
        Ok(())
    }

    pub fn take(&mut self) -> Option<Packet> {
        let packet = if self.prefer_terminal {
            self.terminal
                .pop_front()
                .or_else(|| self.control.pop_front())
        } else {
            self.control
                .pop_front()
                .or_else(|| self.terminal.pop_front())
        }?;
        self.prefer_terminal = !self.prefer_terminal;
        Some(packet)
    }

    pub fn complete(&mut self, packet: &Packet) {
        if is_terminal_output(packet) {
            self.terminal_bytes -= packet_cost(packet);
            self.terminal_packets -= 1;
        } else {
            self.control_bytes -= packet_cost(packet);
            self.control_packets -= 1;
        }
    }

    pub fn restore_front(&mut self, packet: Packet) {
        if is_terminal_output(&packet) {
            self.terminal.push_front(packet);
        } else {
            self.control.push_front(packet);
        }
    }

    pub fn pop(&mut self) -> Option<Packet> {
        let packet = self.take()?;
        self.complete(&packet);
        Some(packet)
    }

    pub fn can_accept_terminal(&self, payload_bytes: usize) -> bool {
        let wanted = payload_bytes.saturating_add(crate::packet::HEADER_LEN + FRAME_BYTES);
        match self.mode {
            FlowControlMode::Backpressure => {
                self.terminal_packets < MAX_PACKETS_PER_LANE
                    && self.terminal_bytes.saturating_add(wanted) <= self.limit
            }
            FlowControlMode::Discard => wanted <= self.limit,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.terminal.is_empty() && self.control.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.terminal_bytes + self.control_bytes
    }
}

fn packet_cost(packet: &Packet) -> usize {
    packet.wire_len().saturating_add(FRAME_BYTES)
}

fn truncate_terminal(packet: Packet, limit: usize) -> Result<Packet, Packet> {
    let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
        return Err(packet);
    };
    let Some(bytes) = message.buffer else {
        return Err(packet);
    };
    let mut low = 0usize;
    let mut high = bytes.len();
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let encoded = TerminalBuffer {
            buffer: Some(bytes[bytes.len() - middle..].to_vec()),
        }
        .encode_to_vec();
        if encoded
            .len()
            .saturating_add(crate::packet::HEADER_LEN + FRAME_BYTES)
            <= limit
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let encoded = TerminalBuffer {
        buffer: Some(bytes[bytes.len() - low..].to_vec()),
    }
    .encode_to_vec();
    Ok(Packet::new(packet.header(), encoded))
}

pub fn is_terminal_output(packet: &Packet) -> bool {
    packet.header() == TerminalPacketType::TerminalBuffer as u8
}
